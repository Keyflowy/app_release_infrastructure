#!/usr/bin/env python3
"""Verify retention evidence from remote metadata without downloading archives."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from plan import (
  EVIDENCE_REASONS,
  load_retention_metadata,
  release_identity_sha256,
  retention_metadata_sha256,
  sha256_file,
)


SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MD5_RE = re.compile(r"^[0-9a-f]{32}$")
STATE_KEY_RE = re.compile(r"^[^/]+/release-state/(v[0-9]+\.[0-9]+\.[0-9]+)/[^/]+$")
COMMAND_TIMEOUT_SECONDS = 300
RCLONE_TIMEOUT_FLAGS = (
  "--timeout", "30s",
  "--contimeout", "10s",
  "--retries", "1",
  "--low-level-retries", "1",
)
RCLONE_RETRY_DELAYS_SECONDS = (5, 15)


def run_bytes(command):
  try:
    result = subprocess.run(
      command,
      check=False,
      capture_output=True,
      timeout=COMMAND_TIMEOUT_SECONDS,
    )
  except subprocess.TimeoutExpired as error:
    raise ValueError(
      "command timed out after {} seconds: {}".format(
        COMMAND_TIMEOUT_SECONDS,
        " ".join(command),
      )
    ) from error
  if result.returncode != 0:
    message = result.stderr.decode(errors="replace").strip()
    raise ValueError(message or "command failed: {}".format(" ".join(command)))
  return result.stdout


def remote_object(remote, object_key):
  if remote.endswith(":") or remote.endswith("/"):
    return remote + object_key
  return remote + "/" + object_key


def rclone_cat(rclone, object_path):
  command = [rclone, *RCLONE_TIMEOUT_FLAGS, "cat", object_path]
  for attempt in range(len(RCLONE_RETRY_DELAYS_SECONDS) + 1):
    try:
      return run_bytes(command)
    except ValueError:
      if attempt == len(RCLONE_RETRY_DELAYS_SECONDS):
        raise
      delay = RCLONE_RETRY_DELAYS_SECONDS[attempt]
      print(
        "retention evidence: Drive read failed; retrying with a fresh rclone "
        "process in {} seconds".format(delay),
        file=sys.stderr,
      )
      time.sleep(delay)
  raise AssertionError("unreachable")


def metadata_from_entry(entry):
  if not isinstance(entry, dict):
    raise ValueError("Drive metadata entry is not an object")
  size = entry.get("Size")
  hashes = entry.get("Hashes", {})
  md5 = hashes.get("md5", hashes.get("MD5")) if isinstance(hashes, dict) else None
  if not isinstance(size, int) or size < 0:
    raise ValueError("Drive metadata has an invalid size")
  if not isinstance(md5, str) or MD5_RE.fullmatch(md5.lower()) is None:
    raise ValueError("Drive metadata is missing an MD5 checksum")
  return {"size_bytes": size, "md5": md5.lower()}


def rclone_metadata(rclone, object_path):
  payload = run_bytes([
    rclone,
    *RCLONE_TIMEOUT_FLAGS,
    "lsjson",
    "--files-only",
    "--hash",
    "--no-mimetype",
    object_path,
  ])
  try:
    entries = json.loads(payload)
  except json.JSONDecodeError as error:
    raise ValueError("Drive metadata response is not JSON") from error
  if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
    raise ValueError("Drive metadata did not identify exactly one object")
  return metadata_from_entry(entries[0])


def github_asset_metadata(release, repository, github_repository, gh):
  archive = release["archive"]
  release_id = str(archive["github_release_id"])
  asset_id = str(archive["github_asset_id"])
  release_assets = run_bytes([
    gh,
    "api",
    "repos/{}/releases/{}/assets".format(github_repository, release_id),
  ])
  try:
    release_assets = json.loads(release_assets)
  except json.JSONDecodeError as error:
    raise ValueError("GitHub release assets response is not JSON") from error
  if not isinstance(release_assets, list):
    raise ValueError("GitHub release assets response is not an array")
  matching_asset = next(
    (
      asset
      for asset in release_assets
      if isinstance(asset, dict) and str(asset.get("id", "")) == asset_id
    ),
    None,
  )
  if not isinstance(matching_asset, dict):
    raise ValueError("GitHub asset is not attached to the recorded release")
  if matching_asset.get("name") != archive.get("github_asset_name"):
    raise ValueError("GitHub asset name differs from metadata")
  digest = matching_asset.get("digest")
  size = matching_asset.get("size")
  if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
    raise ValueError("GitHub asset is missing a sha256 digest")
  if not isinstance(size, int) or size <= 0:
    raise ValueError("GitHub asset has an invalid size")
  return {"digest": digest, "size_bytes": size}


def verify_archive(release, repository, github_repository, drive_remote, rclone, gh, drive_index=None):
  version = release.get("version")
  label = "releases[{}]".format(version or "?")
  archive = release.get("archive")
  if not isinstance(archive, dict):
    raise ValueError("{} is missing archive evidence metadata".format(label))
  if not github_repository:
    raise ValueError("GitHub repository is required to verify {}".format(label))

  release_id = str(archive.get("github_release_id", ""))
  asset_id = str(archive.get("github_asset_id", ""))
  if not release_id.isdigit() or not asset_id.isdigit() or release_id == "0" or asset_id == "0":
    raise ValueError("{} has invalid GitHub release or asset identity".format(label))

  expected_checksum = release.get("checksum")
  expected_size = release.get("size_bytes")
  if not isinstance(expected_checksum, str) or SHA256_RE.fullmatch(expected_checksum) is None:
    raise ValueError("{} has an invalid release checksum".format(label))
  if not isinstance(expected_size, int) or isinstance(expected_size, bool) or expected_size <= 0:
    raise ValueError("{} has an invalid release size".format(label))

  drive_key = archive.get("drive_object_key")
  if not isinstance(drive_key, str) or not drive_key:
    raise ValueError("{} has an invalid Drive object key".format(label))
  expected_name = Path(release.get("full_zip_object_key", "")).name
  github = github_asset_metadata(release, repository, github_repository, gh)
  drive = (
    drive_index[drive_key]
    if drive_index is not None
    else rclone_metadata(rclone, remote_object(drive_remote, drive_key))
  )
  expected_digest = archive.get("github_asset_digest", archive.get("github_asset_sha256"))
  expected_md5 = archive.get("drive_md5")
  if not isinstance(expected_digest, str) or SHA256_RE.fullmatch(expected_digest) is None:
    raise ValueError("{} is missing the recorded GitHub asset digest".format(label))
  if not isinstance(expected_md5, str) or MD5_RE.fullmatch(expected_md5.lower()) is None:
    raise ValueError("{} is missing the recorded Drive MD5 checksum".format(label))
  if (
    archive.get("github_asset_name") != expected_name
    or github["digest"] != expected_digest
    or github["size_bytes"] != expected_size
    or drive["md5"] != expected_md5.lower()
    or drive["size_bytes"] != expected_size
  ):
    raise ValueError("{} GitHub or Drive metadata differs".format(label))

  return {
    "version": version,
    "full_zip_object_key": release.get("full_zip_object_key"),
    "github_release_id": archive.get("github_release_id"),
    "github_asset_id": archive.get("github_asset_id"),
    "github_asset_name": archive.get("github_asset_name"),
    "github_asset_digest": github["digest"],
    "github_asset_size_bytes": github["size_bytes"],
    "drive_object_key": drive_key,
    "drive_md5": drive["md5"],
    "drive_size_bytes": drive["size_bytes"],
    "verified": True,
  }


def verify_archive_bytes(release, repository, github_repository, drive_remote, rclone, gh):
  """Deeply verify one archive immediately before its R2 object is deleted."""
  archive = release.get("archive") or {}
  expected_checksum = release.get("checksum")
  expected_size = release.get("size_bytes")
  if not isinstance(expected_checksum, str) or SHA256_RE.fullmatch(expected_checksum) is None:
    raise ValueError("release has an invalid archive checksum")
  if not isinstance(expected_size, int) or expected_size <= 0:
    raise ValueError("release has an invalid archive size")
  asset_id = str(archive.get("github_asset_id", ""))
  if not asset_id.isdigit() or asset_id == "0":
    raise ValueError("release has an invalid GitHub asset identity")
  github_bytes = run_bytes([
    gh,
    "api",
    "repos/{}/releases/assets/{}".format(github_repository, asset_id),
    "--header",
    "Accept: application/octet-stream",
  ])
  drive_key = archive.get("drive_object_key")
  if not isinstance(drive_key, str) or not drive_key:
    raise ValueError("release has an invalid Drive object key")
  drive_bytes = rclone_cat(rclone, remote_object(drive_remote, drive_key))
  github_checksum = "sha256:" + hashlib.sha256(github_bytes).hexdigest()
  drive_checksum = "sha256:" + hashlib.sha256(drive_bytes).hexdigest()
  if (
    github_checksum != expected_checksum
    or drive_checksum != expected_checksum
    or len(github_bytes) != expected_size
    or len(drive_bytes) != expected_size
  ):
    raise ValueError("GitHub or Drive archive checksum or size differs")
  return {"github_sha256": github_checksum, "drive_sha256": drive_checksum, "size_bytes": expected_size}


def normalized_sha256(value, label):
  if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value):
    return "sha256:" + value
  if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
    raise ValueError("{} is not a SHA-256 checksum".format(label))
  return value


def release_entry(manifest, version, label):
  releases = manifest.get("releases", [])
  if not isinstance(releases, list):
    raise ValueError("{} manifest releases is not an array".format(label))
  matches = [
    release
    for release in releases
    if isinstance(release, dict) and release.get("version") == version
  ]
  if len(matches) != 1:
    raise ValueError("{} manifest does not identify exactly one release".format(label))
  return matches[0]


def verify_completion(
  metadata,
  manifest,
  repository,
  trusted_main_ref="refs/remotes/origin/main",
):
  object_key = metadata.get("object_key", "")
  match = STATE_KEY_RE.fullmatch(object_key)
  if match is None:
    raise ValueError("release metadata object key is not versioned")
  tag = match.group(1)
  version = tag.removeprefix("v")
  completion = metadata.get("completion")
  if not isinstance(completion, dict):
    raise ValueError("release metadata is missing a completion tombstone")
  git_path = completion.get("git_path")
  git_commit = completion.get("git_commit")
  if not isinstance(git_path, str) or not git_path.endswith("/{}.json".format(tag)):
    raise ValueError("release completion path does not match release tag")
  if not isinstance(git_commit, str) or re.fullmatch(r"[0-9a-fA-F]{40,64}", git_commit) is None:
    raise ValueError("release completion commit is invalid")
  if completion.get("evidence_version") != 3:
    raise ValueError("release completion evidence_version must be 3")
  bound_manifest_path = completion.get("manifest_path")
  if (
    not isinstance(bound_manifest_path, str)
    or not bound_manifest_path
    or bound_manifest_path.startswith("/")
    or "\\" in bound_manifest_path
    or any(part in ("", ".", "..") for part in bound_manifest_path.split("/"))
  ):
    raise ValueError("release completion manifest path is invalid")
  zip_sha256 = normalized_sha256(
    completion.get("zip_sha256"),
    "release completion ZIP digest",
  )
  completion_entry_sha256 = normalized_sha256(
    completion.get("manifest_entry_sha256"),
    "release completion manifest identity",
  )

  current_release = release_entry(manifest, version, "current")
  if current_release.get("completion") != completion:
    raise ValueError("release completion evidence differs from the release entry")
  current_archive_sha256 = normalized_sha256(
    current_release.get("checksum"),
    "current release archive checksum",
  )
  if zip_sha256 != current_archive_sha256:
    raise ValueError("release completion ZIP digest differs from the manifest")
  current_manifest_entry_sha256 = release_identity_sha256(current_release)
  if completion_entry_sha256 != current_manifest_entry_sha256:
    raise ValueError("release completion manifest identity differs")

  try:
    run_bytes([
      "git", "-C", str(repository), "merge-base", "--is-ancestor",
      git_commit, trusted_main_ref,
    ])
  except ValueError as error:
    raise ValueError("release completion commit is not reachable from trusted main") from error

  tombstone_bytes = run_bytes([
    "git", "-C", str(repository), "show", "{}:{}".format(git_commit, git_path),
  ])
  manifest_bytes = run_bytes([
    "git", "-C", str(repository), "show",
    "{}:{}".format(git_commit, bound_manifest_path),
  ])
  try:
    tombstone = json.loads(tombstone_bytes)
  except json.JSONDecodeError as error:
    raise ValueError("release completion tombstone is not JSON") from error
  try:
    historical_manifest = json.loads(manifest_bytes)
  except json.JSONDecodeError as error:
    raise ValueError("release completion manifest is not JSON") from error
  if tombstone.get("release_id") != tag or tombstone.get("version") != version:
    raise ValueError("release completion tombstone identity differs")
  if tombstone.get("evidence_version") != 3:
    raise ValueError("release completion tombstone evidence version differs")
  if tombstone.get("manifest_path") != bound_manifest_path:
    raise ValueError("release completion tombstone manifest path differs")
  if normalized_sha256(
    tombstone.get("manifest_entry_sha256"),
    "release completion tombstone manifest identity",
  ) != completion_entry_sha256:
    raise ValueError("release completion tombstone manifest identity differs")
  if normalized_sha256(
    tombstone.get("zip_sha256"),
    "release completion tombstone ZIP digest",
  ) != zip_sha256:
    raise ValueError("release completion tombstone ZIP digest differs from evidence")
  historical_release = release_entry(historical_manifest, version, "completion commit")
  if release_identity_sha256(historical_release) != current_manifest_entry_sha256:
    raise ValueError("release completion manifest entry differs from the current manifest")
  return {
    "git_commit": git_commit.lower(),
    "git_path": git_path,
    "zip_sha256": zip_sha256,
    "manifest_entry_sha256": current_manifest_entry_sha256,
  }


def verify_metadata_bytes(
  metadata,
  manifest,
  repository,
  drive_remote,
  rclone,
  trusted_main_ref="refs/remotes/origin/main",
):
  """Deeply verify one release-state object immediately before deletion."""
  backup = metadata.get("backup", metadata.get("drive_backup", {}))
  drive_key = backup.get("drive_object_key")
  expected_checksum = metadata.get("checksum")
  expected_size = metadata.get("size_bytes")
  if not isinstance(drive_key, str) or not drive_key:
    raise ValueError("release metadata has an invalid Drive object key")
  contents = rclone_cat(rclone, remote_object(drive_remote, drive_key))
  actual_checksum = "sha256:" + hashlib.sha256(contents).hexdigest()
  if actual_checksum != expected_checksum or len(contents) != expected_size:
    raise ValueError("Drive release metadata checksum or size differs")
  verify_completion(
    metadata,
    manifest,
    repository,
    trusted_main_ref,
  )
  return {"sha256": actual_checksum, "size_bytes": len(contents)}


def selected(value, primary, alias, label):
  if primary in value and alias in value and value[primary] != value[alias]:
    raise ValueError("{} has conflicting {} and {}".format(label, primary, alias))
  result = value.get(primary, value.get(alias))
  if not isinstance(result, dict):
    raise ValueError("{} is missing {}".format(label, primary))
  return result


def verify_metadata_candidate(
  metadata,
  manifest,
  repository,
  drive_remote,
  rclone,
  completions,
  drive_metadata_cache,
  trusted_main_ref,
):
  """Verify one expired-release-metadata candidate against live metadata."""
  checksum = metadata.get("checksum")
  size_bytes = metadata.get("size_bytes")
  if not isinstance(checksum, str) or SHA256_RE.fullmatch(checksum) is None:
    raise ValueError("candidate metadata has an invalid checksum")
  if not isinstance(size_bytes, int) or isinstance(size_bytes, bool) or size_bytes <= 0:
    raise ValueError("candidate metadata has an invalid size")

  backup = selected(metadata, "backup", "drive_backup", metadata.get("object_key"))
  completion = metadata.get("completion")
  if not isinstance(completion, dict):
    raise ValueError("candidate metadata is missing a completion tombstone")
  if backup.get("verified") is not True or completion.get("verified") is not True:
    raise ValueError("candidate metadata evidence is not marked verified")
  if backup.get("sha256") != checksum or backup.get("size_bytes") != size_bytes:
    raise ValueError("candidate Drive evidence differs from metadata")

  drive_object_key = backup.get("drive_object_key")
  if not isinstance(drive_object_key, str) or not drive_object_key:
    raise ValueError("candidate Drive object key is invalid")
  drive_md5 = backup.get("md5")
  if not isinstance(drive_md5, str) or MD5_RE.fullmatch(drive_md5.lower()) is None:
    raise ValueError("candidate Drive evidence is missing an MD5 checksum")
  if drive_object_key not in drive_metadata_cache:
    drive_metadata_cache[drive_object_key] = rclone_metadata(
      rclone,
      remote_object(drive_remote, drive_object_key),
    )
  actual = drive_metadata_cache[drive_object_key]
  if actual["size_bytes"] != size_bytes or actual["md5"] != drive_md5.lower():
    raise ValueError("candidate Drive metadata checksum or size differs")

  identity = (completion.get("git_commit"), completion.get("git_path"))
  if identity not in completions:
    completions[identity] = verify_completion(
      metadata,
      manifest,
      repository,
      trusted_main_ref,
    )
  verified_completion = completions[identity]
  return {
    "drive_object_key": drive_object_key,
    "drive_md5": actual["md5"],
    "size_bytes": actual["size_bytes"],
    "git_commit": verified_completion["git_commit"],
    "git_path": verified_completion["git_path"],
    "zip_sha256": verified_completion["zip_sha256"],
    "manifest_entry_sha256": verified_completion["manifest_entry_sha256"],
  }


def verify_candidates(
  manifest_path,
  candidates_path,
  repository,
  drive_remote,
  rclone,
  github_repository=None,
  gh="gh",
  trusted_main_ref="refs/remotes/origin/main",
  retention_metadata_dir=None,
):
  """Verify only the deletion candidates listed by a provisional plan."""
  with Path(manifest_path).open(encoding="utf-8") as source:
    manifest = json.load(source)
  document = load_candidates_document(candidates_path)
  metadata_entries = load_retention_metadata(
    Path(retention_metadata_dir) if retention_metadata_dir is not None else None
  )
  if document["manifest_sha256"] != sha256_file(Path(manifest_path)):
    raise ValueError("deletion candidates manifest digest does not match the manifest")
  if document["retention_metadata_sha256"] != retention_metadata_sha256(metadata_entries):
    raise ValueError("deletion candidates retention metadata digest does not match")

  candidates = []
  for index, candidate in enumerate(document["candidates"]):
    label = "candidates[{}]".format(index)
    if not isinstance(candidate, dict):
      raise ValueError("{} must be an object".format(label))
    key = candidate.get("key")
    reason = candidate.get("reason")
    if not isinstance(key, str) or not key:
      raise ValueError("{} key is invalid".format(label))
    if reason not in EVIDENCE_REASONS:
      raise ValueError("{} reason {!r} is not a verifiable deletion reason".format(label, reason))
    candidates.append({"key": key, "reason": reason})
  candidates.sort(key=lambda item: item["key"])

  metadata_by_key = {entry["object_key"]: entry for entry in metadata_entries}
  completions = {}
  drive_metadata_cache = {}
  results = []
  for candidate in candidates:
    key = candidate["key"]
    reason = candidate["reason"]
    try:
      if reason == "archived-stable-expired":
        matches = [
          release
          for release in manifest.get("releases", [])
          if isinstance(release, dict) and release.get("full_zip_object_key") == key
        ]
        if len(matches) != 1:
          raise ValueError("candidate does not identify exactly one manifest release")
        archive = verify_archive(
          matches[0],
          repository,
          github_repository,
          drive_remote,
          rclone,
          gh,
          drive_index=None,
        )
        results.append({
          "key": key,
          "reason": reason,
          "status": "verified",
          "archive": archive,
        })
      else:
        metadata = metadata_by_key.get(key)
        if metadata is None:
          raise ValueError("candidate has no retention metadata entry")
        results.append({
          "key": key,
          "reason": reason,
          "status": "verified",
          "metadata": verify_metadata_candidate(
            metadata,
            manifest,
            repository,
            drive_remote,
            rclone,
            completions,
            drive_metadata_cache,
            trusted_main_ref,
          ),
        })
    except ValueError as error:
      results.append({
        "key": key,
        "reason": reason,
        "status": "failed",
        "error": str(error),
      })
      print(
        "retention evidence: candidate {} failed verification: {}".format(key, error),
        file=sys.stderr,
      )

  return {
    "schema_version": 3,
    "as_of": document["as_of"],
    "manifest_sha256": document["manifest_sha256"],
    "retention_metadata_sha256": document["retention_metadata_sha256"],
    "inventory_sha256": document["inventory_sha256"],
    "candidates": candidates,
    "results": sorted(results, key=lambda item: item["key"]),
  }


def load_candidates_document(candidates_path):
  try:
    document = json.loads(Path(candidates_path).read_text(encoding="utf-8"))
  except json.JSONDecodeError as error:
    raise ValueError("deletion candidates document is not JSON") from error
  if not isinstance(document, dict):
    raise ValueError("deletion candidates document must be a JSON object")
  if document.get("schema_version") != 1:
    raise ValueError("unsupported deletion candidates schema_version")
  for field in ("as_of", "manifest_sha256", "retention_metadata_sha256", "inventory_sha256"):
    if not isinstance(document.get(field), str) or not document[field]:
      raise ValueError("deletion candidates {} is missing".format(field))
  if not isinstance(document.get("candidates"), list):
    raise ValueError("deletion candidates must be an array")
  return document


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--manifest", required=True, type=Path)
  parser.add_argument(
    "--candidates",
    required=True,
    type=Path,
    help="deletion candidates document produced by plan.py --candidates-output",
  )
  parser.add_argument(
    "--retention-metadata-dir",
    type=Path,
    help="directory of per-version release-state metadata files",
  )
  parser.add_argument("--repository", default=Path("."), type=Path)
  parser.add_argument("--drive-remote", default="gd_admin:")
  parser.add_argument("--rclone", default="rclone")
  parser.add_argument(
    "--github-repository",
    default=os.environ.get("GITHUB_REPOSITORY", ""),
    help="GitHub owner/name containing the release assets",
  )
  parser.add_argument("--gh", default="gh")
  parser.add_argument("--trusted-main-ref", default="refs/remotes/origin/main")
  parser.add_argument("--output", type=Path)
  args = parser.parse_args()
  try:
    evidence = verify_candidates(
      args.manifest,
      args.candidates,
      args.repository,
      args.drive_remote,
      args.rclone,
      args.github_repository,
      args.gh,
      args.trusted_main_ref,
      args.retention_metadata_dir,
    )
    rendered = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
      args.output.write_text(rendered, encoding="utf-8")
    else:
      sys.stdout.write(rendered)
  except (OSError, ValueError, json.JSONDecodeError) as error:
    raise SystemExit("retention evidence: {}".format(error)) from error


if __name__ == "__main__":
  main()
