#!/usr/bin/env python3
"""Verify Drive backups and Git completion tombstones used by retention v2."""

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path


SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
STATE_KEY_RE = re.compile(r"^[^/]+/release-state/(v[0-9]+\.[0-9]+\.[0-9]+)/[^/]+$")
COMMAND_TIMEOUT_SECONDS = 300


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


def verify_archive(release, repository, github_repository, drive_remote, rclone, gh):
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

  release_assets = run_bytes([
    gh,
    "api",
    "repos/{}/releases/{}/assets".format(github_repository, release_id),
  ])
  try:
    release_assets = json.loads(release_assets)
  except json.JSONDecodeError as error:
    raise ValueError("{} GitHub release assets response is not JSON".format(label)) from error
  if not isinstance(release_assets, list):
    raise ValueError("{} GitHub release assets response is not an array".format(label))
  matching_asset = next(
    (
      asset
      for asset in release_assets
      if isinstance(asset, dict) and str(asset.get("id", "")) == asset_id
    ),
    None,
  )
  if not isinstance(matching_asset, dict):
    raise ValueError("{} GitHub asset is not attached to the recorded release".format(label))
  if matching_asset.get("name") != archive.get("github_asset_name"):
    raise ValueError("{} GitHub asset name differs from metadata".format(label))

  github_bytes = run_bytes([
    gh,
    "api",
    "repos/{}/releases/assets/{}".format(github_repository, asset_id),
    "--header",
    "Accept: application/octet-stream",
  ])
  github_checksum = "sha256:" + hashlib.sha256(github_bytes).hexdigest()
  github_size = len(github_bytes)

  drive_key = archive.get("drive_object_key")
  if not isinstance(drive_key, str) or not drive_key:
    raise ValueError("{} has an invalid Drive object key".format(label))
  drive_bytes = run_bytes([rclone, "cat", remote_object(drive_remote, drive_key)])
  drive_checksum = "sha256:" + hashlib.sha256(drive_bytes).hexdigest()
  drive_size = len(drive_bytes)

  expected_name = Path(release.get("full_zip_object_key", "")).name
  if (
    archive.get("github_asset_name") != expected_name
    or github_checksum != expected_checksum
    or github_size != expected_size
    or drive_checksum != expected_checksum
    or drive_size != expected_size
  ):
    raise ValueError("{} GitHub or Drive archive checksum or size differs".format(label))

  return {
    "version": version,
    "full_zip_object_key": release.get("full_zip_object_key"),
    "github_release_id": archive.get("github_release_id"),
    "github_asset_id": archive.get("github_asset_id"),
    "github_asset_name": archive.get("github_asset_name"),
    "github_asset_sha256": github_checksum,
    "github_asset_size_bytes": github_size,
    "drive_object_key": drive_key,
    "drive_sha256": drive_checksum,
    "drive_size_bytes": drive_size,
    "verified": True,
  }


def selected(value, primary, alias, label):
  if primary in value and alias in value and value[primary] != value[alias]:
    raise ValueError("{} has conflicting {} and {}".format(label, primary, alias))
  result = value.get(primary, value.get(alias))
  if not isinstance(result, dict):
    raise ValueError("{} is missing {}".format(label, primary))
  return result


def verify(
  manifest_path,
  repository,
  drive_remote,
  rclone,
  github_repository=None,
  gh="gh",
):
  with Path(manifest_path).open(encoding="utf-8") as source:
    manifest = json.load(source)
  metadata_entries = manifest.get("retention_metadata", [])
  if not isinstance(metadata_entries, list):
    raise ValueError("retention_metadata must be an array")
  tombstones = {}
  verified_drive_objects = set()
  for index, metadata in enumerate(metadata_entries):
    label = "retention_metadata[{}]".format(index)
    if not isinstance(metadata, dict):
      raise ValueError("{} must be an object".format(label))
    object_key = metadata.get("object_key")
    match = STATE_KEY_RE.fullmatch(object_key or "")
    if match is None:
      raise ValueError("{} object_key is not a versioned release-state object".format(label))
    tag = match.group(1)
    checksum = metadata.get("checksum")
    size_bytes = metadata.get("size_bytes")
    if not isinstance(checksum, str) or SHA256_RE.fullmatch(checksum) is None:
      raise ValueError("{} has an invalid checksum".format(label))
    if not isinstance(size_bytes, int) or isinstance(size_bytes, bool) or size_bytes <= 0:
      raise ValueError("{} has an invalid size".format(label))

    backup = selected(metadata, "backup", "drive_backup", label)
    completion = selected(metadata, "completion", "git_completion_tombstone", label)
    if backup.get("verified") is not True or completion.get("verified") is not True:
      raise ValueError("{} evidence is not marked verified".format(label))
    if backup.get("sha256") != checksum or backup.get("size_bytes") != size_bytes:
      raise ValueError("{} Drive evidence differs from metadata".format(label))

    drive_object_key = backup.get("drive_object_key")
    if not isinstance(drive_object_key, str) or not drive_object_key:
      raise ValueError("{} Drive object key is invalid".format(label))
    drive_identity = (drive_object_key, checksum, size_bytes)
    if drive_identity not in verified_drive_objects:
      contents = run_bytes([rclone, "cat", drive_remote + drive_object_key])
      actual_checksum = "sha256:" + hashlib.sha256(contents).hexdigest()
      if len(contents) != size_bytes or actual_checksum != checksum:
        raise ValueError("{} Drive backup checksum or size differs".format(label))
      verified_drive_objects.add(drive_identity)

    git_path = completion.get("git_path", completion.get("path"))
    git_commit = completion.get("git_commit", completion.get("commit"))
    if not isinstance(git_path, str) or not git_path.endswith("/{}.json".format(tag)):
      raise ValueError("{} completion path does not match release tag".format(label))
    identity = (git_commit, git_path)
    if identity not in tombstones:
      contents = run_bytes(["git", "-C", str(repository), "show", "{}:{}".format(git_commit, git_path)])
      try:
        tombstone = json.loads(contents)
      except json.JSONDecodeError as error:
        raise ValueError("{} completion tombstone is not JSON".format(label)) from error
      if tombstone.get("release_id") != tag or tombstone.get("version") != tag.removeprefix("v"):
        raise ValueError("{} completion tombstone identity differs".format(label))
      tombstones[identity] = tombstone

  archives = []
  seen_archive_keys = set()
  for release in manifest.get("releases", []):
    if not isinstance(release, dict) or "archive" not in release:
      continue
    evidence = verify_archive(
      release,
      repository,
      github_repository,
      drive_remote,
      rclone,
      gh,
    )
    key = evidence["full_zip_object_key"]
    if key in seen_archive_keys:
      raise ValueError("duplicate archive evidence for {}".format(key))
    seen_archive_keys.add(key)
    archives.append(evidence)

  return {
    "schema_version": 1,
    "manifest_sha256": "sha256:" + hashlib.sha256(
      Path(manifest_path).read_bytes()
    ).hexdigest(),
    "archives": sorted(archives, key=lambda item: item["full_zip_object_key"]),
  }


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--manifest", required=True, type=Path)
  parser.add_argument("--repository", default=Path("."), type=Path)
  parser.add_argument("--drive-remote", default="gd_admin:")
  parser.add_argument("--rclone", default="rclone")
  parser.add_argument(
    "--github-repository",
    default=os.environ.get("GITHUB_REPOSITORY", ""),
    help="GitHub owner/name containing the release assets",
  )
  parser.add_argument("--gh", default="gh")
  parser.add_argument("--output", type=Path)
  args = parser.parse_args()
  try:
    evidence = verify(
      args.manifest,
      args.repository,
      args.drive_remote,
      args.rclone,
      args.github_repository,
      args.gh,
    )
    if args.output is not None:
      args.output.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
      )
  except (OSError, ValueError, json.JSONDecodeError) as error:
    raise SystemExit("retention evidence: {}".format(error)) from error


if __name__ == "__main__":
  main()
