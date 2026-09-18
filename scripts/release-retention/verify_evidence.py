#!/usr/bin/env python3
"""Verify Drive backups and Git completion tombstones used by retention v2."""

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
STATE_KEY_RE = re.compile(r"^[^/]+/release-state/(v[0-9]+\.[0-9]+\.[0-9]+)/[^/]+$")


def run_bytes(command):
  result = subprocess.run(command, check=False, capture_output=True)
  if result.returncode != 0:
    message = result.stderr.decode(errors="replace").strip()
    raise ValueError(message or "command failed: {}".format(" ".join(command)))
  return result.stdout


def selected(value, primary, alias, label):
  if primary in value and alias in value and value[primary] != value[alias]:
    raise ValueError("{} has conflicting {} and {}".format(label, primary, alias))
  result = value.get(primary, value.get(alias))
  if not isinstance(result, dict):
    raise ValueError("{} is missing {}".format(label, primary))
  return result


def verify(manifest_path, repository, drive_remote, rclone):
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


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--manifest", required=True, type=Path)
  parser.add_argument("--repository", default=Path("."), type=Path)
  parser.add_argument("--drive-remote", default="gd_admin:")
  parser.add_argument("--rclone", default="rclone")
  args = parser.parse_args()
  try:
    verify(args.manifest, args.repository, args.drive_remote, args.rclone)
  except (OSError, ValueError, json.JSONDecodeError) as error:
    raise SystemExit("retention evidence: {}".format(error)) from error


if __name__ == "__main__":
  main()
