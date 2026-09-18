import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
  "verify_evidence",
  ROOT / "scripts" / "release-retention" / "verify_evidence.py",
)
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class RetentionEvidenceTests(unittest.TestCase):
  def fixture(self):
    temporary = tempfile.TemporaryDirectory()
    self.addCleanup(temporary.cleanup)
    directory = Path(temporary.name)
    contents = b'{"release_id":"v1.2.3"}\n'
    checksum = "sha256:" + VERIFY.hashlib.sha256(contents).hexdigest()
    manifest = directory / "release-manifest.json"
    manifest.write_text(json.dumps({
      "retention_metadata": [{
        "object_key": "kindow/release-state/v1.2.3/complete.json",
        "checksum": checksum,
        "size_bytes": len(contents),
        "backup": {
          "drive_object_key": "keyflowy/apps/kindow/releases/v1.2.3/release-state/complete.json",
          "sha256": checksum,
          "size_bytes": len(contents),
          "verified": True,
        },
        "completion": {
          "git_path": "release-completions/v1.2.3.json",
          "git_commit": "a" * 40,
          "verified": True,
        },
      }],
    }), encoding="utf-8")
    tombstone = b'{"release_id":"v1.2.3","version":"1.2.3"}\n'
    return manifest, contents, tombstone

  def archive_fixture(self):
    temporary = tempfile.TemporaryDirectory()
    self.addCleanup(temporary.cleanup)
    directory = Path(temporary.name)
    contents = b"release zip bytes"
    checksum = "sha256:" + VERIFY.hashlib.sha256(contents).hexdigest()
    manifest = directory / "release-manifest.json"
    manifest.write_text(json.dumps({
      "releases": [{
        "version": "1.2.3",
        "full_zip_object_key": "kindow/kindow-1.2.3.zip",
        "checksum": checksum,
        "size_bytes": len(contents),
        "archive": {
          "github_release_id": 101,
          "github_asset_id": 202,
          "github_asset_name": "kindow-1.2.3.zip",
          "github_asset_sha256": checksum,
          "github_asset_size_bytes": len(contents),
          "drive_object_key": "keyflowy/apps/kindow/releases/v1.2.3/kindow-1.2.3.zip",
          "drive_sha256": checksum,
          "drive_size_bytes": len(contents),
          "verified": True,
        },
      }],
    }), encoding="utf-8")
    return manifest, contents

  def test_verified_drive_bytes_and_reachable_git_tombstone_are_accepted(self):
    manifest, contents, tombstone = self.fixture()

    with patch.object(VERIFY, "run_bytes", side_effect=[contents, tombstone]) as run:
      VERIFY.verify(manifest, Path("."), "gd_admin:", "rclone")

    self.assertEqual(run.call_count, 2)
    self.assertEqual(run.call_args_list[0].args[0][0:2], ["rclone", "cat"])
    self.assertEqual(run.call_args_list[1].args[0][0:3], ["git", "-C", "."])

  def test_drive_checksum_mismatch_fails_closed_before_git_is_consulted(self):
    manifest, _, tombstone = self.fixture()

    with patch.object(VERIFY, "run_bytes", side_effect=[b"wrong", tombstone]) as run:
      with self.assertRaisesRegex(ValueError, "Drive backup checksum or size differs"):
        VERIFY.verify(manifest, Path("."), "gd_admin:", "rclone")

    self.assertEqual(run.call_count, 1)

  def test_git_tombstone_must_bind_the_same_release(self):
    manifest, contents, _ = self.fixture()
    wrong_tombstone = b'{"release_id":"v9.9.9","version":"9.9.9"}\n'

    with patch.object(VERIFY, "run_bytes", side_effect=[contents, wrong_tombstone]):
      with self.assertRaisesRegex(ValueError, "tombstone identity differs"):
        VERIFY.verify(manifest, Path("."), "gd_admin:", "rclone")

  def test_verified_github_asset_and_drive_bytes_are_returned_as_archive_evidence(self):
    manifest, contents = self.archive_fixture()

    with patch.object(VERIFY, "run_bytes", side_effect=[contents, contents]) as run:
      evidence = VERIFY.verify(
        manifest,
        Path("."),
        "gd_admin:",
        "rclone",
        "Keyflowy/kindow",
        "gh",
      )

    self.assertEqual(evidence["archives"][0]["verified"], True)
    self.assertEqual(run.call_args_list[0].args[0][0:2], ["gh", "api"])
    self.assertEqual(
      run.call_args_list[1].args[0],
      ["rclone", "cat", "gd_admin:keyflowy/apps/kindow/releases/v1.2.3/kindow-1.2.3.zip"],
    )

  def test_github_asset_checksum_mismatch_fails_closed(self):
    manifest, contents = self.archive_fixture()

    with patch.object(VERIFY, "run_bytes", side_effect=[b"wrong", contents]) as run:
      with self.assertRaisesRegex(ValueError, "GitHub or Drive archive checksum or size differs"):
        VERIFY.verify(manifest, Path("."), "gd_admin:", "rclone", "Keyflowy/kindow", "gh")

    self.assertEqual(run.call_count, 2)


if __name__ == "__main__":
  unittest.main()
