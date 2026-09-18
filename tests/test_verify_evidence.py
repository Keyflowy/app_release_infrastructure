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


if __name__ == "__main__":
  unittest.main()
