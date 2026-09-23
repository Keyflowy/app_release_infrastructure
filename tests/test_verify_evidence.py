import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "release-retention"))
import plan
import verify_evidence as VERIFY


class RetentionEvidenceTests(unittest.TestCase):
  def release(self, version="1.2.3"):
    item = {
      "version": version,
      "feature_line": ".".join(version.split(".")[:2]),
      "release_date": "2024-01-01",
      "channel": "stable",
      "notarization_status": "notarized",
      "full_zip_object_key": "kindow/releases/{}.zip".format(version),
      "checksum": "sha256:" + "b" * 64,
      "size_bytes": 10,
      "sparkle_delta_object_keys": [],
    }
    item["completion"] = self.completion(item)
    return item

  def completion(self, release):
    return {
      "evidence_version": 3,
      "git_path": "release-completions/v{}.json".format(release["version"]),
      "git_commit": "a" * 40,
      "zip_sha256": release["checksum"],
      "manifest_path": "release-manifest.json",
      "manifest_entry_sha256": plan.release_identity_sha256(release),
      "verified": True,
    }

  def tombstone(self, release):
    completion = release["completion"]
    return json.dumps({
      "release_id": "v{}".format(release["version"]),
      "version": release["version"],
      "evidence_version": 3,
      "zip_sha256": completion["zip_sha256"],
      "manifest_path": completion["manifest_path"],
      "manifest_entry_sha256": completion["manifest_entry_sha256"],
    }).encode()

  def metadata_fixture(self):
    contents = b'{"complete":true}\n'
    checksum = "sha256:" + VERIFY.hashlib.sha256(contents).hexdigest()
    md5 = VERIFY.hashlib.md5(contents).hexdigest()
    release = self.release()
    metadata = {
      "object_key": "kindow/release-state/v1.2.3/complete.json",
      "release_date": "2024-01-01",
      "checksum": checksum,
      "size_bytes": len(contents),
      "backup": {
        "drive_object_key": "keyflowy/apps/kindow/releases/v1.2.3/release-state/complete.json",
        "sha256": checksum,
        "md5": md5,
        "size_bytes": len(contents),
        "verified": True,
      },
      "completion": release["completion"],
    }
    return metadata, release, contents, md5

  def drive_listing(self, size, md5):
    return json.dumps([{
      "Path": "object",
      "Size": size,
      "Hashes": {"md5": md5},
    }]).encode()

  def candidates_document(self, manifest_path, candidates, metadata_entries=None):
    return {
      "schema_version": 1,
      "as_of": "2026-08-26T00:00:00Z",
      "manifest_sha256": plan.sha256_file(manifest_path),
      "retention_metadata_sha256": plan.retention_metadata_sha256(metadata_entries or []),
      "inventory_sha256": "f" * 64,
      "candidates": candidates,
    }

  def write_metadata_dir(self, directory, entries_by_version):
    directory_path = Path(directory)
    for version, entries in entries_by_version.items():
      version_dir = directory_path / "v{}".format(version)
      version_dir.mkdir(parents=True)
      (version_dir / "metadata.json").write_text(json.dumps({
        "schema_version": 1,
        "version": version,
        "retention_metadata": entries,
      }), encoding="utf-8")
    return directory_path

  def test_given_a_backfilled_archive_when_verifying_completion_then_identity_still_matches(self):
    metadata, release, _, _ = self.metadata_fixture()
    # The archive was backfilled after the completion commit: the historical
    # entry has neither archive nor drive_md5, but the identity fields match.
    historical_release = {
      key: release[key] for key in plan.RELEASE_IDENTITY_FIELDS if key in release
    }
    release["archive"] = {
      "github_release_id": 101,
      "github_asset_id": 202,
      "github_asset_name": "1.2.3.zip",
      "drive_object_key": "keyflowy/apps/kindow/releases/v1.2.3/1.2.3.zip",
      "drive_md5": "b" * 32,
      "verified": True,
    }
    historical_manifest = json.dumps({"releases": [historical_release]}).encode()
    manifest = {"releases": [release]}

    with patch.object(
      VERIFY,
      "run_bytes",
      side_effect=[b"", self.tombstone(release), historical_manifest],
    ) as run:
      result = VERIFY.verify_completion(metadata, manifest, Path("."))

    self.assertEqual(run.call_count, 3)
    self.assertIn("merge-base", run.call_args_list[0].args[0])
    self.assertEqual(result["git_commit"], "a" * 40)
    self.assertEqual(result["zip_sha256"], release["checksum"])

  def test_given_evidence_version_2_or_missing_when_verifying_completion_then_rejected(self):
    metadata, release, _, _ = self.metadata_fixture()
    manifest = {"releases": [release]}
    for version_marker in (2, None):
      with self.subTest(evidence_version=version_marker):
        changed = json.loads(json.dumps(metadata))
        if version_marker is None:
          changed["completion"].pop("evidence_version")
        else:
          changed["completion"]["evidence_version"] = version_marker
        with self.assertRaisesRegex(ValueError, "evidence_version must be 3"):
          VERIFY.verify_completion(changed, manifest, Path("."))

  def test_given_historical_identity_drift_when_verifying_completion_then_rejected(self):
    metadata, release, _, _ = self.metadata_fixture()
    drifted = {
      key: release[key] for key in plan.RELEASE_IDENTITY_FIELDS if key in release
    }
    drifted["checksum"] = "sha256:" + "c" * 64
    historical_manifest = json.dumps({"releases": [drifted]}).encode()
    manifest = {"releases": [release]}

    with patch.object(
      VERIFY,
      "run_bytes",
      side_effect=[b"", self.tombstone(release), historical_manifest],
    ):
      with self.assertRaisesRegex(ValueError, "manifest entry differs"):
        VERIFY.verify_completion(metadata, manifest, Path("."))

  def test_given_a_tombstone_hash_differing_from_completion_then_rejected(self):
    metadata, release, _, _ = self.metadata_fixture()
    tombstone = json.loads(self.tombstone(release))
    tombstone["manifest_entry_sha256"] = "sha256:" + "f" * 64
    manifest = {"releases": [release]}
    historical_manifest = json.dumps({"releases": [release]}).encode()

    with patch.object(
      VERIFY,
      "run_bytes",
      side_effect=[b"", json.dumps(tombstone).encode(), historical_manifest],
    ):
      with self.assertRaisesRegex(ValueError, "tombstone manifest identity differs"):
        VERIFY.verify_completion(metadata, manifest, Path("."))

  def test_given_a_tombstone_for_another_release_then_rejected(self):
    metadata, release, _, _ = self.metadata_fixture()
    tombstone = json.loads(self.tombstone(release))
    tombstone["release_id"] = "v9.9.9"
    manifest = {"releases": [release]}
    historical_manifest = json.dumps({"releases": [release]}).encode()

    with patch.object(
      VERIFY,
      "run_bytes",
      side_effect=[b"", json.dumps(tombstone).encode(), historical_manifest],
    ):
      with self.assertRaisesRegex(ValueError, "tombstone identity differs"):
        VERIFY.verify_completion(metadata, manifest, Path("."))

  def test_given_a_completion_commit_outside_trusted_main_then_evidence_fails_closed(self):
    metadata, release, _, _ = self.metadata_fixture()
    manifest = {"releases": [release]}

    with patch.object(
      VERIFY,
      "run_bytes",
      side_effect=[ValueError("not an ancestor")],
    ) as run:
      with self.assertRaisesRegex(ValueError, "not reachable from trusted main"):
        VERIFY.verify_completion(metadata, manifest, Path("."))

    self.assertEqual(run.call_count, 1)

  def test_verify_candidates_with_zero_candidates_makes_no_subprocess_calls(self):
    temporary = tempfile.TemporaryDirectory()
    self.addCleanup(temporary.cleanup)
    directory = Path(temporary.name)
    manifest_path = directory / "manifest.json"
    manifest_path.write_text(json.dumps({"releases": []}), encoding="utf-8")
    candidates_path = directory / "candidates.json"
    candidates_path.write_text(json.dumps(
      self.candidates_document(manifest_path, []),
    ), encoding="utf-8")

    with patch.object(VERIFY, "run_bytes") as run:
      evidence = VERIFY.verify_candidates(
        manifest_path,
        candidates_path,
        Path("."),
        "gd_admin:",
        "rclone",
      )

    run.assert_not_called()
    self.assertEqual(evidence["schema_version"], 3)
    self.assertEqual(evidence["candidates"], [])
    self.assertEqual(evidence["results"], [])

  def test_verify_candidates_reports_a_verified_archive_candidate(self):
    temporary = tempfile.TemporaryDirectory()
    self.addCleanup(temporary.cleanup)
    directory = Path(temporary.name)
    contents = b"release zip bytes"
    checksum = "sha256:" + VERIFY.hashlib.sha256(contents).hexdigest()
    md5 = VERIFY.hashlib.md5(contents).hexdigest()
    release = {
      "version": "1.2.3",
      "full_zip_object_key": "kindow/kindow-1.2.3.zip",
      "checksum": checksum,
      "size_bytes": len(contents),
      "archive": {
        "github_release_id": 101,
        "github_asset_id": 202,
        "github_asset_name": "kindow-1.2.3.zip",
        "github_asset_sha256": checksum,
        "github_asset_digest": checksum,
        "github_asset_size_bytes": len(contents),
        "drive_object_key": "keyflowy/apps/kindow/releases/v1.2.3/kindow-1.2.3.zip",
        "drive_sha256": checksum,
        "drive_md5": md5,
        "drive_size_bytes": len(contents),
        "verified": True,
      },
    }
    manifest_path = directory / "manifest.json"
    manifest_path.write_text(json.dumps({"releases": [release]}), encoding="utf-8")
    candidates_path = directory / "candidates.json"
    candidates_path.write_text(json.dumps(self.candidates_document(
      manifest_path,
      [{"key": release["full_zip_object_key"], "reason": "archived-stable-expired"}],
    )), encoding="utf-8")

    github_listing = json.dumps([{
      "id": 202,
      "name": "kindow-1.2.3.zip",
      "digest": checksum,
      "size": len(contents),
    }]).encode()
    with patch.object(
      VERIFY,
      "run_bytes",
      side_effect=[github_listing, self.drive_listing(len(contents), md5)],
    ) as run:
      evidence = VERIFY.verify_candidates(
        manifest_path,
        candidates_path,
        Path("."),
        "gd_admin:",
        "rclone",
        github_repository="Keyflowy/kindow",
        gh="gh",
      )

    self.assertEqual(run.call_count, 2)
    self.assertEqual(
      run.call_args_list[0].args[0][-1],
      "repos/Keyflowy/kindow/releases/101/assets",
    )
    self.assertIn("lsjson", run.call_args_list[1].args[0])
    self.assertEqual(len(evidence["results"]), 1)
    result = evidence["results"][0]
    self.assertEqual(result["status"], "verified")
    self.assertEqual(result["archive"]["drive_md5"], md5)
    self.assertEqual(result["archive"]["github_asset_digest"], checksum)

  def test_verify_candidates_reports_a_failed_candidate_without_raising(self):
    temporary = tempfile.TemporaryDirectory()
    self.addCleanup(temporary.cleanup)
    directory = Path(temporary.name)
    manifest_path = directory / "manifest.json"
    manifest_path.write_text(json.dumps({"releases": []}), encoding="utf-8")
    candidates_path = directory / "candidates.json"
    candidates_path.write_text(json.dumps(self.candidates_document(
      manifest_path,
      [{"key": "kindow/releases/9.9.9.zip", "reason": "archived-stable-expired"}],
    )), encoding="utf-8")

    with patch.object(VERIFY, "run_bytes") as run:
      evidence = VERIFY.verify_candidates(
        manifest_path,
        candidates_path,
        Path("."),
        "gd_admin:",
        "rclone",
      )

    run.assert_not_called()
    self.assertEqual(evidence["results"][0]["status"], "failed")
    self.assertIn("exactly one manifest release", evidence["results"][0]["error"])

  def test_verify_candidates_rejects_a_manifest_digest_mismatch(self):
    temporary = tempfile.TemporaryDirectory()
    self.addCleanup(temporary.cleanup)
    directory = Path(temporary.name)
    manifest_path = directory / "manifest.json"
    manifest_path.write_text(json.dumps({"releases": []}), encoding="utf-8")
    document = self.candidates_document(manifest_path, [])
    document["manifest_sha256"] = "0" * 64
    candidates_path = directory / "candidates.json"
    candidates_path.write_text(json.dumps(document), encoding="utf-8")

    with self.assertRaisesRegex(ValueError, "manifest digest does not match"):
      VERIFY.verify_candidates(
        manifest_path,
        candidates_path,
        Path("."),
        "gd_admin:",
        "rclone",
      )

  def test_verify_candidates_rejects_an_unknown_reason(self):
    temporary = tempfile.TemporaryDirectory()
    self.addCleanup(temporary.cleanup)
    directory = Path(temporary.name)
    manifest_path = directory / "manifest.json"
    manifest_path.write_text(json.dumps({"releases": []}), encoding="utf-8")
    candidates_path = directory / "candidates.json"
    candidates_path.write_text(json.dumps(self.candidates_document(
      manifest_path,
      [{"key": "kindow/releases/1.2.3.zip", "reason": "superseded-stable-patch"}],
    )), encoding="utf-8")

    with self.assertRaisesRegex(ValueError, "not a verifiable deletion reason"):
      VERIFY.verify_candidates(
        manifest_path,
        candidates_path,
        Path("."),
        "gd_admin:",
        "rclone",
      )

  def test_verify_candidates_verifies_a_metadata_candidate(self):
    temporary = tempfile.TemporaryDirectory()
    self.addCleanup(temporary.cleanup)
    directory = Path(temporary.name)
    metadata, release, contents, md5 = self.metadata_fixture()
    manifest_path = directory / "manifest.json"
    manifest_path.write_text(json.dumps({"releases": [release]}), encoding="utf-8")
    metadata_dir = self.write_metadata_dir(
      directory / "release-state-metadata",
      {"1.2.3": [metadata]},
    )
    candidates_path = directory / "candidates.json"
    candidates_path.write_text(json.dumps(self.candidates_document(
      manifest_path,
      [{"key": metadata["object_key"], "reason": "expired-release-metadata"}],
      metadata_entries=[metadata],
    )), encoding="utf-8")

    historical_release = {
      key: release[key] for key in plan.RELEASE_IDENTITY_FIELDS if key in release
    }
    historical_manifest = json.dumps({"releases": [historical_release]}).encode()
    with patch.object(
      VERIFY,
      "run_bytes",
      side_effect=[
        self.drive_listing(len(contents), md5),
        b"",
        self.tombstone(release),
        historical_manifest,
      ],
    ) as run:
      evidence = VERIFY.verify_candidates(
        manifest_path,
        candidates_path,
        Path("."),
        "gd_admin:",
        "rclone",
        retention_metadata_dir=metadata_dir,
      )

    self.assertEqual(run.call_count, 4)
    self.assertIn("lsjson", run.call_args_list[0].args[0])
    self.assertIn("merge-base", run.call_args_list[1].args[0])
    result = evidence["results"][0]
    self.assertEqual(result["status"], "verified")
    self.assertEqual(result["metadata"]["drive_md5"], md5)
    self.assertEqual(
      result["metadata"]["manifest_entry_sha256"],
      release["completion"]["manifest_entry_sha256"],
    )

  def test_verify_candidates_rejects_a_metadata_digest_mismatch(self):
    temporary = tempfile.TemporaryDirectory()
    self.addCleanup(temporary.cleanup)
    directory = Path(temporary.name)
    metadata, release, _, _ = self.metadata_fixture()
    manifest_path = directory / "manifest.json"
    manifest_path.write_text(json.dumps({"releases": [release]}), encoding="utf-8")
    candidates_path = directory / "candidates.json"
    candidates_path.write_text(json.dumps(self.candidates_document(
      manifest_path,
      [{"key": metadata["object_key"], "reason": "expired-release-metadata"}],
      metadata_entries=[metadata],
    )), encoding="utf-8")

    with self.assertRaisesRegex(ValueError, "retention metadata digest does not match"):
      VERIFY.verify_candidates(
        manifest_path,
        candidates_path,
        Path("."),
        "gd_admin:",
        "rclone",
      )

  def test_given_a_transient_drive_failure_when_reading_evidence_then_a_fresh_process_retries(self):
    with (
      patch.object(VERIFY, "run_bytes", side_effect=[ValueError("timeout"), b"contents"]) as run,
      patch.object(VERIFY.time, "sleep") as sleep,
    ):
      contents = VERIFY.rclone_cat("rclone", "gd_admin:path/to/object")

    self.assertEqual(contents, b"contents")
    self.assertEqual(run.call_count, 2)
    self.assertEqual(run.call_args_list[0], run.call_args_list[1])
    sleep.assert_called_once_with(5)

  def test_github_asset_checksum_mismatch_fails_closed(self):
    contents = b"release zip bytes"
    checksum = "sha256:" + VERIFY.hashlib.sha256(contents).hexdigest()
    md5 = VERIFY.hashlib.md5(contents).hexdigest()
    release = {
      "version": "1.2.3",
      "full_zip_object_key": "kindow/kindow-1.2.3.zip",
      "checksum": checksum,
      "size_bytes": len(contents),
      "archive": {
        "github_release_id": 101,
        "github_asset_id": 202,
        "github_asset_name": "kindow-1.2.3.zip",
        "github_asset_sha256": checksum,
        "github_asset_digest": checksum,
        "github_asset_size_bytes": len(contents),
        "drive_object_key": "keyflowy/apps/kindow/releases/v1.2.3/kindow-1.2.3.zip",
        "drive_sha256": checksum,
        "drive_md5": md5,
        "drive_size_bytes": len(contents),
        "verified": True,
      },
    }

    with patch.object(
      VERIFY,
      "run_bytes",
      side_effect=[
        json.dumps([{
          "id": 202,
          "name": "kindow-1.2.3.zip",
          "digest": "sha256:" + "f" * 64,
          "size": len(contents),
        }]).encode(),
        self.drive_listing(len(contents), md5),
      ],
    ):
      with self.assertRaisesRegex(ValueError, "GitHub or Drive metadata differs"):
        VERIFY.verify_archive(
          release,
          Path("."),
          "Keyflowy/kindow",
          "gd_admin:",
          "rclone",
          "gh",
        )


if __name__ == "__main__":
  unittest.main()
