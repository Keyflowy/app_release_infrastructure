import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "release-retention"))
import apply_plan
import plan


UTC = timezone.utc
AS_OF = datetime(2026, 8, 26, tzinfo=UTC)
POLICY = ROOT / "config" / "release-retention.toml"
REMOTE = "cf_r2:keyflowy-apps/"
PREFIX = "kindow/"


def release(version, release_date):
  return {
    "version": version,
    "feature_line": ".".join(version.split(".")[:2]),
    "release_date": release_date,
    "channel": "stable",
    "notarization_status": "notarized",
    "full_zip_object_key": "kindow/releases/{}.zip".format(version),
    "sparkle_delta_object_keys": [],
  }


def inventory_item(version, size, digest):
  return {
    "Path": "kindow/releases/{}.zip".format(version),
    "Size": size,
    "ModTime": "2026-08-25T00:00:00Z",
    "Hashes": {"MD5": digest},
  }


class RetentionApplyTests(unittest.TestCase):
  def fixture(self):
    directory = tempfile.TemporaryDirectory()
    self.addCleanup(directory.cleanup)
    path = Path(directory.name)
    manifest = {
      "schema_version": 1,
      "product": "kindow",
      "generated_at": "2026-08-26T00:00:00Z",
      "releases": [
        release("3.1.0", "2024-01-01"),
        release("3.1.4", "2024-01-02"),
      ],
    }
    manifest_path = path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    inventory = [inventory_item("3.1.0", 10, "old"), inventory_item("3.1.4", 20, "new")]
    inventory_path = path / "inventory.json"
    inventory_path.write_text(json.dumps({"objects": inventory}), encoding="utf-8")
    retention_plan = plan.build_plan(
      manifest_path,
      POLICY,
      inventory_path,
      AS_OF,
      REMOTE,
      PREFIX,
    )
    plan_path = path / "retention-plan.json"
    plan_path.write_text(json.dumps(retention_plan), encoding="utf-8")
    return path, retention_plan, plan_path, manifest_path

  def result(self, args, calls):
    return CompletedProcess(args=args, returncode=0, stdout="", stderr="")

  def lsjson(self, objects):
    return json.dumps(objects)

  def test_rejects_a_tampered_plan_before_contacting_rclone(self):
    _, retention_plan, plan_path, _ = self.fixture()
    retention_plan["product"] = "other-product"
    plan_path.write_text(json.dumps(retention_plan), encoding="utf-8")
    with patch("apply_plan.subprocess.run") as run:
      code = apply_plan.main([
        "--plan", str(plan_path),
        "--expected-plan-sha256", retention_plan["plan_id"],
        "--product", "kindow",
        "--rclone-remote", REMOTE,
        "--r2-prefix", PREFIX,
        "--now", "2026-08-26T00:00:00Z",
      ])
    self.assertEqual(code, 2)
    run.assert_not_called()

  def test_rejects_new_unknown_object_and_performs_no_delete(self):
    _, retention_plan, plan_path, _ = self.fixture()
    objects = [
      inventory_item("3.1.0", 10, "old"),
      inventory_item("3.1.4", 20, "new"),
      {"Path": "kindow/unapproved.bin", "Size": 1, "ModTime": "2026-08-25T00:00:00Z", "Hashes": {"MD5": "x"}},
    ]
    calls = []

    def command(args, **kwargs):
      calls.append((args, kwargs))
      return self.result(args, calls) if args[1] == "lsjson" else self.result(args, calls)

    with patch("apply_plan.subprocess.run", side_effect=lambda args, **kwargs: CompletedProcess(
      args=args,
      returncode=0,
      stdout=self.lsjson(objects) if args[1] == "lsjson" else "",
      stderr="",
    )) as run:
      code = apply_plan.main([
        "--plan", str(plan_path),
        "--expected-plan-sha256", retention_plan["plan_id"],
        "--product", "kindow",
        "--rclone-remote", REMOTE,
        "--r2-prefix", PREFIX,
        "--now", "2026-08-26T00:00:00Z",
      ])
    self.assertEqual(code, 1)
    self.assertEqual(run.call_count, 1)
    self.assertEqual(run.call_args.args[0][1], "lsjson")

  def test_ignores_objects_from_other_products_in_a_shared_remote_root(self):
    _, retention_plan, plan_path, _ = self.fixture()
    objects = [
      inventory_item("3.1.0", 10, "old"),
      inventory_item("3.1.4", 20, "new"),
      {"Path": "other-app/releases/9.0.0.zip", "Size": 1, "ModTime": "2026-08-25T00:00:00Z", "Hashes": {"MD5": "other"}},
    ]
    with patch("apply_plan.subprocess.run", side_effect=lambda args, **kwargs: CompletedProcess(
      args=args,
      returncode=0,
      stdout=self.lsjson(objects) if args[1] == "lsjson" else "",
      stderr="",
    )) as run:
      code = apply_plan.main([
        "--plan", str(plan_path),
        "--expected-plan-sha256", retention_plan["plan_id"],
        "--product", "kindow",
        "--rclone-remote", REMOTE,
        "--r2-prefix", PREFIX,
        "--now", "2026-08-26T00:00:00Z",
      ])
    self.assertEqual(code, 0)
    self.assertEqual(run.call_count, 2)

  def test_without_execute_only_dry_runs_each_candidate_without_a_shell(self):
    _, retention_plan, plan_path, _ = self.fixture()
    objects = [inventory_item("3.1.0", 10, "old"), inventory_item("3.1.4", 20, "new")]

    def command(args, **kwargs):
      return CompletedProcess(
        args=args,
        returncode=0,
        stdout=self.lsjson(objects) if args[1] == "lsjson" else "",
        stderr="",
      )

    with patch("apply_plan.subprocess.run", side_effect=command) as run:
      code = apply_plan.main([
        "--plan", str(plan_path),
        "--expected-plan-sha256", retention_plan["plan_id"],
        "--product", "kindow",
        "--rclone-remote", REMOTE,
        "--r2-prefix", PREFIX,
        "--now", "2026-08-26T00:00:00Z",
      ])
    self.assertEqual(code, 0)
    self.assertEqual(run.call_count, 2)
    dry_run_args = run.call_args.args[0]
    self.assertEqual(dry_run_args[0:3], ["rclone", "--dry-run", "deletefile"])
    self.assertEqual(dry_run_args[3], REMOTE + "kindow/releases/3.1.0.zip")
    self.assertFalse(run.call_args.kwargs.get("shell", False))

  def test_execute_deletes_candidates_then_verifies_the_keep_set(self):
    _, retention_plan, plan_path, _ = self.fixture()
    initial = [inventory_item("3.1.0", 10, "old"), inventory_item("3.1.4", 20, "new")]
    final = [inventory_item("3.1.4", 20, "new")]
    outputs = [self.lsjson(initial), "", "", self.lsjson(final)]

    def command(args, **kwargs):
      output = outputs.pop(0)
      return CompletedProcess(args=args, returncode=0, stdout=output, stderr="")

    with patch("apply_plan.subprocess.run", side_effect=command) as run:
      code = apply_plan.main([
        "--plan", str(plan_path),
        "--expected-plan-sha256", retention_plan["plan_id"],
        "--product", "kindow",
        "--rclone-remote", REMOTE,
        "--r2-prefix", PREFIX,
        "--approval-id", "approval-123",
        "--plan-run-id", "run-123",
        "--plan-artifact-id", "artifact-123",
        "--now", "2026-08-26T00:00:00Z",
        "--execute",
      ])
    self.assertEqual(code, 0)
    self.assertEqual(run.call_count, 4)
    self.assertEqual(run.call_args_list[2].args[0][1:3], ["deletefile", REMOTE + "kindow/releases/3.1.0.zip"])

  def test_expired_plan_is_rejected(self):
    _, retention_plan, plan_path, _ = self.fixture()
    with patch("apply_plan.subprocess.run") as run:
      code = apply_plan.main([
        "--plan", str(plan_path),
        "--expected-plan-sha256", retention_plan["plan_id"],
        "--product", "kindow",
        "--rclone-remote", REMOTE,
        "--r2-prefix", PREFIX,
        "--now", "2026-08-27T01:00:00Z",
      ])
    self.assertEqual(code, 2)
    run.assert_not_called()

  def test_rejects_changed_fingerprint_before_running_dry_run(self):
    _, retention_plan, plan_path, _ = self.fixture()
    objects = [inventory_item("3.1.0", 11, "old"), inventory_item("3.1.4", 20, "new")]
    with patch("apply_plan.subprocess.run", return_value=CompletedProcess(
      args=["rclone"], returncode=0, stdout=self.lsjson(objects), stderr="",
    )) as run:
      code = apply_plan.main([
        "--plan", str(plan_path),
        "--expected-plan-sha256", retention_plan["plan_id"],
        "--product", "kindow",
        "--rclone-remote", REMOTE,
        "--r2-prefix", PREFIX,
        "--now", "2026-08-26T00:00:00Z",
      ])
    self.assertEqual(code, 1)
    self.assertEqual(run.call_count, 1)

  def test_already_absent_after_a_failed_delete_is_idempotent(self):
    _, retention_plan, plan_path, _ = self.fixture()
    initial = [inventory_item("3.1.0", 10, "old"), inventory_item("3.1.4", 20, "new")]
    final = [inventory_item("3.1.4", 20, "new")]
    responses = [
      CompletedProcess(args=["rclone"], returncode=0, stdout=self.lsjson(initial), stderr=""),
      CompletedProcess(args=["rclone"], returncode=0, stdout="", stderr=""),
      CompletedProcess(args=["rclone"], returncode=1, stdout="", stderr="not found"),
      CompletedProcess(args=["rclone"], returncode=0, stdout=self.lsjson(final), stderr=""),
      CompletedProcess(args=["rclone"], returncode=0, stdout=self.lsjson(final), stderr=""),
    ]
    with patch("apply_plan.subprocess.run", side_effect=responses) as run:
      code = apply_plan.main([
        "--plan", str(plan_path),
        "--expected-plan-sha256", retention_plan["plan_id"],
        "--product", "kindow",
        "--rclone-remote", REMOTE,
        "--r2-prefix", PREFIX,
        "--approval-id", "approval-123",
        "--plan-run-id", "run-123",
        "--plan-artifact-id", "artifact-123",
        "--now", "2026-08-26T00:00:00Z",
        "--execute",
      ])
    self.assertEqual(code, 0)
    self.assertEqual(run.call_count, 5)

  def test_execute_requires_an_explicit_approval_binding(self):
    _, retention_plan, plan_path, _ = self.fixture()
    with patch("apply_plan.subprocess.run") as run:
      code = apply_plan.main([
        "--plan", str(plan_path),
        "--expected-plan-sha256", retention_plan["plan_id"],
        "--product", "kindow",
        "--rclone-remote", REMOTE,
        "--r2-prefix", PREFIX,
        "--execute",
      ])
    self.assertEqual(code, 2)
    run.assert_not_called()

  def test_delete_limits_are_checked_before_remote_access(self):
    _, retention_plan, plan_path, _ = self.fixture()
    with patch("apply_plan.subprocess.run") as run:
      code = apply_plan.main([
        "--plan", str(plan_path),
        "--expected-plan-sha256", retention_plan["plan_id"],
        "--product", "kindow",
        "--rclone-remote", REMOTE,
        "--r2-prefix", PREFIX,
        "--max-delete-objects", "0",
        "--now", "2026-08-26T00:00:00Z",
      ])
    self.assertEqual(code, 1)
    run.assert_not_called()


if __name__ == "__main__":
  unittest.main()
