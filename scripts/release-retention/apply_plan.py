#!/usr/bin/env python3
"""Apply one reviewed release-retention plan with fail-closed checks.

The command always refreshes the remote inventory before doing anything. It
uses one ``rclone deletefile`` invocation per approved object and stops at the
first unexpected failure. Without ``--execute`` it performs only validation and
rclone dry-runs.
"""

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from plan import InventoryObject, canonical_sha256, parse_as_of, parse_inventory_value, require_key, sha256_file


UTC = timezone.utc
APPLY_CONTRACT_VERSION = 1
ALLOWED_DELETE_REASONS = {
  "superseded-stable-patch": "stable-installer",
  "expired-sparkle-delta": "sparkle-delta",
  "expired-prerelease": "prerelease-installer",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ApplyError(ValueError):
  pass


def load_json(path: Path) -> Any:
  try:
    return json.loads(path.read_text(encoding="utf-8"))
  except (OSError, json.JSONDecodeError) as error:
    raise ApplyError("invalid JSON in {}: {}".format(path, error)) from error


def parse_now(value: Optional[str]) -> datetime:
  try:
    return parse_as_of(value)
  except ValueError as error:
    raise ApplyError(str(error)) from error


def validate_remote_root(value: Any) -> str:
  if not isinstance(value, str) or not value:
    raise ApplyError("rclone_remote must be a non-empty remote root")
  if any(ord(character) < 32 or ord(character) == 127 or character == "\\" for character in value):
    raise ApplyError("rclone_remote contains unsafe characters")
  match = re.fullmatch(r"([A-Za-z0-9._-]+):(.+/)", value)
  if match is None:
    raise ApplyError("rclone_remote must look like remote:path/ and end in '/'")
  path = match.group(2)
  if any(part in ("", ".", "..") for part in path.rstrip("/").split("/")):
    raise ApplyError("rclone_remote must have a normalized path")
  return value


def validate_prefix(value: Any) -> str:
  if not isinstance(value, str) or not value.endswith("/"):
    raise ApplyError("r2_prefix must be a non-empty normalized prefix ending in '/'")
  require_key(value[:-1], "r2_prefix")
  return value


def normalize_fingerprint(value: Dict[str, Any], label: str) -> InventoryObject:
  key = require_key(value.get("key"), label + ".key")
  size_bytes = value.get("size_bytes")
  if not isinstance(size_bytes, int) or isinstance(size_bytes, bool) or size_bytes < 0:
    raise ApplyError("{}.size_bytes must be a non-negative integer".format(label))
  mod_time = value.get("mod_time")
  if not isinstance(mod_time, str) or not mod_time:
    raise ApplyError("{}.mod_time must be present".format(label))
  raw_hashes = value.get("hashes", {})
  if not isinstance(raw_hashes, dict):
    raise ApplyError("{}.hashes must be an object".format(label))
  hashes: List[Tuple[str, str]] = []
  for hash_name, hash_value in raw_hashes.items():
    if not isinstance(hash_name, str) or not hash_name or not isinstance(hash_value, str) or not hash_value:
      raise ApplyError("{}.hashes must contain non-empty strings".format(label))
    hashes.append((hash_name, hash_value))
  object_id = value.get("object_id")
  if object_id is not None and (not isinstance(object_id, str) or not object_id):
    raise ApplyError("{}.object_id must be a non-empty string".format(label))
  if not hashes and object_id is None:
    raise ApplyError("{}.fingerprint needs hashes or object_id".format(label))
  return InventoryObject(
    key=key,
    size_bytes=size_bytes,
    mod_time=mod_time,
    hashes=tuple(sorted(hashes)),
    object_id=object_id,
  )


def fingerprint_equal(left: InventoryObject, right: InventoryObject) -> bool:
  return left.as_dict() == right.as_dict()


def inventory_from_entries(entries: Sequence[Dict[str, Any]], label: str) -> Dict[str, InventoryObject]:
  result: Dict[str, InventoryObject] = {}
  for index, entry in enumerate(entries):
    if not isinstance(entry, dict):
      raise ApplyError("{}[{}] must be an object".format(label, index))
    item = normalize_fingerprint(entry, "{}[{}]".format(label, index))
    if item.key in result:
      raise ApplyError("duplicate object key in {}: {}".format(label, item.key))
    result[item.key] = item
  return result


def validate_plan(
  plan: Any,
  expected_plan_sha256: str,
  expected_product: str,
  expected_remote: str,
  expected_prefix: str,
  now: datetime,
  manifest_path: Optional[Path] = None,
  policy_path: Optional[Path] = None,
) -> Tuple[Dict[str, Any], Dict[str, InventoryObject], Dict[str, InventoryObject]]:
  if not isinstance(plan, dict):
    raise ApplyError("plan must be a JSON object")
  if plan.get("contract_version") != APPLY_CONTRACT_VERSION:
    raise ApplyError("unsupported plan contract_version")
  if not isinstance(plan.get("planner_version"), str) or not plan["planner_version"]:
    raise ApplyError("plan planner_version is missing")
  if not isinstance(expected_plan_sha256, str) or not SHA256_RE.fullmatch(expected_plan_sha256.lower()):
    raise ApplyError("expected_plan_sha256 must be a lowercase SHA-256 digest")
  stored_plan_id = plan.get("plan_id")
  unsigned_plan = dict(plan)
  unsigned_plan.pop("plan_id", None)
  actual_plan_id = canonical_sha256(unsigned_plan)
  if stored_plan_id != actual_plan_id or actual_plan_id != expected_plan_sha256.lower():
    raise ApplyError("plan digest does not match expected_plan_sha256")
  if plan.get("product") != expected_product:
    raise ApplyError("plan product does not match the approved product")
  remote = validate_remote_root(plan.get("rclone_remote"))
  prefix = validate_prefix(plan.get("r2_prefix"))
  if remote != expected_remote or prefix != expected_prefix:
    raise ApplyError("plan storage target does not match the approved target")
  if plan.get("inventory_complete") is not True:
    raise ApplyError("plan was not generated from a complete inventory")
  for field in ("manifest_sha256", "policy_sha256", "inventory_sha256"):
    if not isinstance(plan.get(field), str) or not SHA256_RE.fullmatch(plan[field]):
      raise ApplyError("plan {} must be a SHA-256 digest".format(field))
  try:
    expires_at = parse_as_of(plan.get("expires_at"))
    as_of = parse_as_of(plan.get("as_of"))
  except (TypeError, ValueError) as error:
    raise ApplyError("plan timestamps are invalid") from error
  if expires_at <= as_of or now > expires_at:
    raise ApplyError("plan has expired")
  if manifest_path is not None and sha256_file(manifest_path) != plan.get("manifest_sha256"):
    raise ApplyError("manifest digest does not match the approved plan")
  if policy_path is not None and sha256_file(policy_path) != plan.get("policy_sha256"):
    raise ApplyError("policy digest does not match the approved plan")

  keep_raw = plan.get("keep")
  delete_raw = plan.get("delete")
  if not isinstance(keep_raw, list) or not isinstance(delete_raw, list):
    raise ApplyError("plan keep and delete fields must be arrays")
  keep = inventory_from_entries(keep_raw, "keep")
  delete = inventory_from_entries(delete_raw, "delete")
  overlap = sorted(set(keep).intersection(delete))
  if overlap:
    raise ApplyError("object appears in both keep and delete: {}".format(overlap[0]))
  for key in list(keep) + list(delete):
    if not key.startswith(prefix):
      raise ApplyError("plan object is outside r2_prefix: {}".format(key))
  for index, entry in enumerate(delete_raw):
    reason = entry.get("reason")
    expected_kind = ALLOWED_DELETE_REASONS.get(reason)
    if expected_kind is None:
      raise ApplyError("delete[{}] has a non-deletable reason".format(index))
    if entry.get("kind") != expected_kind:
      raise ApplyError("delete[{}] kind does not match its reason".format(index))

  summary = plan.get("summary")
  if not isinstance(summary, dict):
    raise ApplyError("plan summary is missing")
  if summary.get("keep_count") != len(keep) or summary.get("delete_count") != len(delete):
    raise ApplyError("plan summary counts do not match entries")
  delete_bytes = sum(item.size_bytes or 0 for item in delete.values())
  if summary.get("delete_bytes") != delete_bytes:
    raise ApplyError("plan summary delete_bytes does not match entries")

  all_objects = list(keep.values()) + list(delete.values())
  if canonical_sha256([item.as_dict() for item in sorted(all_objects, key=lambda item: item.key)]) != plan.get("inventory_sha256"):
    raise ApplyError("plan inventory digest does not match entries")
  return plan, keep, delete


def run_command(rclone_bin: str, arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
  return subprocess.run(
    [rclone_bin, *arguments],
    check=False,
    capture_output=True,
    text=True,
  )


def list_inventory(rclone_bin: str, remote: str) -> Dict[str, InventoryObject]:
  result = run_command(rclone_bin, [
    "lsjson",
    "--recursive",
    "--files-only",
    "--hash",
    "--no-mimetype",
    remote,
  ])
  if result.returncode != 0:
    raise ApplyError("rclone lsjson failed: {}".format((result.stderr or result.stdout).strip()))
  try:
    return {item.key: item for item in parse_inventory_value(json.loads(result.stdout))}
  except (ApplyError, ValueError, json.JSONDecodeError) as error:
    raise ApplyError("rclone lsjson returned an invalid inventory: {}".format(error)) from error


def compare_inventory(
  expected_keep: Dict[str, InventoryObject],
  expected_delete: Dict[str, InventoryObject],
  actual: Dict[str, InventoryObject],
) -> None:
  expected_keys = set(expected_keep).union(expected_delete)
  extra = sorted(set(actual).difference(expected_keys))
  if extra:
    raise ApplyError("fresh inventory contains an unapproved object: {}".format(extra[0]))
  missing_keep = sorted(set(expected_keep).difference(actual))
  if missing_keep:
    raise ApplyError("fresh inventory is missing a protected object: {}".format(missing_keep[0]))
  for key, expected in expected_keep.items():
    if not fingerprint_equal(expected, actual[key]):
      raise ApplyError("protected object fingerprint changed: {}".format(key))
  for key, expected in expected_delete.items():
    if key in actual and not fingerprint_equal(expected, actual[key]):
      raise ApplyError("delete candidate fingerprint changed: {}".format(key))


def target_path(remote: str, key: str) -> str:
  return remote + key


def write_result(path: Optional[Path], result: Dict[str, Any]) -> None:
  if path is not None:
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


def apply_plan(
  plan: Dict[str, Any],
  keep: Dict[str, InventoryObject],
  delete: Dict[str, InventoryObject],
  rclone_bin: str,
  execute: bool,
  max_delete_objects: int,
  max_delete_bytes: int,
  approval_id: str,
  plan_run_id: str,
  plan_artifact_id: str,
  started_at: datetime,
) -> Tuple[int, Dict[str, Any]]:
  statuses: List[Dict[str, Any]] = []
  result: Dict[str, Any] = {
    "contract_version": APPLY_CONTRACT_VERSION,
    "plan_id": plan["plan_id"],
    "approval_id": approval_id,
    "plan_run_id": plan_run_id,
    "plan_artifact_id": plan_artifact_id,
    "product": plan["product"],
    "rclone_remote": plan["rclone_remote"],
    "r2_prefix": plan["r2_prefix"],
    "started_at": started_at.isoformat().replace("+00:00", "Z"),
    "execute": execute,
    "entries": statuses,
  }
  if max_delete_objects < 0 or max_delete_bytes < 0:
    result["status"] = "failed"
    result["error"] = "deletion limits must be non-negative"
    return 1, result
  delete_bytes = sum(item.size_bytes or 0 for item in delete.values())
  if len(delete) > max_delete_objects:
    result["status"] = "failed"
    result["error"] = "delete object count exceeds the configured limit"
    return 1, result
  if delete_bytes > max_delete_bytes:
    result["status"] = "failed"
    result["error"] = "delete byte count exceeds the configured limit"
    return 1, result

  remote = plan["rclone_remote"]
  try:
    actual = list_inventory(rclone_bin, remote)
    compare_inventory(keep, delete, actual)
  except ApplyError as error:
    result["status"] = "failed"
    result["error"] = str(error)
    return 1, result

  for key in sorted(delete):
    command = ["--dry-run", "deletefile", target_path(remote, key)]
    dry_run = run_command(rclone_bin, command)
    if dry_run.returncode != 0:
      statuses.append({"key": key, "status": "dry-run-failed", "error": (dry_run.stderr or dry_run.stdout).strip()})
      result["status"] = "failed"
      return 1, result
    statuses.append({"key": key, "status": "dry-run"})

  if not execute:
    result["status"] = "dry-run"
    return 0, result

  for index, key in enumerate(sorted(delete)):
    command_result = run_command(rclone_bin, ["deletefile", target_path(remote, key)])
    if command_result.returncode == 0:
      statuses[index]["status"] = "deleted"
      continue
    try:
      after_failure = list_inventory(rclone_bin, remote)
    except ApplyError:
      statuses[index]["status"] = "failed"
      statuses[index]["error"] = (command_result.stderr or command_result.stdout).strip()
      result["status"] = "failed"
      return 1, result
    if key not in after_failure:
      statuses[index]["status"] = "already-absent"
      continue
    statuses[index]["status"] = "failed"
    statuses[index]["error"] = (command_result.stderr or command_result.stdout).strip()
    result["status"] = "failed"
    return 1, result

  try:
    final_inventory = list_inventory(rclone_bin, remote)
    compare_inventory(keep, {}, final_inventory)
  except ApplyError as error:
    result["status"] = "failed"
    result["error"] = str(error)
    return 1, result
  result["finished_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
  result["status"] = "applied"
  return 0, result


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--plan", required=True, type=Path)
  parser.add_argument("--expected-plan-sha256", required=True)
  parser.add_argument("--product", required=True)
  parser.add_argument("--rclone-remote", required=True)
  parser.add_argument("--r2-prefix", required=True)
  parser.add_argument("--rclone-bin", default="rclone")
  parser.add_argument("--manifest", type=Path)
  parser.add_argument("--policy", type=Path)
  parser.add_argument("--max-delete-objects", type=int, default=100)
  parser.add_argument("--max-delete-bytes", type=int, default=50 * 1024 * 1024 * 1024)
  parser.add_argument("--approval-id", default="")
  parser.add_argument("--plan-run-id", default="")
  parser.add_argument("--plan-artifact-id", default="")
  parser.add_argument("--now")
  parser.add_argument("--result-output", type=Path, default=Path("apply-result.json"))
  parser.add_argument("--execute", action="store_true")
  return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
  args = parse_args(argv)
  started_at = parse_now(args.now)
  result: Dict[str, Any] = {
    "status": "failed",
    "started_at": started_at.isoformat().replace("+00:00", "Z"),
  }
  loaded_plan: Optional[Dict[str, Any]] = None
  try:
    if args.execute and (not args.approval_id or not args.plan_run_id or not args.plan_artifact_id):
      raise ApplyError("--execute requires approval-id, plan-run-id, and plan-artifact-id")
    plan = load_json(args.plan)
    if isinstance(plan, dict):
      loaded_plan = plan
    validated_plan, keep, delete = validate_plan(
      plan,
      args.expected_plan_sha256,
      args.product,
      args.rclone_remote,
      args.r2_prefix,
      started_at,
      args.manifest,
      args.policy,
    )
    code, result = apply_plan(
      validated_plan,
      keep,
      delete,
      args.rclone_bin,
      args.execute,
      args.max_delete_objects,
      args.max_delete_bytes,
      args.approval_id,
      args.plan_run_id,
      args.plan_artifact_id,
      started_at,
    )
    write_result(args.result_output, result)
    return code
  except (ApplyError, OSError) as error:
    if loaded_plan is not None:
      for field in ("contract_version", "plan_id", "product", "rclone_remote", "r2_prefix"):
        if field in loaded_plan:
          result[field] = loaded_plan[field]
      result["approval_id"] = args.approval_id
      result["plan_run_id"] = args.plan_run_id
      result["plan_artifact_id"] = args.plan_artifact_id
      result["execute"] = args.execute
    result["error"] = str(error)
    try:
      write_result(args.result_output, result)
    except OSError:
      pass
    sys.stderr.write("error: {}\n".format(error))
    return 2


if __name__ == "__main__":
  raise SystemExit(main())
