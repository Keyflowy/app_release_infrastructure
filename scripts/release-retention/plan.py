#!/usr/bin/env python3
"""Build a safe, deterministic release-retention plan.

This program only plans. It never calls rclone or deletes an object. Unknown
objects are kept so an incomplete manifest cannot cause an accidental delete.
"""

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Sequence, Tuple


UTC = timezone.utc
PLAN_CONTRACT_VERSION = 1
PLANNER_VERSION = "1"
SEMVER_RE = re.compile(
  r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
  r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
  r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
MANIFEST_TIMESTAMP_RE = re.compile(
  r"^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}"
  r"(?:\.[0-9]+)?(?:[Zz]|[+-][0-9]{2}:[0-9]{2})$"
)
MANIFEST_FIELDS = frozenset({
  "schema_version",
  "product",
  "generated_at",
  "appcast_object_key",
  "protected_object_keys",
  "releases",
})
REQUIRED_MANIFEST_FIELDS = frozenset({
  "schema_version",
  "product",
  "generated_at",
  "releases",
})
RELEASE_FIELDS = frozenset({
  "version",
  "feature_line",
  "release_date",
  "channel",
  "notarization_status",
  "fallback",
  "full_zip_object_key",
  "checksum",
  "checksum_object_key",
  "signature_object_key",
  "sparkle_delta_object_keys",
})
REQUIRED_RELEASE_FIELDS = frozenset({
  "version",
  "feature_line",
  "release_date",
  "channel",
  "notarization_status",
  "full_zip_object_key",
  "sparkle_delta_object_keys",
})


@dataclass(frozen=True)
class Artifact:
  key: str
  kind: str
  release_date: Optional[date] = None
  version: Optional[Tuple[int, int, int]] = None
  feature_line: Optional[str] = None
  fallback: bool = False
  notarized: bool = False


@dataclass(frozen=True)
class InventoryObject:
  key: str
  size_bytes: Optional[int] = None
  mod_time: Optional[str] = None
  hashes: Tuple[Tuple[str, str], ...] = ()
  object_id: Optional[str] = None

  def as_dict(self) -> Dict[str, Any]:
    value: Dict[str, Any] = {"key": self.key}
    if self.size_bytes is not None:
      value["size_bytes"] = self.size_bytes
    if self.mod_time is not None:
      value["mod_time"] = self.mod_time
    if self.hashes:
      value["hashes"] = dict(self.hashes)
    if self.object_id is not None:
      value["object_id"] = self.object_id
    return value


def load_json(path: Path) -> Any:
  try:
    return json.loads(path.read_text(encoding="utf-8"))
  except json.JSONDecodeError as error:
    raise ValueError("invalid JSON in {}: {}".format(path, error)) from error


def sha256_bytes(value: bytes) -> str:
  return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
  return sha256_bytes(path.read_bytes())


def canonical_sha256(value: Any) -> str:
  encoded = json.dumps(
    value,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=True,
  ).encode("utf-8")
  return sha256_bytes(encoded)


def _parse_simple_toml(path: Path) -> Dict[str, Any]:
  """Parse the flat policy subset on Python versions without tomllib.

  The checked-in policy deliberately uses only strings, integers, booleans,
  and arrays of strings, so this fallback stays small and dependency-free.
  """
  values: Dict[str, Any] = {}
  for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
    line = raw_line.strip()
    if not line or line.startswith("#"):
      continue
    if "=" not in line:
      raise ValueError("invalid policy line {} in {}".format(line_number, path))
    key, raw_value = line.split("=", 1)
    key = key.strip()
    raw_value = raw_value.strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
      raise ValueError("invalid policy key {!r}".format(key))
    if raw_value in ("true", "false"):
      values[key] = raw_value == "true"
      continue
    if re.fullmatch(r"-?[0-9]+", raw_value):
      values[key] = int(raw_value)
      continue
    if raw_value.startswith("[") and raw_value.endswith("]"):
      try:
        values[key] = json.loads(raw_value)
      except json.JSONDecodeError as error:
        raise ValueError("invalid policy array for {!r}".format(key)) from error
      continue
    if len(raw_value) >= 2 and raw_value[0] == '"' and raw_value[-1] == '"':
      try:
        values[key] = json.loads(raw_value)
      except json.JSONDecodeError as error:
        raise ValueError("invalid policy string for {!r}".format(key)) from error
      continue
    raise ValueError("unsupported policy value for {!r}".format(key))
  return values


def load_policy(path: Path) -> Dict[str, Any]:
  try:
    import tomllib
  except ImportError:
    policy = _parse_simple_toml(path)
  else:
    try:
      with path.open("rb") as policy_file:
        policy = tomllib.load(policy_file)
    except tomllib.TOMLDecodeError as error:
      raise ValueError("invalid TOML in {}: {}".format(path, error)) from error
  if not isinstance(policy, dict):
    raise ValueError("policy must be a TOML table")
  required = (
    "policy_version",
    "recent_stable_days",
    "fallback_strategy",
    "retain_sparkle_deltas_days",
    "retain_prereleases_days",
    "unknown_objects",
  )
  for key in required:
    if key not in policy:
      raise ValueError("policy is missing {!r}".format(key))
  if policy["policy_version"] != 1:
    raise ValueError("unsupported policy_version {!r}".format(policy["policy_version"]))
  if policy["fallback_strategy"] != "latest-stable-patch-per-feature-line":
    raise ValueError("unsupported fallback_strategy {!r}".format(policy["fallback_strategy"]))
  if policy["unknown_objects"] != "keep":
    raise ValueError("unknown_objects must be 'keep'")
  for key in ("recent_stable_days", "retain_sparkle_deltas_days", "retain_prereleases_days"):
    if not isinstance(policy[key], int) or isinstance(policy[key], bool) or policy[key] < 0:
      raise ValueError("{} must be a non-negative integer".format(key))
  return policy


def parse_release_date(value: Any, label: str) -> date:
  if not isinstance(value, str) or DATE_RE.fullmatch(value) is None:
    raise ValueError("{} must be an ISO date".format(label))
  try:
    return date.fromisoformat(value)
  except ValueError as error:
    raise ValueError("{} must be an ISO date".format(label)) from error


def parse_as_of(value: Optional[str]) -> datetime:
  if value is None:
    return datetime.now(UTC)
  normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
  try:
    parsed = datetime.fromisoformat(normalized)
  except ValueError as error:
    raise ValueError("--as-of must be an ISO timestamp") from error
  if parsed.tzinfo is None:
    parsed = parsed.replace(tzinfo=UTC)
  return parsed.astimezone(UTC)


def parse_semver(value: Any, label: str) -> Tuple[int, int, int, Optional[str]]:
  if not isinstance(value, str):
    raise ValueError("{} must be semantic version".format(label))
  match = SEMVER_RE.fullmatch(value)
  if match is None:
    raise ValueError("{} is not a supported semantic version: {!r}".format(label, value))
  return (int(match.group(1)), int(match.group(2)), int(match.group(3)), match.group(4))


def require_key(value: Any, label: str) -> str:
  if not isinstance(value, str) or not value:
    raise ValueError("{} must be a non-empty object key".format(label))
  if value.startswith("/") or "\\" in value or any(ord(character) < 32 or ord(character) == 127 for character in value):
    raise ValueError("{} is not a safe relative object key".format(label))
  parts = value.split("/")
  if any(part in ("", ".", "..") for part in parts):
    raise ValueError("{} is not a normalized object key".format(label))
  return value


def reject_unknown_fields(value: Dict[str, Any], allowed: FrozenSet[str], label: str) -> None:
  unknown = sorted(set(value) - allowed)
  if unknown:
    raise ValueError("{} has unknown field {!r}".format(label, unknown[0]))


def require_fields(value: Dict[str, Any], required: FrozenSet[str], label: str) -> None:
  missing = sorted(required - set(value))
  if missing:
    raise ValueError("{} is missing required field {!r}".format(label, missing[0]))


def require_unique(values: Sequence[str], label: str) -> None:
  if len(values) != len(set(values)):
    raise ValueError("{} must contain unique values".format(label))


def validate_manifest_timestamp(value: Any) -> None:
  if not isinstance(value, str) or MANIFEST_TIMESTAMP_RE.fullmatch(value) is None:
    raise ValueError("manifest generated_at must be an ISO date-time with a timezone")
  normalized = value[:-1] + "+00:00" if value[-1] in ("Z", "z") else value
  try:
    datetime.fromisoformat(normalized)
  except ValueError as error:
    raise ValueError("manifest generated_at must be an ISO date-time with a timezone") from error


def _optional_non_negative_integer(value: Any, label: str) -> Optional[int]:
  if value is None:
    return None
  if not isinstance(value, int) or isinstance(value, bool) or value < 0:
    raise ValueError("{} must be a non-negative integer".format(label))
  return value


def _optional_string(value: Any, label: str) -> Optional[str]:
  if value is None:
    return None
  if not isinstance(value, str) or not value:
    raise ValueError("{} must be a non-empty string".format(label))
  return value


def parse_inventory_value(raw: Any) -> List[InventoryObject]:
  if isinstance(raw, list):
    raw_objects = raw
  elif isinstance(raw, dict) and isinstance(raw.get("objects"), list):
    raw_objects = raw["objects"]
  else:
    raise ValueError("inventory must be an array or an object with an 'objects' array")

  objects: Dict[str, InventoryObject] = {}
  for index, item in enumerate(raw_objects):
    if isinstance(item, str):
      key = item
      size_bytes = None
      mod_time = None
      hashes: Tuple[Tuple[str, str], ...] = ()
      object_id = None
    elif isinstance(item, dict):
      if item.get("IsDir") is True:
        raise ValueError("inventory object {} must describe a file".format(index))
      key = item.get("key", item.get("object_key", item.get("Path")))
      size_bytes = _optional_non_negative_integer(
        item.get("size_bytes", item.get("Size")),
        "inventory object {} size".format(index),
      )
      mod_time = _optional_string(
        item.get("mod_time", item.get("ModTime")),
        "inventory object {} modification time".format(index),
      )
      raw_hashes = item.get("hashes", item.get("Hashes", {}))
      if raw_hashes is None:
        raw_hashes = {}
      if not isinstance(raw_hashes, dict):
        raise ValueError("inventory object {} hashes must be an object".format(index))
      normalized_hashes = []
      for hash_name, hash_value in raw_hashes.items():
        if not isinstance(hash_name, str) or not hash_name:
          raise ValueError("inventory object {} hash name must be a string".format(index))
        if not isinstance(hash_value, str) or not hash_value:
          raise ValueError("inventory object {} hash value must be a string".format(index))
        normalized_hashes.append((hash_name, hash_value))
      hashes = tuple(sorted(normalized_hashes))
      object_id = _optional_string(
        item.get("object_id", item.get("ID")),
        "inventory object {} ID".format(index),
      )
    else:
      raise ValueError("inventory object {} must be a string or object".format(index))

    object_key = require_key(key, "inventory object {} key".format(index))
    if object_key in objects:
      raise ValueError("inventory contains duplicate object key {!r}".format(object_key))
    objects[object_key] = InventoryObject(
      key=object_key,
      size_bytes=size_bytes,
      mod_time=mod_time,
      hashes=hashes,
      object_id=object_id,
    )
  return [objects[key] for key in sorted(objects)]


def parse_inventory(path: Optional[Path], manifest_keys: Iterable[str]) -> List[InventoryObject]:
  if path is None:
    return [InventoryObject(key=key) for key in sorted(set(manifest_keys))]
  return parse_inventory_value(load_json(path))


def scope_inventory(inventory: Sequence[InventoryObject], prefix: Optional[str]) -> List[InventoryObject]:
  """Keep only objects owned by this product when the remote root is shared."""
  if prefix is None:
    return list(inventory)
  return [item for item in inventory if item.key.startswith(prefix)]


def validate_storage(rclone_remote: str, allowed_prefix: str) -> None:
  if not isinstance(rclone_remote, str) or not re.fullmatch(r"[A-Za-z0-9._-]+:.+/", rclone_remote):
    raise ValueError("rclone_remote must look like remote:path/ and end in '/'")
  remote_path = rclone_remote.split(":", 1)[1]
  if any(part in ("", ".", "..") for part in remote_path.rstrip("/").split("/")):
    raise ValueError("rclone_remote must have a normalized path")
  if not allowed_prefix.endswith("/"):
    raise ValueError("allowed_prefix must end in '/'")
  require_key(allowed_prefix[:-1], "allowed_prefix")


def add_artifact(
  artifacts: Dict[str, List[Artifact]],
  key: Any,
  kind: str,
  release_date: Optional[date] = None,
  version: Optional[Tuple[int, int, int]] = None,
  feature_line: Optional[str] = None,
  fallback: bool = False,
  notarized: bool = False,
) -> None:
  object_key = require_key(key, "artifact object key")
  artifacts.setdefault(object_key, []).append(Artifact(
    key=object_key,
    kind=kind,
    release_date=release_date,
    version=version,
    feature_line=feature_line,
    fallback=fallback,
    notarized=notarized,
  ))


def load_manifest(path: Path) -> Tuple[Dict[str, List[Artifact]], str]:
  manifest = load_json(path)
  if not isinstance(manifest, dict):
    raise ValueError("manifest must be a JSON object")
  reject_unknown_fields(manifest, MANIFEST_FIELDS, "manifest")
  require_fields(manifest, REQUIRED_MANIFEST_FIELDS, "manifest")
  if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
    raise ValueError("manifest schema_version must be 1")
  product = manifest["product"]
  if not isinstance(product, str) or not product:
    raise ValueError("manifest product must be a non-empty string")
  validate_manifest_timestamp(manifest["generated_at"])
  releases = manifest["releases"]
  if not isinstance(releases, list):
    raise ValueError("manifest releases must be an array")

  artifacts: Dict[str, List[Artifact]] = {}
  if "appcast_object_key" in manifest:
    appcast_key = require_key(manifest["appcast_object_key"], "appcast_object_key")
    add_artifact(artifacts, appcast_key, "protected-metadata")
  raw_protected = manifest.get("protected_object_keys", [])
  if not isinstance(raw_protected, list):
    raise ValueError("protected_object_keys must be an array")
  protected_keys = []
  for index, key in enumerate(raw_protected):
    protected_key = require_key(key, "protected_object_keys[{}]".format(index))
    protected_keys.append(protected_key)
    add_artifact(artifacts, protected_key, "protected-metadata")
  require_unique(protected_keys, "protected_object_keys")

  for index, release in enumerate(releases):
    label = "releases[{}]".format(index)
    if not isinstance(release, dict):
      raise ValueError("{} must be an object".format(label))
    reject_unknown_fields(release, RELEASE_FIELDS, label)
    require_fields(release, REQUIRED_RELEASE_FIELDS, label)
    version_parts = parse_semver(release["version"], label + ".version")
    version = version_parts[:3]
    feature_line = release.get("feature_line")
    expected_feature_line = "{}.{}".format(version[0], version[1])
    if feature_line != expected_feature_line:
      raise ValueError(
        "{} feature_line must be {} for version {}".format(
          label, expected_feature_line, release.get("version")
        )
      )
    release_date = parse_release_date(release.get("release_date"), label + ".release_date")
    channel = release.get("channel")
    if channel not in ("stable", "prerelease"):
      raise ValueError("{} channel must be stable or prerelease".format(label))
    if channel == "stable" and version_parts[3] is not None:
      raise ValueError("{} stable release version cannot contain a prerelease suffix".format(label))
    notarization_status = release.get("notarization_status")
    if notarization_status not in ("notarized", "pending", "failed"):
      raise ValueError("{} notarization_status is invalid".format(label))
    fallback = release.get("fallback", False)
    if not isinstance(fallback, bool):
      raise ValueError("{} fallback must be boolean".format(label))
    if "checksum" in release:
      checksum = release["checksum"]
      if not isinstance(checksum, str) or not checksum:
        raise ValueError("{} checksum must be a non-empty string".format(label))
    full_key = require_key(release["full_zip_object_key"], label + ".full_zip_object_key")
    add_artifact(
      artifacts,
      full_key,
      "stable-installer" if channel == "stable" else "prerelease-installer",
      release_date=release_date,
      version=version,
      feature_line=feature_line,
      fallback=fallback,
      notarized=notarization_status == "notarized",
    )
    for field in ("checksum_object_key", "signature_object_key"):
      if field in release:
        metadata_key = require_key(release[field], label + "." + field)
        add_artifact(artifacts, metadata_key, "protected-metadata")
    delta_keys = release["sparkle_delta_object_keys"]
    if not isinstance(delta_keys, list):
      raise ValueError("{} sparkle_delta_object_keys must be an array".format(label))
    normalized_delta_keys = []
    for delta_index, delta_key in enumerate(delta_keys):
      normalized_delta_key = require_key(
        delta_key,
        "{}.sparkle_delta_object_keys[{}]".format(label, delta_index),
      )
      normalized_delta_keys.append(normalized_delta_key)
      add_artifact(
        artifacts,
        normalized_delta_key,
        "sparkle-delta",
        release_date=release_date,
        version=version,
        feature_line=feature_line,
      )
    require_unique(normalized_delta_keys, label + ".sparkle_delta_object_keys")
  return artifacts, product


def choose_latest_stable(artifacts: Dict[str, List[Artifact]]) -> Dict[str, Tuple[int, int, int]]:
  latest: Dict[str, Tuple[int, int, int]] = {}
  for descriptors in artifacts.values():
    for descriptor in descriptors:
      if descriptor.kind != "stable-installer" or not descriptor.notarized:
        continue
      if descriptor.feature_line is None or descriptor.version is None:
        continue
      current = latest.get(descriptor.feature_line)
      if current is None or descriptor.version > current:
        latest[descriptor.feature_line] = descriptor.version
  return latest


def decide_descriptor(
  descriptor: Artifact,
  recent_cutoff: date,
  delta_cutoff: date,
  prerelease_cutoff: date,
  latest_stable: Dict[str, Tuple[int, int, int]],
) -> Tuple[str, str]:
  if descriptor.kind == "protected-metadata":
    return "keep", "protected-metadata"
  if descriptor.fallback:
    return "keep", "fallback-release"
  if descriptor.kind == "stable-installer":
    if not descriptor.notarized:
      return "keep", "unverified-stable-installer"
    if descriptor.release_date is not None and descriptor.release_date >= recent_cutoff:
      return "keep", "recent-stable"
    if (
      descriptor.feature_line is not None
      and descriptor.version is not None
      and latest_stable.get(descriptor.feature_line) == descriptor.version
    ):
      return "keep", "latest-stable-patch-for-feature-line"
    return "delete", "superseded-stable-patch"
  if descriptor.kind == "sparkle-delta":
    if descriptor.release_date is not None and descriptor.release_date >= delta_cutoff:
      return "keep", "recent-sparkle-delta"
    return "delete", "expired-sparkle-delta"
  if descriptor.kind == "prerelease-installer":
    if descriptor.release_date is not None and descriptor.release_date >= prerelease_cutoff:
      return "keep", "recent-prerelease"
    return "delete", "expired-prerelease"
  return "keep", "unknown-artifact"


def inventory_entry(item: InventoryObject, kind: str, reason: str) -> Dict[str, Any]:
  entry: Dict[str, Any] = {
    "key": item.key,
    "kind": kind,
    "reason": reason,
  }
  if item.size_bytes is not None:
    entry["size_bytes"] = item.size_bytes
  if item.mod_time is not None:
    entry["mod_time"] = item.mod_time
  if item.hashes:
    entry["hashes"] = dict(item.hashes)
  if item.object_id is not None:
    entry["object_id"] = item.object_id
  return entry


def inventory_digest(inventory: Sequence[InventoryObject]) -> str:
  return canonical_sha256([item.as_dict() for item in inventory])


def build_plan(
  manifest_path: Path,
  policy_path: Path,
  inventory_path: Optional[Path] = None,
  as_of: Optional[datetime] = None,
  rclone_remote: Optional[str] = None,
  r2_prefix: Optional[str] = None,
  plan_ttl_hours: int = 24,
) -> Dict[str, Any]:
  if plan_ttl_hours <= 0:
    raise ValueError("plan_ttl_hours must be positive")
  if (rclone_remote is None) != (r2_prefix is None):
    raise ValueError("rclone_remote and r2_prefix must be provided together")
  if rclone_remote is not None and r2_prefix is not None:
    validate_storage(rclone_remote, r2_prefix)
  policy = load_policy(policy_path)
  artifacts, product = load_manifest(manifest_path)
  inventory = parse_inventory(inventory_path, artifacts.keys())
  if r2_prefix is not None:
    invalid_manifest_keys = sorted(key for key in artifacts if not key.startswith(r2_prefix))
    if invalid_manifest_keys:
      raise ValueError("manifest object is outside r2_prefix: {}".format(invalid_manifest_keys[0]))
    inventory = scope_inventory(inventory, r2_prefix)
  reference_time = as_of or datetime.now(UTC)
  if reference_time.tzinfo is None:
    reference_time = reference_time.replace(tzinfo=UTC)
  reference_time = reference_time.astimezone(UTC)
  reference_date = reference_time.date()
  recent_cutoff = reference_date - timedelta(days=policy["recent_stable_days"])
  delta_cutoff = reference_date - timedelta(days=policy["retain_sparkle_deltas_days"])
  prerelease_cutoff = reference_date - timedelta(days=policy["retain_prereleases_days"])
  latest_stable = choose_latest_stable(artifacts)

  keep: List[Dict[str, Any]] = []
  delete: List[Dict[str, Any]] = []
  unknown_count = 0
  for item in inventory:
    descriptors = artifacts.get(item.key)
    if descriptors is None:
      unknown_count += 1
      keep.append(inventory_entry(item, "unknown", "unknown-object"))
      continue
    decisions = [
      decide_descriptor(
        descriptor,
        recent_cutoff,
        delta_cutoff,
        prerelease_cutoff,
        latest_stable,
      )
      for descriptor in descriptors
    ]
    kind_set = {descriptor.kind for descriptor in descriptors}
    kind = next(iter(kind_set)) if len(kind_set) == 1 else "mixed"
    keep_decisions = [decision for decision in decisions if decision[0] == "keep"]
    if keep_decisions:
      reason = next(
        (reason for _, reason in keep_decisions if reason in ("fallback-release", "protected-metadata")),
        keep_decisions[0][1],
      )
      keep.append(inventory_entry(item, kind, reason))
    else:
      delete.append(inventory_entry(item, kind, decisions[0][1]))

  keep.sort(key=lambda item: item["key"])
  delete.sort(key=lambda item: item["key"])
  payload: Dict[str, Any] = {
    "contract_version": PLAN_CONTRACT_VERSION,
    "planner_version": PLANNER_VERSION,
    "product": product,
    "rclone_remote": rclone_remote,
    "r2_prefix": r2_prefix,
    "as_of": reference_time.isoformat().replace("+00:00", "Z"),
    "expires_at": (reference_time + timedelta(hours=plan_ttl_hours)).isoformat().replace("+00:00", "Z"),
    "inventory_complete": inventory_path is not None,
    "manifest_sha256": sha256_file(manifest_path),
    "policy_sha256": sha256_file(policy_path),
    "inventory_sha256": inventory_digest(inventory),
    "cutoffs": {
      "recent_stable": recent_cutoff.isoformat(),
      "sparkle_delta": delta_cutoff.isoformat(),
      "prerelease": prerelease_cutoff.isoformat(),
    },
    "keep": keep,
    "delete": delete,
    "summary": {
      "keep_count": len(keep),
      "delete_count": len(delete),
      "unknown_count": unknown_count,
      "delete_bytes": sum(item.get("size_bytes", 0) for item in delete),
    },
  }
  payload["plan_id"] = canonical_sha256(payload)
  return payload


def render_text(plan: Dict[str, Any]) -> str:
  lines = ["product: {}".format(plan["product"]), "as_of: {}".format(plan["as_of"]), ""]
  for item in plan["keep"]:
    lines.append("KEEP\t{}\t{}\t{}".format(item["kind"], item["reason"], item["key"]))
  for item in plan["delete"]:
    lines.append("DELETE\t{}\t{}\t{}".format(item["kind"], item["reason"], item["key"]))
  summary = plan["summary"]
  lines.extend([
    "",
    "summary: keep={} delete={} unknown={}".format(
      summary["keep_count"], summary["delete_count"], summary["unknown_count"]
    ),
  ])
  return "\n".join(lines) + "\n"


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--manifest", required=True, type=Path)
  parser.add_argument("--policy", required=True, type=Path)
  parser.add_argument(
    "--inventory",
    type=Path,
    help="JSON R2 inventory; omitted means plan all objects named by the manifest",
  )
  parser.add_argument("--as-of", help="UTC ISO timestamp for deterministic planning")
  parser.add_argument("--format", choices=("json", "text"), default="json")
  parser.add_argument("--output", type=Path, help="write the plan to this file")
  parser.add_argument("--rclone-remote", help="rclone remote root used by the apply step, for example cf_r2:keyflowy-apps/")
  parser.add_argument("--r2-prefix", help="complete object prefix, including trailing slash")
  parser.add_argument(
    "--plan-ttl-hours",
    type=int,
    default=24,
    help="hours after as-of during which a plan may be applied",
  )
  return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
  args = parse_args(argv)
  try:
    plan = build_plan(
      args.manifest,
      args.policy,
      args.inventory,
      parse_as_of(args.as_of),
      args.rclone_remote,
      args.r2_prefix,
      args.plan_ttl_hours,
    )
    rendered = render_text(plan) if args.format == "text" else json.dumps(plan, indent=2) + "\n"
    if args.output is None:
      sys.stdout.write(rendered)
    else:
      args.output.write_text(rendered, encoding="utf-8")
  except (OSError, ValueError) as error:
    sys.stderr.write("error: {}\n".format(error))
    return 2
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
