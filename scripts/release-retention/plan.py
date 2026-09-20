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
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Sequence, Tuple


UTC = timezone.utc
PLAN_CONTRACT_VERSION = 2
PLANNER_VERSION = "2"
LEGACY_PLANNER_VERSION = "1"
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
  "retention_metadata",
  "appcast_referenced_object_keys",
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
  "size_bytes",
  "checksum",
  "checksum_object_key",
  "signature_object_key",
  "sparkle_delta_object_keys",
  "archive",
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
POLICY_FIELDS = frozenset({
  "policy_version",
  "recent_stable_days",
  "fallback_strategy",
  "retain_sparkle_deltas_days",
  "retain_prereleases_days",
  "retain_metadata_days",
  "fallback_cache_prefix",
  "fallback_cache_lifecycle_days",
  "excluded_prefixes",
  "max_delete_objects",
  "max_delete_bytes",
  "unknown_objects",
})

ARCHIVE_FIELDS = frozenset({
  "github_release_id",
  "github_asset_id",
  "github_asset_name",
  "github_asset_sha256",
  "github_asset_digest",
  "github_asset_size_bytes",
  "drive_object_key",
  "drive_sha256",
  "drive_md5",
  "drive_size_bytes",
  "verified",
})
METADATA_FIELDS = frozenset({
  "object_key",
  "release_date",
  "checksum",
  "size_bytes",
  "backup",
  "completion",
  # These aliases are accepted so callers can use names that mirror the
  # storage systems while the normalized planner representation stays flat.
  "drive_backup",
  "git_completion_tombstone",
})
BACKUP_FIELDS = frozenset({
  "drive_object_key",
  "sha256",
  "md5",
  "size_bytes",
  "verified",
})
COMPLETION_FIELDS = frozenset({
  "git_path",
  "git_commit",
  "path",
  "commit",
  "verified",
})
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
GIT_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40,64}$")


@dataclass(frozen=True)
class Artifact:
  key: str
  kind: str
  release_date: Optional[date] = None
  version: Optional[Tuple[int, int, int]] = None
  feature_line: Optional[str] = None
  fallback: bool = False
  notarized: bool = False
  checksum: Optional[str] = None
  size_bytes: Optional[int] = None
  archive: Optional[Dict[str, Any]] = None
  metadata_verified: bool = False


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
  unknown = sorted(set(policy) - POLICY_FIELDS)
  if unknown:
    raise ValueError("policy has unknown field {!r}".format(unknown[0]))
  required_fields = {
    "policy_version",
    "recent_stable_days",
    "fallback_strategy",
    "retain_sparkle_deltas_days",
    "retain_prereleases_days",
    "unknown_objects",
  }
  if policy.get("policy_version") == 2:
    required_fields.update({
      "retain_metadata_days",
      "fallback_cache_prefix",
      "fallback_cache_lifecycle_days",
      "excluded_prefixes",
      "max_delete_objects",
      "max_delete_bytes",
    })
  for key in sorted(required_fields):
    if key not in policy:
      raise ValueError("policy is missing {!r}".format(key))
  if policy["policy_version"] not in (1, 2):
    raise ValueError("unsupported policy_version {!r}".format(policy["policy_version"]))
  allowed_strategies = {
    1: "latest-stable-patch-per-feature-line",
    2: "archive-backed-exact-version",
  }
  if policy["fallback_strategy"] != allowed_strategies[policy["policy_version"]]:
    raise ValueError("unsupported fallback_strategy {!r}".format(policy["fallback_strategy"]))
  if policy["unknown_objects"] != "keep":
    raise ValueError("unknown_objects must be 'keep'")
  for key in ("recent_stable_days", "retain_sparkle_deltas_days", "retain_prereleases_days"):
    if not isinstance(policy[key], int) or isinstance(policy[key], bool) or policy[key] < 0:
      raise ValueError("{} must be a non-negative integer".format(key))
  if policy["policy_version"] == 2:
    if not isinstance(policy["retain_metadata_days"], int) or isinstance(policy["retain_metadata_days"], bool) or policy["retain_metadata_days"] < 0:
      raise ValueError("retain_metadata_days must be a non-negative integer")
    if not isinstance(policy["fallback_cache_prefix"], str) or not policy["fallback_cache_prefix"].endswith("/"):
      raise ValueError("fallback_cache_prefix must be a non-empty normalized prefix")
    require_key(policy["fallback_cache_prefix"][:-1], "fallback_cache_prefix")
    if not isinstance(policy["fallback_cache_lifecycle_days"], int) or isinstance(policy["fallback_cache_lifecycle_days"], bool) or policy["fallback_cache_lifecycle_days"] <= 0:
      raise ValueError("fallback_cache_lifecycle_days must be a positive integer")
    excluded = policy["excluded_prefixes"]
    if not isinstance(excluded, list) or not all(isinstance(item, str) for item in excluded):
      raise ValueError("excluded_prefixes must be an array of strings")
    normalized_excluded = []
    for item in excluded:
      if not item.endswith("/"):
        raise ValueError("excluded_prefixes must contain prefixes ending in '/'")
      require_key(item[:-1], "excluded_prefixes entry")
      if item not in normalized_excluded:
        normalized_excluded.append(item)
    policy["excluded_prefixes"] = sorted(normalized_excluded)
    for key in ("max_delete_objects", "max_delete_bytes"):
      if not isinstance(policy[key], int) or isinstance(policy[key], bool) or policy[key] < 0:
        raise ValueError("{} must be a non-negative integer".format(key))
  else:
    # Legacy policies intentionally do not opt into archive or lifecycle
    # behavior. These defaults make the plan envelope self-describing while
    # preserving the v1 decision rules for existing callers.
    policy.setdefault("retain_metadata_days", 0)
    policy.setdefault("fallback_cache_prefix", "")
    policy.setdefault("fallback_cache_lifecycle_days", 0)
    policy.setdefault("excluded_prefixes", [])
    policy.setdefault("max_delete_objects", 2**31 - 1)
    policy.setdefault("max_delete_bytes", 2**63 - 1)
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


def require_sha256(value: Any, label: str) -> str:
  if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
    raise ValueError("{} must be a sha256:<64 lowercase hex> checksum".format(label))
  return value


def require_md5(value: Any, label: str) -> str:
  if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{32}", value.lower()) is None:
    raise ValueError("{} must be a 32-character lowercase MD5 checksum".format(label))
  return value.lower()


def require_positive_integer(value: Any, label: str) -> int:
  if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
    raise ValueError("{} must be a positive integer".format(label))
  return value


def validate_archive(value: Any, label: str) -> Dict[str, Any]:
  if not isinstance(value, dict):
    raise ValueError("{} must be an object".format(label))
  reject_unknown_fields(value, ARCHIVE_FIELDS, label)
  require_fields(value, {
    "github_release_id",
    "github_asset_id",
    "github_asset_name",
    "github_asset_sha256",
    "github_asset_size_bytes",
    "drive_object_key",
    "drive_sha256",
    "drive_size_bytes",
    "verified",
  }, label)

  for field in ("github_release_id", "github_asset_id"):
    identifier = value[field]
    if isinstance(identifier, bool) or not isinstance(identifier, (str, int)):
      raise ValueError("{}.{} must be a positive numeric identifier".format(label, field))
    if not re.fullmatch(r"[1-9][0-9]*", str(identifier)):
      raise ValueError("{}.{} must be a positive numeric identifier".format(label, field))
  asset_name = value["github_asset_name"]
  if not isinstance(asset_name, str) or not asset_name or "/" in asset_name or "\\" in asset_name:
    raise ValueError("{}.github_asset_name must be a file name".format(label))
  require_sha256(value["github_asset_sha256"], label + ".github_asset_sha256")
  if "github_asset_digest" in value:
    require_sha256(value["github_asset_digest"], label + ".github_asset_digest")
  require_sha256(value["drive_sha256"], label + ".drive_sha256")
  if "drive_md5" in value:
    require_md5(value["drive_md5"], label + ".drive_md5")
  require_positive_integer(value["github_asset_size_bytes"], label + ".github_asset_size_bytes")
  require_positive_integer(value["drive_size_bytes"], label + ".drive_size_bytes")
  require_key(value["drive_object_key"], label + ".drive_object_key")
  if not isinstance(value["verified"], bool):
    raise ValueError("{}.verified must be boolean".format(label))
  return dict(value)


def _normalize_alias(value: Dict[str, Any], primary: str, alias: str, label: str) -> Any:
  if primary in value and alias in value and value[primary] != value[alias]:
    raise ValueError("{} has conflicting {!r} and {!r}".format(label, primary, alias))
  return value.get(primary, value.get(alias))


def validate_metadata_backup(value: Any, label: str) -> Dict[str, Any]:
  if not isinstance(value, dict):
    raise ValueError("{} must be an object".format(label))
  reject_unknown_fields(value, BACKUP_FIELDS, label)
  require_fields(value, {"drive_object_key", "sha256", "size_bytes", "verified"}, label)
  require_key(value["drive_object_key"], label + ".drive_object_key")
  require_sha256(value["sha256"], label + ".sha256")
  if "md5" in value:
    require_md5(value["md5"], label + ".md5")
  require_positive_integer(value["size_bytes"], label + ".size_bytes")
  if not isinstance(value["verified"], bool):
    raise ValueError("{}.verified must be boolean".format(label))
  return dict(value)


def validate_metadata_completion(value: Any, label: str) -> Dict[str, Any]:
  if not isinstance(value, dict):
    raise ValueError("{} must be an object".format(label))
  reject_unknown_fields(value, COMPLETION_FIELDS, label)
  path = _normalize_alias(value, "git_path", "path", label)
  commit = _normalize_alias(value, "git_commit", "commit", label)
  if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path:
    raise ValueError("{}.git_path must be a repository-relative path".format(label))
  path_parts = path.split("/")
  if any(part in ("", ".", "..") for part in path_parts):
    raise ValueError("{}.git_path must be normalized".format(label))
  if not isinstance(commit, str) or GIT_COMMIT_RE.fullmatch(commit) is None:
    raise ValueError("{}.git_commit must be a full Git commit SHA".format(label))
  if not isinstance(value.get("verified"), bool):
    raise ValueError("{}.verified must be boolean".format(label))
  return {
    "git_path": path,
    "git_commit": commit.lower(),
    "verified": value["verified"],
  }


def validate_retention_metadata(value: Any, label: str) -> Dict[str, Any]:
  if not isinstance(value, dict):
    raise ValueError("{} must be an object".format(label))
  reject_unknown_fields(value, METADATA_FIELDS, label)
  require_fields(value, {"object_key", "release_date", "checksum", "size_bytes"}, label)
  object_key = require_key(value["object_key"], label + ".object_key")
  release_date = parse_release_date(value["release_date"], label + ".release_date")
  checksum = require_sha256(value["checksum"], label + ".checksum")
  size_bytes = require_positive_integer(value["size_bytes"], label + ".size_bytes")
  raw_backup = _normalize_alias(value, "backup", "drive_backup", label)
  raw_completion = _normalize_alias(value, "completion", "git_completion_tombstone", label)
  if raw_backup is None:
    raise ValueError("{} is missing required field 'backup'".format(label))
  if raw_completion is None:
    raise ValueError("{} is missing required field 'completion'".format(label))
  backup = validate_metadata_backup(raw_backup, label + ".backup")
  completion = validate_metadata_completion(raw_completion, label + ".completion")
  return {
    "object_key": object_key,
    "release_date": release_date,
    "checksum": checksum,
    "size_bytes": size_bytes,
    "backup": backup,
    "completion": completion,
  }


def archive_is_verified(
  descriptor: Artifact,
  inventory_object: Optional[InventoryObject] = None,
  evidence_keys: FrozenSet[str] = frozenset(),
) -> bool:
  archive = descriptor.archive
  if descriptor.kind != "stable-installer" or archive is None:
    return False
  if descriptor.checksum is None or descriptor.size_bytes is None:
    return False
  if not SHA256_RE.fullmatch(descriptor.checksum):
    return False
  if descriptor.key not in evidence_keys:
    return False
  manifest_matches = (
    archive.get("verified") is True
    and archive.get("github_asset_sha256") == descriptor.checksum
    and archive.get("drive_sha256") == descriptor.checksum
    and archive.get("github_asset_size_bytes") == descriptor.size_bytes
    and archive.get("drive_size_bytes") == descriptor.size_bytes
    and archive.get("github_asset_name") == Path(descriptor.key).name
  )
  if not manifest_matches or inventory_object is None:
    return manifest_matches
  if inventory_object.size_bytes is not None and inventory_object.size_bytes != descriptor.size_bytes:
    return False
  hashes = {name.lower().replace("-", ""): value.lower() for name, value in inventory_object.hashes}
  inventory_sha256 = hashes.get("sha256")
  if inventory_sha256 is not None and inventory_sha256 != descriptor.checksum.removeprefix("sha256:"):
    return False
  return True


def metadata_is_verified(
  descriptor: Artifact,
  inventory_object: Optional[InventoryObject] = None,
) -> bool:
  if descriptor.kind != "release-metadata" or not descriptor.metadata_verified:
    return False
  if inventory_object is None:
    return True
  if inventory_object.size_bytes is not None and inventory_object.size_bytes != descriptor.size_bytes:
    return False
  hashes = {name.lower().replace("-", ""): value.lower() for name, value in inventory_object.hashes}
  inventory_sha256 = hashes.get("sha256")
  if inventory_sha256 is not None and inventory_sha256 != descriptor.checksum.removeprefix("sha256:"):
    return False
  return True


def load_archive_evidence(
  path: Path,
  manifest_path: Path,
  artifacts: Dict[str, List[Artifact]],
) -> FrozenSet[str]:
  """Validate live GitHub/Drive metadata before allowing deletion."""
  evidence = load_json(path)
  if not isinstance(evidence, dict):
    raise ValueError("archive evidence must be a JSON object")
  evidence_version = evidence.get("schema_version")
  if evidence_version not in (1, 2):
    raise ValueError("unsupported archive evidence schema_version")
  manifest_digest = evidence.get("manifest_sha256")
  expected_manifest_digest = "sha256:" + sha256_file(manifest_path)
  if manifest_digest != expected_manifest_digest:
    raise ValueError("archive evidence manifest digest does not match the plan manifest")
  entries = evidence.get("archives")
  if not isinstance(entries, list):
    raise ValueError("archive evidence archives must be an array")

  archive_descriptors = {
    descriptor.key: descriptor
    for descriptors in artifacts.values()
    for descriptor in descriptors
    if descriptor.archive is not None
  }
  verified_keys = set()
  for index, entry in enumerate(entries):
    label = "archive evidence archives[{}]".format(index)
    if not isinstance(entry, dict):
      raise ValueError("{} must be an object".format(label))
    key = require_key(entry.get("full_zip_object_key"), label + ".full_zip_object_key")
    if key in verified_keys:
      raise ValueError("duplicate archive evidence for {}".format(key))
    descriptor = archive_descriptors.get(key)
    if descriptor is None or descriptor.archive is None:
      raise ValueError("{} does not match a manifest archive".format(label))
    archive = descriptor.archive
    if (
      entry.get("version") is None
      or entry.get("version") != ".".join(str(part) for part in descriptor.version or ())
      or entry.get("github_release_id") != archive.get("github_release_id")
      or entry.get("github_asset_id") != archive.get("github_asset_id")
      or entry.get("github_asset_name") != archive.get("github_asset_name")
      or entry.get("drive_object_key") != archive.get("drive_object_key")
      or entry.get("verified") is not True
    ):
      raise ValueError("{} identity does not match the manifest archive".format(label))
    github_size = require_positive_integer(entry.get("github_asset_size_bytes"), label + ".github_asset_size_bytes")
    drive_size = require_positive_integer(entry.get("drive_size_bytes"), label + ".drive_size_bytes")
    if evidence_version == 1:
      github_checksum = require_sha256(entry.get("github_asset_sha256"), label + ".github_asset_sha256")
      drive_checksum = require_sha256(entry.get("drive_sha256"), label + ".drive_sha256")
      if (
        github_checksum != descriptor.checksum
        or drive_checksum != descriptor.checksum
        or github_size != descriptor.size_bytes
        or drive_size != descriptor.size_bytes
      ):
        raise ValueError("{} checksum or size does not match the manifest archive".format(label))
    else:
      github_digest = require_sha256(entry.get("github_asset_digest"), label + ".github_asset_digest")
      drive_md5 = require_md5(entry.get("drive_md5"), label + ".drive_md5")
      archive = descriptor.archive
      if (
        github_digest != archive.get("github_asset_digest")
        or drive_md5 != archive.get("drive_md5", "").lower()
        or github_digest != descriptor.checksum
        or github_size != descriptor.size_bytes
        or drive_size != descriptor.size_bytes
      ):
        raise ValueError("{} metadata or size does not match the manifest archive".format(label))
    verified_keys.add(key)

  missing = sorted(set(archive_descriptors).difference(verified_keys))
  if missing:
    raise ValueError("archive evidence is missing manifest archive {}".format(missing[0]))
  return frozenset(verified_keys)


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


def scope_managed_inventory(
  inventory: Sequence[InventoryObject],
  prefix: Optional[str],
  excluded_prefixes: Sequence[str] = (),
) -> List[InventoryObject]:
  """Scope inventory and leave cache/manual prefixes outside retention."""
  scoped = scope_inventory(inventory, prefix)
  excluded = tuple(excluded_prefixes)
  return [item for item in scoped if not any(item.key.startswith(value) for value in excluded)]


def _appcast_key_from_url(value: Any, r2_prefix: Optional[str]) -> Optional[str]:
  if not isinstance(value, str) or not value:
    return None
  parsed = urllib.parse.urlparse(value)
  if parsed.scheme or parsed.netloc:
    candidate = urllib.parse.unquote(parsed.path).lstrip("/")
  else:
    candidate = urllib.parse.unquote(value).lstrip("/")
  if not candidate:
    return None
  if r2_prefix is None:
    return candidate
  if candidate.startswith(r2_prefix):
    return candidate
  if parsed.scheme or parsed.netloc:
    return None
  return r2_prefix + candidate


def parse_appcast_references(path: Optional[Path], r2_prefix: Optional[str] = None) -> List[str]:
  """Extract enclosure/delta object keys from a Sparkle appcast snapshot."""
  if path is None:
    return []
  try:
    raw = path.read_bytes()
  except OSError as error:
    raise ValueError("unable to read appcast: {}".format(error)) from error
  values: List[Any] = []
  try:
    root = ET.fromstring(raw)
    for element in root.iter():
      for attribute in ("url", "sparkle:url"):
        if attribute in element.attrib:
          values.append(element.attrib[attribute])
  except ET.ParseError:
    try:
      decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
      raise ValueError("appcast must be XML or a JSON array") from error
    if isinstance(decoded, list):
      values.extend(decoded)
    elif isinstance(decoded, dict):
      raw_values = decoded.get("references", decoded.get("appcast_referenced_object_keys", []))
      if not isinstance(raw_values, list):
        raise ValueError("appcast JSON references must be an array")
      values.extend(raw_values)
    else:
      raise ValueError("appcast must be XML or a JSON array")
  references = []
  for value in values:
    key = _appcast_key_from_url(value, r2_prefix)
    if key is None:
      continue
    references.append(require_key(key, "appcast reference"))
  return sorted(set(references))


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
  checksum: Optional[str] = None,
  size_bytes: Optional[int] = None,
  archive: Optional[Dict[str, Any]] = None,
  metadata_verified: bool = False,
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
    checksum=checksum,
    size_bytes=size_bytes,
    archive=archive,
    metadata_verified=metadata_verified,
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
  raw_appcast_references = manifest.get("appcast_referenced_object_keys", [])
  if not isinstance(raw_appcast_references, list):
    raise ValueError("appcast_referenced_object_keys must be an array")
  appcast_references = []
  for index, key in enumerate(raw_appcast_references):
    reference_key = require_key(key, "appcast_referenced_object_keys[{}]".format(index))
    appcast_references.append(reference_key)
    # Appcast references are hot dependencies, not protected metadata. They
    # remain eligible for normal age handling once no longer referenced.
    add_artifact(artifacts, reference_key, "appcast-reference")
  require_unique(appcast_references, "appcast_referenced_object_keys")
  raw_protected = manifest.get("protected_object_keys", [])
  if not isinstance(raw_protected, list):
    raise ValueError("protected_object_keys must be an array")
  protected_keys = []
  for index, key in enumerate(raw_protected):
    protected_key = require_key(key, "protected_object_keys[{}]".format(index))
    protected_keys.append(protected_key)
    add_artifact(artifacts, protected_key, "protected-metadata")
  require_unique(protected_keys, "protected_object_keys")

  raw_retention_metadata = manifest.get("retention_metadata", [])
  if not isinstance(raw_retention_metadata, list):
    raise ValueError("retention_metadata must be an array")
  for index, raw_metadata in enumerate(raw_retention_metadata):
    label = "retention_metadata[{}]".format(index)
    metadata = validate_retention_metadata(raw_metadata, label)
    add_artifact(
      artifacts,
      metadata["object_key"],
      "release-metadata",
      release_date=metadata["release_date"],
      checksum=metadata["checksum"],
      size_bytes=metadata["size_bytes"],
      metadata_verified=(
        metadata["backup"]["verified"] is True
        and metadata["backup"]["sha256"] == metadata["checksum"]
        and metadata["backup"]["size_bytes"] == metadata["size_bytes"]
        and metadata["completion"]["verified"] is True
      ),
    )

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
    checksum = None
    if "checksum" in release:
      checksum = release["checksum"]
      if not isinstance(checksum, str) or not checksum:
        raise ValueError("{} checksum must be a non-empty string".format(label))
    size_bytes = None
    if "size_bytes" in release:
      size_bytes = release["size_bytes"]
      if not isinstance(size_bytes, int) or isinstance(size_bytes, bool) or size_bytes <= 0:
        raise ValueError("{} size_bytes must be a positive integer".format(label))
    archive = None
    if "archive" in release:
      archive = validate_archive(release["archive"], label + ".archive")
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
      checksum=checksum,
      size_bytes=size_bytes,
      archive=archive,
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
  archive_policy: bool = False,
  appcast_references: FrozenSet[str] = frozenset(),
  metadata_cutoff: Optional[date] = None,
  inventory_object: Optional[InventoryObject] = None,
  archive_evidence_keys: FrozenSet[str] = frozenset(),
) -> Tuple[str, str]:
  if descriptor.kind == "protected-metadata":
    return "keep", "protected-metadata"
  if descriptor.kind == "release-metadata":
    if not archive_policy:
      return "keep", "protected-metadata"
    if descriptor.release_date is not None and metadata_cutoff is not None and descriptor.release_date >= metadata_cutoff:
      return "keep", "recent-release-metadata"
    if metadata_is_verified(descriptor, inventory_object):
      return "delete", "expired-release-metadata"
    return "keep", "unverified-release-metadata"
  if descriptor.kind == "appcast-reference":
    return "keep", "appcast-reference"
  if descriptor.key in appcast_references:
    return "keep", "appcast-reference"
  if descriptor.fallback and not archive_policy:
    return "keep", "fallback-release"
  if descriptor.kind == "stable-installer":
    if not descriptor.notarized:
      return "keep", "unverified-stable-installer"
    if descriptor.release_date is not None and descriptor.release_date >= recent_cutoff:
      return "keep", "recent-stable"
    if archive_policy:
      if archive_is_verified(descriptor, inventory_object, archive_evidence_keys):
        return "delete", "archived-stable-expired"
      return "keep", "awaiting-archive-verification"
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


def bounded_delete_batch(
  candidates: Sequence[Dict[str, Any]],
  max_objects: int,
  max_bytes: int,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
  """Select a deterministic bounded prefix and defer the rest.

  Deferral is represented as a keep decision in the current immutable plan;
  the next fresh plan can revisit it. This avoids a permanent guard failure
  when a backlog is larger than one run's safety budget.
  """
  selected: List[Dict[str, Any]] = []
  deferred: List[Dict[str, Any]] = []
  used_bytes = 0
  for candidate in sorted(candidates, key=lambda item: item["key"]):
    candidate_bytes = candidate.get("size_bytes", 0)
    if (
      len(selected) >= max_objects
      or used_bytes + candidate_bytes > max_bytes
    ):
      deferred.append(candidate)
      continue
    selected.append(candidate)
    used_bytes += candidate_bytes
  return selected, deferred


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
  appcast_path: Optional[Path] = None,
  archive_evidence_path: Optional[Path] = None,
  appcast_references: Optional[Sequence[str]] = None,
  max_delete_objects: Optional[int] = None,
  max_delete_bytes: Optional[int] = None,
) -> Dict[str, Any]:
  if plan_ttl_hours <= 0:
    raise ValueError("plan_ttl_hours must be positive")
  if (rclone_remote is None) != (r2_prefix is None):
    raise ValueError("rclone_remote and r2_prefix must be provided together")
  if rclone_remote is not None and r2_prefix is not None:
    validate_storage(rclone_remote, r2_prefix)
  policy = load_policy(policy_path)
  artifacts, product = load_manifest(manifest_path)
  archive_policy = policy["policy_version"] >= 2
  manifest = load_json(manifest_path)
  if (
    archive_policy
    and inventory_path is not None
    and rclone_remote is not None
    and manifest.get("appcast_object_key")
    and appcast_path is None
  ):
    raise ValueError("policy v2 complete plans require a live appcast snapshot")
  archive_descriptors = {
    descriptor.key
    for descriptors in artifacts.values()
    for descriptor in descriptors
    if descriptor.archive is not None
  }
  archive_evidence_keys = frozenset()
  if archive_policy and inventory_path is not None and archive_descriptors:
    if archive_evidence_path is None:
      raise ValueError("policy v2 complete plans require archive evidence")
    archive_evidence_keys = load_archive_evidence(
      archive_evidence_path,
      manifest_path,
      artifacts,
    )
  excluded_prefixes = list(policy.get("excluded_prefixes", []))
  cache_prefix = policy.get("fallback_cache_prefix", "")
  if cache_prefix and cache_prefix not in excluded_prefixes:
    excluded_prefixes.append(cache_prefix)
  excluded_prefixes = sorted(set(excluded_prefixes))
  if r2_prefix is not None:
    outside_exclusions = [
      value for value in excluded_prefixes
      if not value.startswith(r2_prefix)
    ]
    if outside_exclusions:
      raise ValueError("excluded prefix is outside r2_prefix: {}".format(sorted(outside_exclusions)[0]))
  inventory = parse_inventory(inventory_path, artifacts.keys())
  if r2_prefix is not None:
    invalid_manifest_keys = sorted(key for key in artifacts if not key.startswith(r2_prefix))
    if invalid_manifest_keys:
      raise ValueError("manifest object is outside r2_prefix: {}".format(invalid_manifest_keys[0]))
  inventory_before_exclusions = scope_inventory(inventory, r2_prefix)
  inventory = scope_managed_inventory(inventory, r2_prefix, excluded_prefixes)
  parsed_appcast_references = set(
    parse_appcast_references(appcast_path, r2_prefix)
  )
  if appcast_references is not None:
    for index, value in enumerate(appcast_references):
      key = _appcast_key_from_url(value, r2_prefix)
      if key is None:
        raise ValueError("invalid appcast reference at index {}".format(index))
      parsed_appcast_references.add(require_key(key, "appcast reference"))
  for descriptors in artifacts.values():
    for descriptor in descriptors:
      if descriptor.kind == "appcast-reference":
        parsed_appcast_references.add(descriptor.key)
  reference_time = as_of or datetime.now(UTC)
  if reference_time.tzinfo is None:
    reference_time = reference_time.replace(tzinfo=UTC)
  reference_time = reference_time.astimezone(UTC)
  reference_date = reference_time.date()
  recent_cutoff = reference_date - timedelta(days=policy["recent_stable_days"])
  delta_cutoff = reference_date - timedelta(days=policy["retain_sparkle_deltas_days"])
  prerelease_cutoff = reference_date - timedelta(days=policy["retain_prereleases_days"])
  metadata_cutoff = reference_date - timedelta(days=policy.get("retain_metadata_days", 0))
  latest_stable = choose_latest_stable(artifacts)

  keep: List[Dict[str, Any]] = []
  delete: List[Dict[str, Any]] = []
  unknown_count = 0
  excluded_count = len(inventory_before_exclusions) - len(inventory)
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
        archive_policy,
        frozenset(parsed_appcast_references),
        metadata_cutoff,
        item,
        archive_evidence_keys,
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

  configured_max_objects = policy.get("max_delete_objects", 2**31 - 1)
  configured_max_bytes = policy.get("max_delete_bytes", 2**63 - 1)
  if max_delete_objects is not None:
    if max_delete_objects < 0:
      raise ValueError("max_delete_objects must be non-negative")
    configured_max_objects = min(configured_max_objects, max_delete_objects)
  if max_delete_bytes is not None:
    if max_delete_bytes < 0:
      raise ValueError("max_delete_bytes must be non-negative")
    configured_max_bytes = min(configured_max_bytes, max_delete_bytes)
  selected_delete, deferred_delete = bounded_delete_batch(
    delete,
    configured_max_objects,
    configured_max_bytes,
  )
  for item in deferred_delete:
    deferred_entry = dict(item)
    deferred_entry["reason"] = "deferred-delete-batch"
    keep.append(deferred_entry)

  keep.sort(key=lambda item: item["key"])
  selected_delete.sort(key=lambda item: item["key"])
  deferred_delete.sort(key=lambda item: item["key"])
  payload: Dict[str, Any] = {
    "contract_version": PLAN_CONTRACT_VERSION,
    "planner_version": PLANNER_VERSION,
    "product": product,
    "rclone_remote": rclone_remote,
    "r2_prefix": r2_prefix,
    "as_of": reference_time.isoformat().replace("+00:00", "Z"),
    "expires_at": (reference_time + timedelta(hours=plan_ttl_hours)).isoformat().replace("+00:00", "Z"),
    "inventory_complete": inventory_path is not None,
    "policy_version": policy["policy_version"],
    "excluded_prefixes": excluded_prefixes,
    "appcast_references": sorted(parsed_appcast_references),
    "appcast_sha256": sha256_file(appcast_path) if appcast_path is not None else None,
    "archive_evidence_sha256": sha256_file(archive_evidence_path) if archive_evidence_path is not None else None,
    "manifest_sha256": sha256_file(manifest_path),
    "policy_sha256": sha256_file(policy_path),
    "inventory_sha256": inventory_digest(inventory),
    "cutoffs": {
      "recent_stable": recent_cutoff.isoformat(),
      "sparkle_delta": delta_cutoff.isoformat(),
      "prerelease": prerelease_cutoff.isoformat(),
      "release_metadata": metadata_cutoff.isoformat(),
    },
    "keep": keep,
    "delete": selected_delete,
    "deferred": deferred_delete,
    "batch": {
      "max_objects": configured_max_objects,
      "max_bytes": configured_max_bytes,
      "deferred_count": len(deferred_delete),
      "deferred_bytes": sum(item.get("size_bytes", 0) for item in deferred_delete),
    },
    "summary": {
      "keep_count": len(keep),
      "delete_count": len(selected_delete),
      "unknown_count": unknown_count,
      "excluded_count": excluded_count,
      "deferred_count": len(deferred_delete),
      "delete_bytes": sum(item.get("size_bytes", 0) for item in selected_delete),
      "deferred_bytes": sum(item.get("size_bytes", 0) for item in deferred_delete),
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
    "--appcast",
    type=Path,
    help="snapshot of the live appcast whose enclosure and delta objects must be retained",
  )
  parser.add_argument(
    "--archive-evidence",
    type=Path,
    help="metadata evidence from GitHub Releases and Drive for every manifest archive",
  )
  parser.add_argument("--max-delete-objects", type=int)
  parser.add_argument("--max-delete-bytes", type=int)
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
      args.appcast,
      args.archive_evidence,
      None,
      args.max_delete_objects,
      args.max_delete_bytes,
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
