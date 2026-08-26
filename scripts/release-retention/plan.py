#!/usr/bin/env python3
"""Build a safe, deterministic release-retention plan.

This program only plans. It never calls rclone or deletes an object. Unknown
objects are kept so an incomplete manifest cannot cause an accidental delete.
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


UTC = timezone.utc
SEMVER_RE = re.compile(
  r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
  r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
  r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


@dataclass(frozen=True)
class Artifact:
  key: str
  kind: str
  release_date: Optional[date] = None
  version: Optional[Tuple[int, int, int]] = None
  feature_line: Optional[str] = None
  fallback: bool = False
  notarized: bool = False


def load_json(path: Path) -> Any:
  try:
    return json.loads(path.read_text(encoding="utf-8"))
  except json.JSONDecodeError as error:
    raise ValueError("invalid JSON in {}: {}".format(path, error)) from error


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
  if not isinstance(value, str):
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
  return value


def parse_inventory(path: Optional[Path], manifest_keys: Iterable[str]) -> List[str]:
  if path is None:
    return sorted(set(manifest_keys))
  raw = load_json(path)
  if isinstance(raw, list):
    raw_objects = raw
  elif isinstance(raw, dict) and isinstance(raw.get("objects"), list):
    raw_objects = raw["objects"]
  else:
    raise ValueError("inventory must be an array or an object with an 'objects' array")
  keys: Set[str] = set()
  for index, item in enumerate(raw_objects):
    if isinstance(item, str):
      key = item
    elif isinstance(item, dict):
      key = item.get("key", item.get("object_key"))
    else:
      raise ValueError("inventory object {} must be a string or object".format(index))
    keys.add(require_key(key, "inventory object {} key".format(index)))
  return sorted(keys)


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


def load_manifest(path: Path) -> Tuple[Dict[str, List[Artifact]], List[str], str]:
  manifest = load_json(path)
  if not isinstance(manifest, dict):
    raise ValueError("manifest must be a JSON object")
  if manifest.get("schema_version") != 1:
    raise ValueError("manifest schema_version must be 1")
  product = manifest.get("product")
  if not isinstance(product, str) or not product:
    raise ValueError("manifest product must be a non-empty string")
  generated_at = manifest.get("generated_at")
  if not isinstance(generated_at, str) or not generated_at:
    raise ValueError("manifest generated_at must be a non-empty ISO timestamp")
  try:
    parse_as_of(generated_at)
  except ValueError as error:
    raise ValueError("manifest generated_at must be an ISO timestamp") from error
  releases = manifest.get("releases")
  if not isinstance(releases, list):
    raise ValueError("manifest releases must be an array")

  artifacts: Dict[str, List[Artifact]] = {}
  if "appcast_object_key" in manifest:
    appcast_key = require_key(manifest["appcast_object_key"], "appcast_object_key")
    add_artifact(artifacts, appcast_key, "protected-metadata")
  raw_protected = manifest.get("protected_object_keys", [])
  if not isinstance(raw_protected, list):
    raise ValueError("protected_object_keys must be an array")
  for index, key in enumerate(raw_protected):
    protected_key = require_key(key, "protected_object_keys[{}]".format(index))
    add_artifact(artifacts, protected_key, "protected-metadata")

  for index, release in enumerate(releases):
    label = "releases[{}]".format(index)
    if not isinstance(release, dict):
      raise ValueError("{} must be an object".format(label))
    version_parts = parse_semver(release.get("version"), label + ".version")
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
    full_key = require_key(release.get("full_zip_object_key"), label + ".full_zip_object_key")
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
    delta_keys = release.get("sparkle_delta_object_keys")
    if not isinstance(delta_keys, list):
      raise ValueError("{} sparkle_delta_object_keys must be an array".format(label))
    for delta_key in delta_keys:
      add_artifact(
        artifacts,
        delta_key,
        "sparkle-delta",
        release_date=release_date,
        version=version,
        feature_line=feature_line,
      )
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


def build_plan(
  manifest_path: Path,
  policy_path: Path,
  inventory_path: Optional[Path] = None,
  as_of: Optional[datetime] = None,
) -> Dict[str, Any]:
  policy = load_policy(policy_path)
  artifacts, product = load_manifest(manifest_path)
  inventory = parse_inventory(inventory_path, artifacts.keys())
  reference_time = as_of or datetime.now(UTC)
  if reference_time.tzinfo is None:
    reference_time = reference_time.replace(tzinfo=UTC)
  reference_time = reference_time.astimezone(UTC)
  reference_date = reference_time.date()
  recent_cutoff = reference_date - timedelta(days=policy["recent_stable_days"])
  delta_cutoff = reference_date - timedelta(days=policy["retain_sparkle_deltas_days"])
  prerelease_cutoff = reference_date - timedelta(days=policy["retain_prereleases_days"])
  latest_stable = choose_latest_stable(artifacts)

  keep: List[Dict[str, str]] = []
  delete: List[Dict[str, str]] = []
  unknown_count = 0
  for key in inventory:
    descriptors = artifacts.get(key)
    if descriptors is None:
      unknown_count += 1
      keep.append({"key": key, "kind": "unknown", "reason": "unknown-object"})
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
      keep.append({"key": key, "kind": kind, "reason": reason})
    else:
      delete.append({"key": key, "kind": kind, "reason": decisions[0][1]})

  keep.sort(key=lambda item: item["key"])
  delete.sort(key=lambda item: item["key"])
  return {
    "product": product,
    "as_of": reference_time.isoformat().replace("+00:00", "Z"),
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
    },
  }


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
  return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
  args = parse_args(argv)
  try:
    plan = build_plan(
      args.manifest,
      args.policy,
      args.inventory,
      parse_as_of(args.as_of),
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
