import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "release-retention"))
import plan


UTC = timezone.utc
AS_OF = datetime(2026, 8, 26, tzinfo=UTC)
POLICY = ROOT / "config" / "release-retention.toml"


def release(
  version,
  release_date,
  channel="stable",
  notarization_status="notarized",
  fallback=False,
  delta_keys=None,
  checksum_object_key=None,
  signature_object_key=None,
):
  item = {
    "version": version,
    "feature_line": ".".join(version.split(".")[:2]),
    "release_date": release_date,
    "channel": channel,
    "notarization_status": notarization_status,
    "fallback": fallback,
    "full_zip_object_key": "releases/{}/app.zip".format(version),
    "sparkle_delta_object_keys": delta_keys or [],
  }
  if checksum_object_key is not None:
    item["checksum_object_key"] = checksum_object_key
  if signature_object_key is not None:
    item["signature_object_key"] = signature_object_key
  return item


def archived_release(version, release_date, object_key=None, size_bytes=10):
  item = release(version, release_date)
  item["full_zip_object_key"] = object_key or "kindow/releases/{}.zip".format(version)
  item["checksum"] = "sha256:" + "a" * 64
  item["size_bytes"] = size_bytes
  item["archive"] = {
    "github_release_id": 101,
    "github_asset_id": 202,
    "github_asset_name": Path(item["full_zip_object_key"]).name,
    "github_asset_sha256": item["checksum"],
    "github_asset_size_bytes": size_bytes,
    "drive_object_key": "keyflowy/apps/kindow/releases/v{}/{}".format(
      version,
      Path(item["full_zip_object_key"]).name,
    ),
    "drive_sha256": item["checksum"],
    "drive_size_bytes": size_bytes,
    "verified": True,
  }
  return item


class ReleaseRetentionPlanTests(unittest.TestCase):
  def write_fixture(self, manifest, inventory=None):
    directory = tempfile.TemporaryDirectory()
    self.addCleanup(directory.cleanup)
    directory_path = Path(directory.name)
    manifest_path = directory_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    inventory_path = None
    if inventory is not None:
      inventory_path = directory_path / "inventory.json"
      inventory_path.write_text(json.dumps({"objects": inventory}), encoding="utf-8")
    return manifest_path, inventory_path

  def write_v2_policy(self, max_delete_objects=20, max_delete_bytes=1024):
    directory = tempfile.TemporaryDirectory()
    self.addCleanup(directory.cleanup)
    policy_path = Path(directory.name) / "policy.toml"
    policy_path.write_text(
      "\n".join([
        "policy_version = 2",
        "recent_stable_days = 90",
        'fallback_strategy = "archive-backed-exact-version"',
        "retain_sparkle_deltas_days = 90",
        "retain_prereleases_days = 30",
        "retain_metadata_days = 30",
        'fallback_cache_prefix = "kindow/fallback-cache/"',
        "fallback_cache_lifecycle_days = 30",
        'excluded_prefixes = ["kindow/fallback-cache/"]',
        "max_delete_objects = {}".format(max_delete_objects),
        "max_delete_bytes = {}".format(max_delete_bytes),
        'unknown_objects = "keep"',
        "",
      ]),
      encoding="utf-8",
    )
    return policy_path

  def write_appcast(self, directory, urls):
    appcast_path = Path(directory) / "appcast.xml"
    items = "".join('<item><enclosure url="{}" /></item>'.format(url) for url in urls)
    appcast_path.write_text("<rss><channel>{}</channel></rss>".format(items), encoding="utf-8")
    return appcast_path

  def decisions(self, result):
    values = {}
    for item in result["keep"]:
      values[item["key"]] = ("keep", item["reason"])
    for item in result["delete"]:
      values[item["key"]] = ("delete", item["reason"])
    return values

  def test_rejects_unknown_policy_field(self):
    directory = tempfile.TemporaryDirectory()
    self.addCleanup(directory.cleanup)
    policy_path = Path(directory.name) / "policy.toml"
    policy_path.write_text(
      POLICY.read_text(encoding="utf-8") + "\nrecent_stabel_days = 730\n",
      encoding="utf-8",
    )

    with self.assertRaisesRegex(ValueError, "unknown field 'recent_stabel_days'"):
      plan.load_policy(policy_path)

  def test_retains_recent_and_exact_cutoff_stable_builds(self):
    cutoff = (AS_OF.date() - timedelta(days=730)).isoformat()
    manifest = {
      "schema_version": 1,
      "product": "kindow",
      "generated_at": "2026-08-26T00:00:00Z",
      "releases": [
        release("3.2.0", cutoff),
        release("3.2.1", "2026-08-01"),
      ],
    }
    manifest_path, inventory_path = self.write_fixture(manifest, [
      "releases/3.2.0/app.zip",
      "releases/3.2.1/app.zip",
    ])
    result = plan.build_plan(manifest_path, POLICY, inventory_path, AS_OF)
    decisions = self.decisions(result)
    self.assertEqual(decisions["releases/3.2.0/app.zip"], ("keep", "recent-stable"))
    self.assertEqual(decisions["releases/3.2.1/app.zip"], ("keep", "recent-stable"))

  def test_keeps_latest_stable_patch_per_old_feature_line(self):
    manifest = {
      "schema_version": 1,
      "product": "kindow",
      "generated_at": "2026-08-26T00:00:00Z",
      "releases": [
        release("3.1.0", "2024-01-01"),
        release("3.1.2", "2024-01-02"),
        release("3.1.4", "2024-01-03"),
      ],
    }
    manifest_path, inventory_path = self.write_fixture(manifest, [
      "releases/3.1.0/app.zip",
      "releases/3.1.2/app.zip",
      "releases/3.1.4/app.zip",
    ])
    result = plan.build_plan(manifest_path, POLICY, inventory_path, AS_OF)
    decisions = self.decisions(result)
    self.assertEqual(decisions["releases/3.1.0/app.zip"], ("delete", "superseded-stable-patch"))
    self.assertEqual(decisions["releases/3.1.2/app.zip"], ("delete", "superseded-stable-patch"))
    self.assertEqual(
      decisions["releases/3.1.4/app.zip"],
      ("keep", "latest-stable-patch-for-feature-line"),
    )

  def test_fallback_is_kept_even_when_it_is_an_old_non_latest_patch(self):
    manifest = {
      "schema_version": 1,
      "product": "kindow",
      "generated_at": "2026-08-26T00:00:00Z",
      "releases": [
        release("3.1.0", "2024-01-01", fallback=True),
        release("3.1.4", "2024-01-02"),
      ],
    }
    manifest_path, inventory_path = self.write_fixture(manifest, [
      "releases/3.1.0/app.zip",
      "releases/3.1.4/app.zip",
    ])
    result = plan.build_plan(manifest_path, POLICY, inventory_path, AS_OF)
    decisions = self.decisions(result)
    self.assertEqual(decisions["releases/3.1.0/app.zip"], ("keep", "fallback-release"))
    self.assertEqual(
      decisions["releases/3.1.4/app.zip"],
      ("keep", "latest-stable-patch-for-feature-line"),
    )

  def test_unnotarized_stable_build_is_kept_for_investigation(self):
    manifest = {
      "schema_version": 1,
      "product": "kindow",
      "generated_at": "2026-08-26T00:00:00Z",
      "releases": [release("3.0.0", "2020-01-01", notarization_status="pending")],
    }
    manifest_path, inventory_path = self.write_fixture(manifest, ["releases/3.0.0/app.zip"])
    result = plan.build_plan(manifest_path, POLICY, inventory_path, AS_OF)
    self.assertEqual(
      self.decisions(result)["releases/3.0.0/app.zip"],
      ("keep", "unverified-stable-installer"),
    )

  def test_delta_and_prerelease_cutoffs_are_inclusive(self):
    delta_cutoff = (AS_OF.date() - timedelta(days=90)).isoformat()
    prerelease_cutoff = (AS_OF.date() - timedelta(days=30)).isoformat()
    manifest = {
      "schema_version": 1,
      "product": "kindow",
      "generated_at": "2026-08-26T00:00:00Z",
      "releases": [
        release("3.3.0-beta.1", prerelease_cutoff, channel="prerelease"),
        release("3.3.0-beta.2", "2026-07-25", channel="prerelease"),
        release("3.2.7", delta_cutoff, delta_keys=["deltas/exact.delta"]),
        release(
          "3.2.8",
          (AS_OF.date() - timedelta(days=91)).isoformat(),
          delta_keys=["deltas/expired.delta"],
        ),
      ],
    }
    manifest_path, inventory_path = self.write_fixture(manifest, [
      "releases/3.3.0-beta.1/app.zip",
      "releases/3.3.0-beta.2/app.zip",
      "deltas/exact.delta",
      "deltas/expired.delta",
      "releases/3.2.7/app.zip",
      "releases/3.2.8/app.zip",
    ])
    result = plan.build_plan(manifest_path, POLICY, inventory_path, AS_OF)
    decisions = self.decisions(result)
    self.assertEqual(
      decisions["releases/3.3.0-beta.1/app.zip"],
      ("keep", "recent-prerelease"),
    )
    self.assertEqual(
      decisions["releases/3.3.0-beta.2/app.zip"],
      ("delete", "expired-prerelease"),
    )
    self.assertEqual(decisions["deltas/exact.delta"], ("keep", "recent-sparkle-delta"))
    self.assertEqual(decisions["deltas/expired.delta"], ("delete", "expired-sparkle-delta"))

  def test_protected_metadata_and_unknown_inventory_objects_are_kept(self):
    manifest = {
      "schema_version": 1,
      "product": "kindow",
      "generated_at": "2026-08-26T00:00:00Z",
      "appcast_object_key": "kindow/appcast.xml",
      "protected_object_keys": ["kindow/release-manifest.json"],
      "releases": [release(
        "3.2.7",
        "2026-08-01",
        checksum_object_key="metadata/checksums.txt",
        signature_object_key="metadata/checksums.sig",
      )],
    }
    inventory = [
      "kindow/appcast.xml",
      "kindow/release-manifest.json",
      "metadata/checksums.txt",
      "metadata/checksums.sig",
      "unlisted/keep-me.bin",
    ]
    manifest_path, inventory_path = self.write_fixture(manifest, inventory)
    result = plan.build_plan(manifest_path, POLICY, inventory_path, AS_OF)
    decisions = self.decisions(result)
    for key in inventory:
      self.assertEqual(decisions[key][0], "keep")
    self.assertEqual(decisions["unlisted/keep-me.bin"], ("keep", "unknown-object"))
    self.assertEqual(result["summary"]["unknown_count"], 1)

  def test_ignores_objects_from_other_products_in_a_shared_remote_root(self):
    release_item = release("3.2.7", "2026-08-01", delta_keys=[])
    release_item["full_zip_object_key"] = "kindow/releases/3.2.7/app.zip"
    manifest = {
      "schema_version": 1,
      "product": "kindow",
      "generated_at": "2026-08-26T00:00:00Z",
      "releases": [release_item],
    }
    inventory = [
      "kindow/releases/3.2.7/app.zip",
      "other-app/releases/9.0.0/app.zip",
    ]
    manifest_path, inventory_path = self.write_fixture(manifest, inventory)
    result = plan.build_plan(
      manifest_path,
      POLICY,
      inventory_path,
      AS_OF,
      "cf_r2:keyflowy-apps/",
      "kindow/",
    )
    decisions = self.decisions(result)
    self.assertEqual(decisions, {"kindow/releases/3.2.7/app.zip": ("keep", "recent-stable")})
    self.assertEqual(result["summary"]["unknown_count"], 0)

  def test_output_is_sorted_and_text_rendering_is_reviewable(self):
    manifest = {
      "schema_version": 1,
      "product": "kindow",
      "generated_at": "2026-08-26T00:00:00Z",
      "releases": [
        release("3.1.0", "2024-01-01"),
        release("3.1.1", "2024-01-02"),
      ],
    }
    manifest_path, inventory_path = self.write_fixture(manifest, [
      "z-unknown.bin",
      "releases/3.1.1/app.zip",
      "releases/3.1.0/app.zip",
    ])
    result = plan.build_plan(manifest_path, POLICY, inventory_path, AS_OF)
    self.assertEqual(
      [item["key"] for item in result["keep"]],
      ["releases/3.1.1/app.zip", "z-unknown.bin"],
    )
    rendered = plan.render_text(result)
    self.assertIn("KEEP\tunknown\tunknown-object\tz-unknown.bin", rendered)
    self.assertIn("DELETE\tstable-installer\tsuperseded-stable-patch\treleases/3.1.0/app.zip", rendered)

  def test_manifest_feature_line_must_match_semver(self):
    manifest = {
      "schema_version": 1,
      "product": "kindow",
      "generated_at": "2026-08-26T00:00:00Z",
      "releases": [dict(release("3.2.0", "2026-08-01"), feature_line="3.1")],
    }
    manifest_path, _ = self.write_fixture(manifest)
    with self.assertRaisesRegex(ValueError, "feature_line"):
      plan.build_plan(manifest_path, POLICY, None, AS_OF)

  def test_rejects_misspelled_fallback_instead_of_deleting_the_release(self):
    old_release = release("3.1.0", "2024-01-01", fallback=True)
    old_release["fallbak"] = old_release.pop("fallback")
    manifest = {
      "schema_version": 1,
      "product": "kindow",
      "generated_at": "2026-08-26T00:00:00Z",
      "releases": [old_release, release("3.1.4", "2024-01-02")],
    }
    manifest_path, inventory_path = self.write_fixture(manifest, [
      "releases/3.1.0/app.zip",
      "releases/3.1.4/app.zip",
    ])
    with self.assertRaisesRegex(ValueError, "unknown field 'fallbak'"):
      plan.build_plan(manifest_path, POLICY, inventory_path, AS_OF)

  def test_rejects_unknown_top_level_manifest_field(self):
    manifest = {
      "schema_version": 1,
      "product": "kindow",
      "generated_at": "2026-08-26T00:00:00Z",
      "releases": [release("3.2.7", "2026-08-01")],
      "release": [],
    }
    manifest_path, _ = self.write_fixture(manifest)
    with self.assertRaisesRegex(ValueError, "unknown field 'release'"):
      plan.build_plan(manifest_path, POLICY, None, AS_OF)

  def test_rejects_missing_required_manifest_and_release_fields(self):
    valid_manifest = {
      "schema_version": 1,
      "product": "kindow",
      "generated_at": "2026-08-26T00:00:00Z",
      "releases": [release("3.2.7", "2026-08-01")],
    }
    missing_product = json.loads(json.dumps(valid_manifest))
    missing_product.pop("product")
    missing_installer = json.loads(json.dumps(valid_manifest))
    missing_installer["releases"][0].pop("full_zip_object_key")

    for manifest, missing_field in (
      (missing_product, "product"),
      (missing_installer, "full_zip_object_key"),
    ):
      with self.subTest(missing_field=missing_field):
        manifest_path, _ = self.write_fixture(manifest)
        with self.assertRaisesRegex(ValueError, "missing required field {!r}".format(missing_field)):
          plan.build_plan(manifest_path, POLICY, None, AS_OF)

  def test_rejects_values_that_do_not_match_manifest_schema_types_and_formats(self):
    base_manifest = {
      "schema_version": 1,
      "product": "kindow",
      "generated_at": "2026-08-26T00:00:00Z",
      "releases": [release("3.2.7", "2026-08-01")],
    }
    invalid_values = []

    boolean_schema_version = json.loads(json.dumps(base_manifest))
    boolean_schema_version["schema_version"] = True
    invalid_values.append((boolean_schema_version, "schema_version"))

    date_without_time = json.loads(json.dumps(base_manifest))
    date_without_time["generated_at"] = "2026-08-26"
    invalid_values.append((date_without_time, "generated_at"))

    numeric_checksum = json.loads(json.dumps(base_manifest))
    numeric_checksum["releases"][0]["checksum"] = 42
    invalid_values.append((numeric_checksum, "checksum"))

    duplicate_deltas = json.loads(json.dumps(base_manifest))
    duplicate_deltas["releases"][0]["sparkle_delta_object_keys"] = [
      "deltas/update.delta",
      "deltas/update.delta",
    ]
    invalid_values.append((duplicate_deltas, "unique values"))

    for manifest, message in invalid_values:
      with self.subTest(message=message):
        manifest_path, _ = self.write_fixture(manifest)
        with self.assertRaisesRegex(ValueError, message):
          plan.build_plan(manifest_path, POLICY, None, AS_OF)

  def test_accepts_a_manifest_with_every_supported_field(self):
    complete_release = release(
      "3.2.7",
      "2026-08-01",
      fallback=True,
      delta_keys=["kindow/deltas/3.2.6-3.2.7.delta"],
      checksum_object_key="kindow/releases/3.2.7/SHA256SUMS",
      signature_object_key="kindow/releases/3.2.7/SHA256SUMS.sig",
    )
    complete_release["full_zip_object_key"] = "kindow/releases/3.2.7/app.zip"
    complete_release["checksum"] = "sha256:abc123"
    manifest = {
      "schema_version": 1,
      "product": "kindow",
      "generated_at": "2026-08-26T00:00:00Z",
      "appcast_object_key": "kindow/appcast.xml",
      "protected_object_keys": ["kindow/release-manifest.json"],
      "releases": [complete_release],
    }
    inventory = [
      "kindow/appcast.xml",
      "kindow/release-manifest.json",
      "kindow/releases/3.2.7/app.zip",
      "kindow/releases/3.2.7/SHA256SUMS",
      "kindow/releases/3.2.7/SHA256SUMS.sig",
      "kindow/deltas/3.2.6-3.2.7.delta",
    ]
    manifest_path, inventory_path = self.write_fixture(manifest, inventory)

    result = plan.build_plan(manifest_path, POLICY, inventory_path, AS_OF)

    self.assertEqual(result["product"], "kindow")
    self.assertEqual(
      self.decisions(result)["kindow/releases/3.2.7/app.zip"],
      ("keep", "fallback-release"),
    )

  def test_v2_keeps_an_expired_installer_until_both_archives_are_verified(self):
    policy = self.write_v2_policy()
    old_release = release("3.1.0", "2024-01-01")
    old_release["full_zip_object_key"] = "kindow/releases/3.1.0.zip"
    manifest = {
      "schema_version": 1,
      "product": "kindow",
      "generated_at": "2026-08-26T00:00:00Z",
      "releases": [old_release],
    }
    manifest_path, inventory_path = self.write_fixture(
      manifest,
      [{"key": old_release["full_zip_object_key"], "size_bytes": 10}],
    )

    result = plan.build_plan(manifest_path, policy, inventory_path, AS_OF)

    self.assertEqual(
      self.decisions(result)[old_release["full_zip_object_key"]],
      ("keep", "awaiting-archive-verification"),
    )

  def test_v2_deletes_an_expired_installer_only_after_archive_verification(self):
    policy = self.write_v2_policy()
    old_release = archived_release("3.1.0", "2024-01-01")
    manifest = {
      "schema_version": 1,
      "product": "kindow",
      "generated_at": "2026-08-26T00:00:00Z",
      "releases": [old_release],
    }
    manifest_path, inventory_path = self.write_fixture(
      manifest,
      [{"key": old_release["full_zip_object_key"], "size_bytes": 10}],
    )

    result = plan.build_plan(manifest_path, policy, inventory_path, AS_OF)

    self.assertEqual(
      self.decisions(result)[old_release["full_zip_object_key"]],
      ("delete", "archived-stable-expired"),
    )

  def test_v2_keeps_an_archived_installer_when_r2_size_or_sha256_differs(self):
    policy = self.write_v2_policy()
    old_release = archived_release("3.1.0", "2024-01-01")
    manifest = {
      "schema_version": 1,
      "product": "kindow",
      "generated_at": "2026-08-26T00:00:00Z",
      "releases": [old_release],
    }
    mismatches = [
      {"key": old_release["full_zip_object_key"], "size_bytes": 11},
      {
        "key": old_release["full_zip_object_key"],
        "size_bytes": 10,
        "hashes": {"SHA-256": "b" * 64},
      },
    ]
    for inventory in mismatches:
      with self.subTest(inventory=inventory):
        manifest_path, inventory_path = self.write_fixture(manifest, [inventory])
        result = plan.build_plan(manifest_path, policy, inventory_path, AS_OF)
        self.assertEqual(
          self.decisions(result)[old_release["full_zip_object_key"]],
          ("keep", "awaiting-archive-verification"),
        )

  def test_v2_keeps_every_installer_and_delta_referenced_by_the_live_appcast(self):
    policy = self.write_v2_policy()
    old_release = archived_release("3.1.0", "2024-01-01")
    old_release["sparkle_delta_object_keys"] = ["kindow/deltas/3.0.0-3.1.0.delta"]
    manifest = {
      "schema_version": 1,
      "product": "kindow",
      "generated_at": "2026-08-26T00:00:00Z",
      "appcast_object_key": "kindow/appcast.xml",
      "releases": [old_release],
    }
    inventory = [
      {"key": "kindow/appcast.xml", "size_bytes": 1},
      {"key": old_release["full_zip_object_key"], "size_bytes": 10},
      {"key": old_release["sparkle_delta_object_keys"][0], "size_bytes": 2},
    ]
    manifest_path, inventory_path = self.write_fixture(manifest, inventory)
    appcast_path = self.write_appcast(
      manifest_path.parent,
      [
        "https://s3.keyflowy.com/" + old_release["full_zip_object_key"],
        "deltas/3.0.0-3.1.0.delta",
      ],
    )

    result = plan.build_plan(
      manifest_path,
      policy,
      inventory_path,
      AS_OF,
      "cf_r2:keyflowy-apps/",
      "kindow/",
      appcast_path=appcast_path,
    )

    decisions = self.decisions(result)
    self.assertEqual(decisions[old_release["full_zip_object_key"]], ("keep", "appcast-reference"))
    self.assertEqual(
      decisions[old_release["sparkle_delta_object_keys"][0]],
      ("keep", "appcast-reference"),
    )
    self.assertEqual(result["appcast_sha256"], plan.sha256_file(appcast_path))

  def test_v2_complete_plan_fails_closed_without_a_live_appcast_snapshot(self):
    policy = self.write_v2_policy()
    manifest = {
      "schema_version": 1,
      "product": "kindow",
      "generated_at": "2026-08-26T00:00:00Z",
      "appcast_object_key": "kindow/appcast.xml",
      "releases": [archived_release("3.1.0", "2024-01-01")],
    }
    manifest_path, inventory_path = self.write_fixture(manifest, ["kindow/appcast.xml"])

    with self.assertRaisesRegex(ValueError, "require a live appcast snapshot"):
      plan.build_plan(
        manifest_path,
        policy,
        inventory_path,
        AS_OF,
        "cf_r2:keyflowy-apps/",
        "kindow/",
      )

  def test_v2_excludes_fallback_cache_but_keeps_unknown_manual_objects(self):
    policy = self.write_v2_policy()
    manifest = {
      "schema_version": 1,
      "product": "kindow",
      "generated_at": "2026-08-26T00:00:00Z",
      "releases": [],
    }
    inventory = [
      "kindow/fallback-cache/1.0.0/archive.zip",
      "kindow/website-assets/manual.png",
    ]
    manifest_path, inventory_path = self.write_fixture(manifest, inventory)

    result = plan.build_plan(
      manifest_path,
      policy,
      inventory_path,
      AS_OF,
      "cf_r2:keyflowy-apps/",
      "kindow/",
    )

    self.assertNotIn("kindow/fallback-cache/1.0.0/archive.zip", self.decisions(result))
    self.assertEqual(
      self.decisions(result)["kindow/website-assets/manual.png"],
      ("keep", "unknown-object"),
    )
    self.assertEqual(result["summary"]["excluded_count"], 1)

  def test_v2_defers_candidates_beyond_the_batch_and_revisits_them_next_plan(self):
    policy = self.write_v2_policy(max_delete_objects=1)
    releases = [
      archived_release("3.1.0", "2024-01-01"),
      archived_release("3.1.1", "2024-01-02"),
    ]
    manifest = {
      "schema_version": 1,
      "product": "kindow",
      "generated_at": "2026-08-26T00:00:00Z",
      "releases": releases,
    }
    inventory = [
      {"key": item["full_zip_object_key"], "size_bytes": item["size_bytes"]}
      for item in releases
    ]
    manifest_path, inventory_path = self.write_fixture(manifest, inventory)

    first = plan.build_plan(manifest_path, policy, inventory_path, AS_OF)

    self.assertEqual([item["key"] for item in first["delete"]], ["kindow/releases/3.1.0.zip"])
    self.assertEqual(first["summary"]["deferred_count"], 1)
    inventory_path.write_text(json.dumps({"objects": [inventory[1]]}), encoding="utf-8")
    second = plan.build_plan(manifest_path, policy, inventory_path, AS_OF)
    self.assertEqual([item["key"] for item in second["delete"]], ["kindow/releases/3.1.1.zip"])

  def test_v2_deletes_old_metadata_only_with_drive_and_git_completion_evidence(self):
    policy = self.write_v2_policy()
    checksum = "sha256:" + "c" * 64
    metadata = {
      "object_key": "kindow/release-state/v3.1.0/complete.json",
      "release_date": "2024-01-01",
      "checksum": checksum,
      "size_bytes": 12,
      "backup": {
        "drive_object_key": "keyflowy/apps/kindow/releases/v3.1.0/release-state/complete.json",
        "sha256": checksum,
        "size_bytes": 12,
        "verified": True,
      },
      "completion": {
        "git_path": "release-completions/v3.1.0.json",
        "git_commit": "d" * 40,
        "verified": True,
      },
    }
    manifest = {
      "schema_version": 1,
      "product": "kindow",
      "generated_at": "2026-08-26T00:00:00Z",
      "retention_metadata": [metadata],
      "releases": [],
    }
    inventory = [{"key": metadata["object_key"], "size_bytes": 12}]
    manifest_path, inventory_path = self.write_fixture(manifest, inventory)

    verified = plan.build_plan(manifest_path, policy, inventory_path, AS_OF)
    self.assertEqual(
      self.decisions(verified)[metadata["object_key"]],
      ("delete", "expired-release-metadata"),
    )

    manifest["retention_metadata"][0]["backup"]["sha256"] = "sha256:" + "e" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    unverified = plan.build_plan(manifest_path, policy, inventory_path, AS_OF)
    self.assertEqual(
      self.decisions(unverified)[metadata["object_key"]],
      ("keep", "unverified-release-metadata"),
    )

  def test_parser_field_contract_matches_the_canonical_manifest_schema(self):
    schema = json.loads(
      (ROOT / "schemas" / "release-manifest.schema.json").read_text(encoding="utf-8")
    )

    self.assertEqual(plan.MANIFEST_FIELDS, frozenset(schema["properties"]))
    self.assertEqual(plan.REQUIRED_MANIFEST_FIELDS, frozenset(schema["required"]))
    self.assertEqual(plan.RELEASE_FIELDS, frozenset(schema["$defs"]["release"]["properties"]))
    self.assertEqual(
      plan.REQUIRED_RELEASE_FIELDS,
      frozenset(schema["$defs"]["release"]["required"]),
    )

  def test_v2_output_field_contract_matches_the_canonical_plan_schema(self):
    manifest = {
      "schema_version": 1,
      "product": "kindow",
      "generated_at": "2026-08-26T00:00:00Z",
      "releases": [],
    }
    manifest_path, inventory_path = self.write_fixture(manifest, [])
    result = plan.build_plan(manifest_path, self.write_v2_policy(), inventory_path, AS_OF)
    schema = json.loads(
      (ROOT / "schemas" / "retention-plan.schema.json").read_text(encoding="utf-8")
    )

    self.assertEqual(frozenset(result), frozenset(schema["properties"]))
    self.assertEqual(result["contract_version"], schema["properties"]["contract_version"]["const"])

  def test_cli_accepts_deterministic_as_of_and_json_output(self):
    manifest = {
      "schema_version": 1,
      "product": "kindow",
      "generated_at": "2026-08-26T00:00:00Z",
      "releases": [release("3.2.7", "2026-08-01")],
    }
    manifest_path, inventory_path = self.write_fixture(manifest, ["releases/3.2.7/app.zip"])
    output_path = manifest_path.parent / "plan.json"
    exit_code = plan.main([
      "--manifest", str(manifest_path),
      "--policy", str(POLICY),
      "--inventory", str(inventory_path),
      "--as-of", "2026-08-26T00:00:00Z",
      "--output", str(output_path),
    ])
    self.assertEqual(exit_code, 0)
    output = json.loads(output_path.read_text(encoding="utf-8"))
    self.assertEqual(output["product"], "kindow")
    self.assertEqual(output["summary"]["delete_count"], 0)


if __name__ == "__main__":
  unittest.main()
