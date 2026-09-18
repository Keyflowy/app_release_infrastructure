# App Release Infrastructure

Shared release-retention tooling for Keyflowy applications. Each application
keeps its own release manifest and policy values; this repository owns the
planner implementation and the safety contract.

## Retention contract

The planner uses a versioned JSON release manifest. It does not guess whether
an object is a release by looking at its R2 key. An application release should
record its SemVer version, `MAJOR.MINOR` feature line, UTC release date,
channel, notarization status, installer key, and Sparkle delta keys. A
manifest may also mark a release as `fallback` and may list protected appcast,
checksum, or signature objects.

The checked-in example policy demonstrates the legacy v1 strategy and keeps:

- every notarized stable installer from the last 730 UTC calendar days;
- the highest stable patch of every older feature line;
- every release marked `fallback`, regardless of age;
- Sparkle deltas for 90 days;
- prerelease installers for 30 days;
- appcast and metadata objects forever;
- objects not present in the manifest forever.

Production products may opt into policy v2 with
`fallback_strategy = "archive-backed-exact-version"`. Under v2, the planner:

- keeps recent stable installers in R2 as the hot update layer;
- deletes an expired stable installer only when its GitHub Release and Google
  Drive copies have matching SHA-256 and size evidence;
- protects every installer and delta referenced by the live R2 appcast;
- ages release-state metadata only after its Drive bytes and committed Git
  completion tombstone have been verified by the reusable workflow;
- excludes fallback-cache prefixes owned by a separate native R2 lifecycle;
- limits each deterministic deletion batch and defers the remainder to the
  next scheduled plan.

The cutoff dates are inclusive. An object released exactly on a cutoff date is
kept. A stable installer that is not notarized is kept for investigation and
is never treated as a deletion candidate.

The planner is intentionally non-destructive. It never invokes `rclone`, writes
to R2, or deletes an object. A plan includes a canonical `plan_id`, input file
digests, an expiry timestamp, the complete inventory fingerprint, and the
approved storage target. The separate apply command consumes only that exact
reviewed plan.

The reusable workflow at `.github/workflows/reusable-retention-plan.yml` runs
this planner from an App repository and uploads the deterministic plan as a
workflow artifact. A live R2 inventory is gathered on the fixed self-hosted
Linux home runner with its runner-local rclone configuration; the workflow
never receives rclone credentials as a secret. It is a planning workflow, not
an apply workflow. Consumers should pin the shared workflow to a reviewed
release tag once the repository's first release is published. Do not use a
mutable branch for production callers.
For policy v2 it also snapshots the current R2 appcast, verifies every declared
Drive backup byte-for-byte, and proves each Git completion tombstone exists at
the declared commit before producing a plan.

## Running the planner

With only the manifest, every object named by the manifest is planned:

```sh
python3 scripts/release-retention/plan.py \
  --manifest release-manifest.json \
  --policy config/release-retention.toml \
  --as-of 2026-08-26T00:00:00Z
```

For a real R2 listing, pass an inventory JSON file. It may be either an array
of object keys or an object containing an `objects` array. Items in the latter
form can be strings or objects with `key`/`object_key`:

```json
{
  "objects": [
    "kindow/3.2.7/kindow.zip",
    {"key": "kindow/appcast.xml", "size_bytes": 1024}
  ]
}
```

Use `--format text` for a review-friendly tab-separated report or `--output`
to write the JSON/text report to a file. Pass `--as-of` in CI and tests so a
plan is reproducible. Omitting it uses the current UTC timestamp.

For a complete plan bound to a product prefix, include the rclone remote root
and prefix. The remote root is the path passed to `rclone lsjson`; object keys
in the manifest and inventory are relative to that root. Manifest keys must
start with the product prefix. A complete inventory may include sibling product
prefixes from the shared root; planning and apply fingerprint only the selected
product prefix:

```sh
python3 scripts/release-retention/plan.py \
  --manifest release-manifest.json \
  --policy config/release-retention.toml \
  --inventory r2-inventory.json \
  --rclone-remote cf_r2:keyflowy-apps/ \
  --r2-prefix kindow/ \
  --as-of 2026-08-26T00:00:00Z \
  --output retention-plan.json
```

## Applying a reviewed plan

`scripts/release-retention/apply_plan.py` is the only deletion entry point. It
always refreshes the remote with `rclone lsjson --recursive --files-only
--hash`, rejects new objects or changed fingerprints within the approved
product prefix, and preserves every planned keep object. Sibling product
prefixes are outside the plan and ignored. A missing delete candidate is treated as
`already-absent`, which makes an interrupted run safe to retry with the same
plan. Any other delete failure stops immediately.

Without `--execute`, the command performs validation and one `rclone` dry-run
per candidate. Real deletion requires all of `--execute`,
`--approval-id`, `--plan-run-id`, and `--plan-artifact-id`, plus the expected
plan digest. Delete reasons are allow-listed and per-run object/byte limits
are enforced before the first remote call.

The reusable `.github/workflows/reusable-retention-apply.yml` places the job
behind the `release-retention-production` protected environment, serializes
applications per product prefix, downloads the immutable reviewed artifact,
and uploads `apply-result.json`. Product repositories should expose a separate
`workflow_dispatch` caller for apply; scheduled and push workflows must only
produce plans.

Both reusable workflows run on a fixed self-hosted Linux home runner whose
runner-local rclone configuration holds the `cf_r2:` and `gd_admin:` remotes;
there is no `RCLONE_CONFIG` secret. Each workflow fails closed when the runner
is not self-hosted Linux, when rclone or either remote is missing from the
runner-local configuration, or when the plan's storage target is not
accessible from that runner. Require reviewers on the protected environment.

## Manifest shape

The canonical contract is [schemas/release-manifest.schema.json](schemas/release-manifest.schema.json).
The planner enforces that contract before making any retention decision. It
rejects unknown top-level or release fields, missing required fields, invalid
types and formats, and duplicate protected or delta object keys. This is
intentional fail-closed behavior: a misspelled safety field such as `fallbak`
must stop planning instead of being interpreted as `fallback: false`.
The planner also rejects unknown policy keys so a misspelled policy setting
cannot coexist with a valid setting unnoticed.
An abbreviated release looks like this:

```json
{
  "schema_version": 1,
  "product": "kindow",
  "generated_at": "2026-08-26T00:00:00Z",
  "appcast_object_key": "kindow/appcast.xml",
  "releases": [
    {
      "version": "3.2.7",
      "feature_line": "3.2",
      "release_date": "2026-08-25",
      "channel": "stable",
      "notarization_status": "notarized",
      "fallback": true,
      "full_zip_object_key": "kindow/releases/3.2.7/kindow.zip",
      "checksum": "sha256:...",
      "checksum_object_key": "kindow/releases/3.2.7/SHA256SUMS",
      "signature_object_key": "kindow/releases/3.2.7/SHA256SUMS.sig",
      "sparkle_delta_object_keys": [
        "kindow/deltas/3.1.9-3.2.7.delta"
      ]
    }
  ]
}
```

`fallback` remains the v1 compatibility marker. Policy v2 does not keep a
separate R2 installer for every entitlement cutoff: the licensing service
selects the exact archived version, serves GitHub Releases as the primary
archive, falls back to Google Drive, and may populate a short-lived R2 cache.
That cache must have a native bucket lifecycle because it is deliberately
outside this planner's inventory and delete plan.

## Tests

The tests use only Python's standard `unittest` library:

```sh
python3 -m unittest discover -s tests -v
```

The tests include v1 compatibility, archive-evidence gating, live appcast
protection, release metadata evidence, cache exclusion, bounded batch
progression, apply idempotency, deterministic output, and schema parity.
