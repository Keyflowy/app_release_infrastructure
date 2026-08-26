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

The checked-in example policy keeps:

- every notarized stable installer from the last 730 UTC calendar days;
- the highest stable patch of every older feature line;
- every release marked `fallback`, regardless of age;
- Sparkle deltas for 90 days;
- prerelease installers for 30 days;
- appcast and metadata objects forever;
- objects not present in the manifest forever.

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
workflow artifact. It is a planning workflow, not an apply workflow. Consumers
should pin the shared workflow to a reviewed release tag once the repository's
first release is published; `main` is used only during bootstrap.

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
in the manifest and inventory are relative to that root and must start with
the product prefix:

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
--hash`, rejects new objects or changed fingerprints, and preserves every
planned keep object. A missing delete candidate is treated as
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
produce plans. Configure `RCLONE_CONFIG` as an environment/repository secret
and require reviewers on the protected environment.

## Manifest shape

The canonical contract is [schemas/release-manifest.schema.json](schemas/release-manifest.schema.json).
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

`fallback` is an explicit product/licensing decision. The retention planner
does not choose a fallback for a license; it only guarantees that a manifest
marked fallback cannot be deleted. The licensing service should generate or
update the manifest marker when a fallback release becomes part of the
product's entitlement policy.

## Tests

The tests use only Python's standard `unittest` library:

```sh
python3 -m unittest discover -s tests -v
```

The tests include exact cutoff dates, old feature-line patch compression,
fallback protection, unnotarized stable releases, delta/prerelease expiry,
unknown-object preservation, deterministic output, and CLI text/JSON output.
