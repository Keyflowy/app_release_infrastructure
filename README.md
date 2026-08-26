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

The planner is intentionally dry-run only. It never invokes `rclone`, writes
to R2, or deletes an object. A future apply step must consume its reviewed JSON
plan and require an explicit, separately protected action.

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
