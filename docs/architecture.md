# Shared Release Infrastructure

This repository owns release-retention mechanics shared by Keyflowy products.
It does not own license records, payments, device bindings, or user data.

## Ownership boundary

Each App repository owns its release workflow, R2 prefix, retention policy, and
release manifest. This repository owns the reusable workflow, manifest schema,
planner, and safety contract. The API service owns licensing semantics and
records which fallback release a paid license receives. The client SDK verifies
the signed result. A website may request an authorized download but never
implements retention or licensing rules.

Use separate R2 prefixes and scoped credentials for every product, for example:

```text
keyflowy-apps/kindow/
keyflowy-apps/keyflowy/
keyflowy-apps/another-app/
```

## Integration contract

An App calls the reusable workflow with its product name, policy path, manifest
path, and R2 prefix. The workflow passes the manifest to
`scripts/release-retention/plan.py`. The planner is deterministic with an
explicit `--as-of`, defaults to dry-run, and never invokes `rclone`.

The apply workflow is a separate protected action. It may delete only objects
present in a reviewed plan whose reason is an approved expiry rule. Protected
metadata, explicit fallback releases, recent stable installers, and unknown
objects are never deletion candidates.

The first product integration can keep the workflow invocation in its own
repository. When a second product uses the same contract, publish a pinned
reusable workflow tag and migrate products independently. Do not share one
global policy file across products.

## Versioning

Changes to the manifest schema or planner behavior require a versioned release
of this repository. Policy changes remain in the App repository and require an
ADR plus fixture-test updates there. A schema change must be additive or use a
new schema version; the planner must reject an unknown version rather than
guessing.
