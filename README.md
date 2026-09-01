# Gooo claim/evidence lifecycle

This repository answers one precise question: when evidence arrives, does a claim disappear naturally?

No. A claim is never silently removed. The evaluator records the original claim as a tombstone and emits a stable causal edge for the resulting decision. Evidence can lead to `SUPPORTED`, `REFUTED`, or `SUPERSEDED`. Missing, stale, ambiguous, or unbounded evidence keeps an `UNKNOWN` frontier. `REFUTED` has precedence over `UNKNOWN`, and no decision is closed by natural-language guesswork.

The lifecycle contract is authored by [.gooo/claim-evidence-lifecycle.gooo](.gooo/claim-evidence-lifecycle.gooo). It owns the state machine, evidence admissibility, supersession, retention, precedence, and artifact schema. Go only interprets that contract and produces the caller-owned result directory.

## Run in CI

The authoritative path is GitHub Actions on Go 1.27. It compiles, builds, tests, runs conformance, and runs integration without writing to the input tree. The runtime writes exactly these six files to the requested output directory:

- `claim-ledger.ndjson`
- `evidence-ledger.ndjson`
- `transition-events.ndjson`
- `lifecycle-receipt.json`
- `replay-receipt.json`
- `report.md`

The receipt records twelve canonical cases: four `CLOSED`, four `UNKNOWN`, and four `REFUTED`. Every `UNKNOWN` row carries `stage`, `step`, `reason`, `unknown_class`, `next_operation`, and `blocked_by`. Counts are exact; no confidence arithmetic is used.

The release workflow enables the repository's immutable-release setting once, verifies the successful post-main artifact, creates an annotated tag, creates the draft release before uploading assets, and publishes the populated release. It uses only `github.token` in Actions.
