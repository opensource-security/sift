# Evidence surfaces: what the model actually sees

Read this before measuring sift. The two case builders carry **different
evidence surfaces**, and it is easy to draw a wrong conclusion by measuring on
the thinner one. Verified 2026-08-21.

## By case path

| evidence block | `build_replay_case` (replay/eval path) | `build_realtime_case` (product: `analyze_commit`) |
|---|---|---|
| patch + basic history (`author_first_seen_*`, prior counts) | yes | yes |
| `author_identity_history` (name/email drift, splits) | **no** | yes |
| `author_temporal_complexity_history` (timezone drift, cadence) | **no** | yes |
| `domain_provenance` band | no | only if `SIFT_DOMAIN_PROVENANCE=1` (off by default) |
| `email_domain_context` | only if caller passes `email_domain_intel` | **not passed by `analyze_commit`** (see gap below) |

Consequences that have already bitten:

- **Replay runs show the LLM almost none of the behavioral evidence**: no
  identity history, no timezone drift, no provenance. The "15/15 with and
  without email evidence" ceiling result was measured on replay cases whose
  only optional block was the email one; identity/timezone were never in those
  prompts. Judged replay numbers therefore **under-represent the product's
  evidence surface**. To measure the impact of identity/timezone evidence, use
  the realtime path (`build_realtime_case`, as `analyze_commit` does), not the
  replay path.
- **Known gap: `email_domain_context` is built and prompt-rendered but NOT
  wired into the product.** Both builders *accept* an `email_domain_intel`
  argument, but `analyze_commit` (and thus `sift-commit`, `sift-pr` and the
  Action) calls `build_realtime_case` without it. So a live run today sends
  the model no email-domain evidence. Wiring it in (env-gated, mirroring
  `SIFT_DOMAIN_PROVENANCE`) is deferred pending an evidence-impact experiment.

## Two email-domain evidence paths

Reconciled per `docs/plans/2026-08-21-001-merge-domain-provenance-plan.md`.
The snapshot file is the seam, and the one-way import rule is why composition
happens through data, never through imports.

| | offline snapshot (`email_domain_intel` param) | live engine (`SIFT_DOMAIN_PROVENANCE=1`) |
|---|---|---|
| module | `sift/runtime/email_domain.py` (stdlib) | `sift/provenance/` (extra) |
| lookups | none; reads a snapshot written out-of-band | live RDAP/CT/DNS, replayable cache |
| unique evidence | forged-bot/freemail/infra taxonomy | band ladder, GPG anchors, gap activity |
| case block | `email_domain_context` | `author_identity_history.domain_provenance` |
| resurrection | S4 boolean; prefers a v2 snapshot's band when present | band ladder (authoritative) |
| writers of the snapshot | an out-of-band stdlib fetch script (v1, `"writer": "stdlib"`) | `sift.provenance.export_intel.export_intel` (v2, adds `registrable_domain` + `provenance` band block) |

Both switches are independent; either, both, or neither may be on. When both
render into a prompt, each line names its source and observation time.
