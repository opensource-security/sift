<!--
Plan: merge the quarantined domain-provenance branch and reconcile it with the
email-domain enrichment work landed on main 2026-08-21.
Status: proposed (not yet executed).
-->

# feat: Fold `origin/domain-provenance` into main + reconcile with `email_domain.py`

**Target repo:** `sift`. The
branch under review is `origin/domain-provenance` (6 commits, 2026-07-31 →
2026-08-08, ~12k lines, base `ca6401a` = origin/main), preserved pre-wipe and
explicitly quarantined "so it can be reviewed before merging". The work to
reconcile with is main `e1378b9` (`sift/runtime/email_domain.py` + case-builder
wiring; signals S1–S4, measured margin −1 → +1).

## Summary

The two implementations attack the same vector from opposite ends and barely
collide. The branch is the **engine**: live RDAP/CT/GPG domain-provenance facts
behind a `provenance` extra, a band-ladder verdict (`CLEAN … CRITICAL`) whose
discriminator is identity activity *across* the ownership gap, a hardened
security boundary for attacker-controlled domain strings, an author-timezone
drift detector, and two new incident fixtures (keyv/ChainDrop, Injective).
Main's `email_domain.py` is the **stdlib evidence path**: offline snapshot,
forged-bot lexical taxonomy (absent from the branch — verified), and the
corpus-measured heuristic separation. The fold: **merge the branch as-is, then
make the snapshot file the data seam between them** — the provenance engine
gains an intel exporter, the runtime reader gains band passthrough, and the
dependency rule (`provenance` may import `runtime`, never the reverse) is
never violated because composition happens through data, not imports.

## What each side has that the other lacks

| capability | branch (`sift/provenance/`) | main (`email_domain.py`) |
|---|---|---|
| RDAP | live httpx + bundled IANA bootstrap + replay cache | offline snapshot (urllib/dig, out-of-band script) |
| registrable-domain reduction / IDNA | `names.py` security boundary (tldextract, idna) | naive full-domain string (documented gap) |
| resurrection semantics | band ladder + gap-activity discriminator + weak-anchor cap | S4 boolean (`registered_at > first_seen`) |
| corroboration | CT + Wayback (`ct.py`, confidence-only) | none |
| identity anchors | GPG UID binding dates + repo commits | repo history only |
| forged-bot / freemail / infra taxonomy | **absent** | S1 + classification (the margin result) |
| temporal honesty | pinned `now`, replay mode | realtime/retrospective field gating |
| case block | `author_identity_history.domain_provenance` (env-gated `SIFT_DOMAIN_PROVENANCE=1`, live) | `email_domain_context` (snapshot param, offline) |
| timezone drift detector | in case_builder + pinned tests | none |

Conflict geometry (verified): branch case_builder hunks at ~251/1525/2242; main's
email-domain hunks at the import block, both builder signatures, and both
builder tails — **disjoint**. Real conflicts expected only in `CLAUDE.md` (both
rewrote the module docs) and possibly `.gitignore`/`pyproject.toml` (trivial).

## Key Technical Decisions

- **KTD1 — merge first, reconcile after.** The quarantine contract is
  review-then-merge of the branch *as it was*; reconciliation lands as
  follow-up commits on main, never as merge-time semantic edits. Keeps the
  branch's test suite meaningful as a merge gate.
- **KTD2 — the snapshot is the seam.** Runtime must stay stdlib and may not
  import provenance. So: snapshot schema **v2** adds per-domain
  `registrable_domain` and an optional `provenance` sub-object (band,
  `used_since`/`held_since`, gap-activity summary, `assessed_at`). Writers:
  a new provenance-side exporter (rich, requires the extra) and the existing
  stdlib fetch script (v1-compatible, marks `"writer": "stdlib"`). The
  runtime reader accepts both.
- **KTD3 — resurrection converges on the band ladder; S4 is the degraded
  mode.** When a snapshot carries a provenance band, evidence and heuristics key
  on the band (`LIKELY`/`CRITICAL`); the S4 boolean remains the stdlib
  fallback and is never deleted. The branch's two deliberate caps (weak
  author-date anchors never reach CRITICAL; corroboration never moves a band)
  are semantics the boolean cannot express — one more reason the band wins
  when present.
- **KTD4 — S1 stays in runtime.** The forged-bot taxonomy is stdlib-pure,
  needs no network, and the measured margin result depends on it being available
  without the extra. Nothing ports into provenance.
- **KTD5 — both case blocks survive short-term.** `email_domain_context`
  (offline/eval) and `author_identity_history.domain_provenance`
  (live/production) are pinned by existing measurements and tests
  respectively. When both render into a prompt, each line names its source and
  observation time so a disagreement (e.g. snapshot stale vs live lookup) is
  legible rather than contradictory. Full convergence is explicitly deferred.
- **KTD6 — switch matrix documented, not unified.** `SIFT_DOMAIN_PROVENANCE=1`
  (live engine) and the `email_domain_intel` param (offline snapshot) remain
  independent; CLAUDE.md gets the 2×2 of what fires when.

## Scope Boundaries

- No changes to the branch's verdict semantics, band ladder, or security
  boundary in this plan.
- No new incident-fold integration (keyv/ChainDrop and mantine-datatable enter
  as already-merged sift fixtures only; corpus folds are out of scope).
- No CT-corroboration data in the snapshot yet (deferred with KTD2 room left
  for it).

## Requirements

- Network + scratch venv for U1 (installing `.[provenance]`; replay tests
  themselves run offline via `SIFT_FIXTURE_REPLAY=1`).
- Post-wipe hazard: `$SIFT_FIXTURE_MIRRORS` / `../upstream-mirrors` and
  `~/.cache/sift-fixtures` were **wiped**. Provenance HTTP-replay fixtures are
  in-repo (fine), but `fixture_repos.ensure_commits` fallbacks may refetch from
  GitHub — several keyv commits survive upstream only by full SHA, and the
  mantine-datatable object is documented as purged network-wide. U1 must
  record which fixtures still resolve; any that don't are a wipe casualty to
  report, not silently skip. **Safety rule carried from the branch: fixture
  mirrors carry live credential stealers wired to preinstall/agent-config
  auto-run — read metadata and patches only, never check out, never point a
  package manager or editor at one.**

## Implementation Units

### U1. Pre-merge review gate on the branch as-is

Scratch venv; `uv pip install -e '.[provenance]'` at
`origin/domain-provenance`; run `test_provenance_extra_isolation`,
`test_domain_provenance`, `test_domain_provenance_prior`,
`test_provenance_scenarios`, `test_provenance_pipeline_anchors`,
`test_author_timezone_anomaly`, and the refactored
`test_asyncapi_patch_budget` (all with `SIFT_FIXTURE_REPLAY=1` where they
self-set it). Read `docs/domain-provenance-plan.md`'s limitations section and
the "--all flaw" production-run note before merging, not after. Deliverable: a
green/red table per suite, plus the post-wipe fixture-resolution report.

### U2. Merge into main

`git merge origin/domain-provenance` on sift main. Expected conflict:
`CLAUDE.md` — resolve by keeping the branch's rewritten build/provenance
sections and re-inserting main's `email_domain.py` bullet into the module
list. case_builder conflicts, if any, are positional only (disjoint hunks —
keep both sides verbatim). Post-merge gates, in order: `py_compile` across
`sift/**/*.py`; the 7 email-domain fixture tests; the U1 suite list again;
`test_provenance_extra_isolation` specifically confirming `email_domain.py`
kept runtime stdlib-pure. Merge commit message records the quarantine
provenance (branch, preserve date, review gate result).

### U4. Snapshot schema v2 + the two writers

- `sift/provenance/export_intel.py` (or a `sift-domain --export-intel PATH`
  flag): assess the domains of a case/identity and write the v2 snapshot —
  `registrable_domain` via `names.py`, `provenance` sub-object per KTD2,
  `snapshot_version: email_domain_intel_v2`.
- Stdlib fetch script: stamp `"writer": "stdlib"`;
  no other change (v1 remains valid).
- `sift/runtime/email_domain.py`: accept v1 and v2; pass `registrable_domain`
  and band through into the role context and one prompt line
  (`provenance band: LIKELY (used_since 2021-03 < held_since 2026-06)`).
  Extend the fixture tests with a v2 snapshot case.

### U6. Docs and memory

- CLAUDE.md: the KTD6 switch matrix (live engine × offline snapshot).
- Memory: mark the reconciliation done; record that keyv/ChainDrop and
  mantine-datatable are known incidents held as sift fixtures.

### Deferred (named, not scoped here)

Case-block convergence (KTD5); CT/Wayback data in the snapshot; wiring
`sift-domain` into the GitHub Action beyond what the branch already did.

## Estimate / risk

U1–U2 are a day's careful work dominated by U1 review reading; U4 a second
day. Risks: (a) post-wipe fixture resolution failures in U1 — report, don't
mask; mirrors may need re-capture while objects still exist upstream (the
branch's own lesson: reaping is network-wide and silent); (b) the branch's
production-run doc records a known `--all` flaw — confirm its status before
exposing the CLI further; (c) prompt-length growth from two evidence sections —
if judged runs show bloat, KTD5 convergence moves up the queue; (d) the two
`now`/`observed_at` disciplines (pinned-now vs snapshot observed_at) must not
be mixed silently in one prompt — U4's source-labeled lines are the guard.
