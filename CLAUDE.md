# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Sift is an LLM-assisted commit triage system for supply-chain security. It analyzes Git commits and pull requests using Claude to surface security-relevant findings for maintainer review. It runs as a GitHub Action or via CLI.

## Build & Development

Uses `uv` with `hatchling` backend. The core pipeline has no external runtime
dependencies (stdlib only). The optional `provenance` extra does — see below.

```bash
uv pip install -e .                  # core pipeline, stdlib only
uv pip install -e '.[provenance]'    # adds domain-provenance checks
sift-commit                          # analyze a single commit
sift-pr                              # analyze all commits in a PR
sift-domain                          # contributor email-domain provenance
```

**The stdlib-only rule still applies to `sift/runtime/`, `sift/render/`,
`sift/cli/`, and `sift/profiles/`.** Only `sift/provenance/` may use third-party
packages (httpx, tldextract, idna, python-dateutil, dnspython), and the dependency
direction is one-way: `provenance` may import `runtime`, never the reverse.
`tests/test_provenance_extra_isolation.py` enforces this by scanning for
module-scope imports and by importing the whole pipeline with those modules
blocked.

No linting configuration exists yet. There is no general test suite — `tests/`
holds regression fixtures pinned to specific real incidents, runnable directly
(`python tests/<file>.py`) or under pytest, with no pytest dependency required.
Level-1 assertions are deterministic and free; level-2 assertions that call a
live model are opt-in behind `SIFT_FIXTURE_LIVE=1`.

Three kinds of provenance test, and they catch different things:

- `test_domain_provenance.py` — the two real incidents, replayed from recorded
  RDAP/CT responses against a pinned `now`.
- `test_provenance_scenarios.py` — the band ladder as a table of
  (shape → expected band/role), covering the space *around* those incidents. The
  two deliberate caps live here: a weak (author-date) anchor never reaches
  CRITICAL, and corroboration never moves a band.
- `test_provenance_pipeline_anchors.py` — the wiring from `case_builder` history
  through to a verdict. Four defects once lived in that path simultaneously while
  every incident fixture passed, because those fixtures construct their own
  anchors and enter at `assess_domain`.

Provenance tests set `SIFT_FIXTURE_REPLAY=1` for themselves. Replay is opt-in:
production defaults to live network access, because a fixture cache that is never
populated on a runner would make every lookup a `CacheMiss`.

`test_author_timezone_anomaly.py` pins the authored-at timezone detector in
`case_builder.summarize_author_temporal_complexity_history` against two real 2026
ATO incidents (keyv/ChainDrop, drift +420 from a US Pacific baseline; Injective,
drift −720 from +0800 and independently confirmed by Datadog). Three things it
guards that are easy to break:

- **`+0000` is not the signal.** Legitimate release automation in the keyv repo
  commits at `+0000`, the same offset as the attack. Only drift against a
  *per-identity* baseline separates them, and an identity with no history must
  yield an unknown mode rather than a default of zero drift.
- **Burst position degrades the signal.** The history window ingests the
  attacker's own earlier commits, so `first_seen` flips after the first payload
  commit and mode support decays 20 → 19 → 18. Any per-commit evaluation of a
  burst is therefore *not* independent.
- **Inversion is latent.** Once malicious commits exceed half the window the mode
  becomes the attacker's offset and drift collapses to 0. Both incidents are far
  short (3 commits vs the 11 needed at the default window of 20), so the test
  pins the arithmetic rather than the symptom.

### Fixture commit objects: mirror first

`tests/fixture_repos.py` resolves fixture commits from a local bare mirror before
falling back to the `~/.cache/sift-fixtures` cache and then to GitHub. Use
`ensure_commits(repo_slug, shas)`; do not shallow-fetch from GitHub directly in a
new fixture.

The reason is not speed. Malicious commits get reaped after disclosure, and the
fixture only finds out by erroring. `icflorescu/mantine-datatable@f72462d9` has a
full SHA published in vendor writeups and a repository that is still live, yet the
object is purged network-wide — `upload-pack` says "not our ref", REST says 422,
and all ten post-incident forks agree. Several keyv commits in the corpus are
already unreachable from any branch and survive upstream only because GitHub still
serves unreachable objects by full SHA.

Mirrors are read, never written. They live at `$SIFT_FIXTURE_MIRRORS`
(colon-separated) or `../upstream-mirrors` relative to the repo root, as
`<name>.git`. When capturing an unreachable object, pin it with
`git update-ref refs/mirror/<sha> <sha>` or the next `gc` in that mirror reaps it.

**These trees carry live credential stealers wired to `preinstall` hooks and to
`.claude`/`.vscode` agent auto-run configs. The fixtures read commit metadata and
patches only. Never check one out into a working directory, and never point a
package manager or an editor at one.**

## Architecture

### Analysis Pipeline

1. **Case building** (`runtime/case_builder.py`) — constructs commit context: patches, history, file ownership, path classifications
2. **Primary triage** (`runtime/primary.py`) — Claude identifies security-relevant findings across 12 finding types (dependency_injection, build_ci_change, hidden_network_fetch, etc.) with severity levels (low/medium/high)
3. **Verification** (`runtime/verifier.py`) — multiple verifier instances with different perspectives (balanced, skeptical, counterexample, bounded-context, security-boundary) independently vote on each finding
4. **Benign challenge** (`runtime/benign_challenger.py`) — optionally pressure-tests benign judgments using deterministic SHA256-based sampling
5. **Rendering** (`render/github_summary.py`, `render/github_check.py`) — converts results to GitHub markdown summaries and check-run payloads

### Key Modules

- `sift/runtime/analysis.py` — core orchestrator; `analyze_commit()` is the main library entrypoint. Contains `RunnerConfig` and `ResultPolicy` dataclasses.
- `sift/runtime/providers.py` — LLM provider implementations (Anthropic, Ollama) with rate-limit retry logic. Default model: `claude-opus-4-6`.
- `sift/runtime/repo_tools.py` — read-only git tools exposed to Claude via tool use (git_show_commit, git_show_file, git_log)
- `sift/runtime/sensitive_surfaces.py` — pattern-based path classification (ci_workflow, build_config, dependency_manifest, release_publish)
- `sift/runtime/file_ownership.py` — git log analysis for ownership concentration metrics

### Domain Provenance (`sift/provenance/`, optional extra)

Detects whether a contributor's email domain **changed hands** since that identity
began using it — the maintainer-domain takeover vector behind npm `node-ipc` (2026)
and PyPI `ctx` (2022). Drop-and-re-register resets a domain's RDAP registration
date; renewal and voluntary transfer do not, so `used_since < held_since` means the
domain left the identity's control.

- `names.py` — the security boundary. Domains arrive from attacker-controlled PR
  metadata and are then interpolated into URLs, so validation, IDNA A-label
  normalization, registrable-domain reduction, and the skip-list all run **before**
  any egress.
- `rdap.py` — IANA bootstrap (bundled snapshot in `data/`) plus registration/expiry/
  status parsing. Every failure maps to UNKNOWN, never CLEAN.
- `ct.py` — Certificate Transparency and Wayback corroboration. Confidence modifier
  only; measured to be absent for the domain profile this attack targets.
- `identity.py` — `used_since` anchors (GPG UID binding dates via `gpg
  --list-packets`, repo-local commit dates) and the repo-local dormancy test.
- `verdict.py` — the band ladder. The discriminator is whether the identity was
  active *across* the ownership gap, not how long ago the gap closed.
- Attached to the case as `history_before_commit.author_identity_history.
  domain_provenance` and read by the triage model as evidence, not emitted as a
  standalone finding. Off unless `SIFT_DOMAIN_PROVENANCE=1`.

### CLI Entry Points (defined in pyproject.toml)

- `sift-commit` → `sift.cli.analyze_commit:main`
- `sift-pr` → `sift.cli.analyze_pr:main` (supports GitHub event.json parsing)
- `sift-domain` → `sift.cli.domain_provenance:main` (requires the `provenance`
  extra; guards its own import and exits 2 with an install hint without it)

### GitHub Action

`action/action.yml` is a composite action. Key design decision: uses `pull_request_target` trigger so the action runs on the base branch (trusted code) while analyzing untrusted PR commits read-only — PR code is never checked out or executed.

### Environment Variables

- `SIFT_DOMAIN_PROVENANCE=1` — enable domain-provenance evidence during case
  building. Off by default: it is the only part of case building that makes
  outbound network requests.
- `SIFT_FIXTURE_LIVE` — fixture cache mode for `sift/provenance/http_cache.py`.
  Unset replays recorded responses (offline, deterministic, a miss raises); `1`
  fetches live and records on miss; `refresh` re-records unconditionally.
- `ANTHROPIC_API_KEY` — required for the anthropic provider
- `GITHUB_TOKEN` — for PR social context fetching
- `GITHUB_EVENT_PATH` / `GITHUB_WORKSPACE` — set automatically in GitHub Actions
