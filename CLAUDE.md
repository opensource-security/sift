# CLAUDE.md

Guidance for Claude Code when working in this repository. `README.md` is the
user-facing document; this file holds the rules and the things that have bitten
us. Keep it short enough to read in full.

## What this is

Sift is LLM-assisted commit triage for supply-chain security: it builds an
evidence package around a Git commit or PR, asks Claude whether it looks
malicious, and re-judges every finding with independent verifier passes. It
ships as a GitHub Action and as three CLIs. Findings are advisory, never a
merge gate.

## Layout

```
sift/runtime/      case_builder -> primary -> verifier -> benign_challenger; analysis.py orchestrates
sift/render/       GitHub markdown summary + check-run payload
sift/cli/          sift-commit, sift-pr, sift-domain
sift/profiles/     named profiles (model, effort, verifiers, result policy)
sift/provenance/   optional extra: live email-domain provenance (RDAP, CT, GPG)
action/            composite GitHub Action (pull_request_target, read-only analysis)
tests/             regression fixtures pinned to real incidents; scripts, not a framework
docs/              design notes; plans/ and findings/ named YYYY-MM-DD-NNN-slug.md
scripts/           measurement probes; nothing here is wired into the product
.runartifacts/     gitignored run output
```

## Commands

```bash
uv pip install -e .                                    # core, stdlib only
uv pip install -e '.[provenance]'                      # adds sift-domain + live provenance
for t in tests/test_*.py; do python "$t" || break; done # all offline by default; or: pytest tests
sift-commit --repo-path . --sha "$(git rev-parse HEAD)" --ref refs/heads/main --profile maintainer_review_fast_v1
```

No linter is configured. Build backend is `hatchling` via `uv`.

## Hard rules

- **Stdlib only** in `sift/runtime`, `sift/render`, `sift/cli`, `sift/profiles`.
  Only `sift/provenance` may use third-party packages (httpx, tldextract, idna,
  python-dateutil, dnspython). Import direction is one-way: `provenance` may
  import `runtime`, never the reverse. `tests/test_provenance_extra_isolation.py`
  enforces both; keep it green.
- **Fixture repositories are hostile.** The bare mirrors under
  `$SIFT_FIXTURE_MIRRORS` or `../upstream-mirrors` carry live credential
  stealers on `preinstall` hooks and in `.claude`/`.vscode` auto-run configs.
  Read commit metadata and patches only. Never check one out, never point a
  package manager or an editor at one. Mirrors are read, never written.
- **Mirror first.** New fixtures resolve commits with
  `tests/fixture_repos.ensure_commits(repo_slug, shas)`, never by fetching
  GitHub directly. Disclosed malicious commits get purged upstream, and the
  mirror is the only copy that survives. See `docs/testing.md`.
- **Defang in prose, verbatim in records.** Attacker domains and IPs in any
  authored `.md` are written `example[.]xyz`. Captured run output (`.json`,
  `.log`) is left verbatim because it is evidence of what a run produced.
- **Never track payload source.** `.runartifacts/` is gitignored. If a run
  record carries attacker loader code, exclude the file; do not scrub it in
  place.
- **No secrets in the tree, ever.** Keys arrive as env vars at launch.

## Architecture in one screen

1. **Case building** (`runtime/case_builder.py`): patch, file list,
   sensitive-surface classification (`sensitive_surfaces.py`), ownership
   concentration (`file_ownership.py`), author identity and timezone-drift
   history, optional PR social context (`pr_social.py`), optional domain
   provenance.
2. **Primary triage** (`runtime/primary.py`): one model call returns
   `suspicious` or `benign` with 0-3 findings across 12 finding types.
   Unparseable output becomes `unknown`.
3. **Verification** (`runtime/verifier.py`): three perspectives (`balanced`,
   `skeptical`, `counterexample`) vote on each finding independently.
   `verifier_count` controls how many instances run. Each finding gets a
   `matrix.status` (`valid` needs 3 verifications and 0 disproofs); the
   per-commit `findings` key is the *primary* list, and only `sift-pr`
   computes `surviving_findings` (status `valid`/`weak`/`contested`).
4. **Benign challenge** (`runtime/benign_challenger.py`): optional,
   deterministic SHA256-based sampling of benign verdicts to pressure-test.
5. **Rendering** (`render/`): JSON to markdown summary and check run. Any
   surviving finding makes the check `neutral`, otherwise `success`; never
   `failure`.

`runtime/analysis.py` owns `analyze_commit()`, `RunnerConfig` and
`ResultPolicy`. `runtime/providers.py` has the Anthropic, OpenAI and Ollama
clients with rate-limit retry. `runtime/repo_tools.py` exposes the three
read-only git tools. `runtime/assumption_triage.py` is a standalone sibling
pass, not called by `analyze_commit`.

**Defaults differ by entry point.** With no `--profile`, the CLI uses
`claude-opus-4-6` at `max` effort with 3 verifiers; the Action's raw defaults
are Sonnet 4 at `high`. Profiles pin model IDs that are a calibration
snapshot, not the newest model.

### Domain provenance (`sift/provenance/`)

Detects whether a contributor's email domain changed hands since that identity
began using it (npm `node-ipc` 2026, PyPI `ctx` 2022). Drop-and-re-register
resets a domain's RDAP registration date; renewal and transfer do not, so
`used_since < held_since` means the domain left the identity's control.

- `names.py` is the security boundary: domains come from attacker-controlled
  PR metadata and are interpolated into URLs, so validation, IDNA
  normalization, registrable-domain reduction and the skip-list all run before
  any egress.
- `rdap.py`: IANA bootstrap (bundled in `data/`) plus registration parsing.
  Every failure maps to UNKNOWN, never CLEAN.
- `ct.py`: CT and Wayback corroboration, confidence modifier only.
- `identity.py`: `used_since` anchors from GPG UID binding dates and repo
  commits.
- `verdict.py`: the band ladder. The discriminator is whether the identity was
  active *across* the ownership gap.
- Attached to the case as
  `history_before_commit.author_identity_history.domain_provenance`, read as
  evidence, never emitted as a standalone finding. Off unless
  `SIFT_DOMAIN_PROVENANCE=1`.

## Things that have bitten

- **The replay path shows the model far less evidence than the product
  path.** No identity history, no timezone drift, no provenance. Any
  measurement made on `build_replay_case` under-represents what `analyze_commit`
  sends. Details and the full table: `docs/evidence-surfaces.md`.
- **`email_domain_context` is built and rendered but nothing in the product
  passes it.** `analyze_commit` calls `build_realtime_case` without
  `email_domain_intel`. Known gap, deferred. Same doc.
- **`+0000` is not the timezone signal.** Release bots commit at `+0000` too;
  only drift against a per-identity baseline separates them, and an identity
  with no history must yield unknown, not zero drift. The timezone test pins
  the arithmetic. `docs/testing.md` has the three guards.
- **Provenance fixtures can pass while the pipeline wiring is broken**, because
  they construct their own anchors. `test_provenance_pipeline_anchors.py`
  exists for that reason; do not skip it.
- **Replay is opt-in in production.** `SIFT_FIXTURE_REPLAY=1` is set by the
  tests for themselves; a runner with an empty cache would otherwise turn every
  lookup into a `CacheMiss`.

## Environment variables

- `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`: provider credentials.
- `GITHUB_TOKEN`: PR social-context fetching; unauthenticated calls are
  limited to 60 per hour.
- `SIFT_DOMAIN_PROVENANCE=1`: enable live domain-provenance evidence. The only
  outbound network access in case building.
- `SIFT_FIXTURE_LIVE`: provenance HTTP cache mode. Unset replays recorded
  responses and a miss raises; `1` fetches live and records; `refresh`
  re-records.
- `SIFT_FIXTURE_MIRRORS`, `SIFT_FIXTURE_CACHE`: where fixture commit objects
  are resolved from.
- `GITHUB_EVENT_PATH` / `GITHUB_WORKSPACE`: set by GitHub Actions.
