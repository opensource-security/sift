# sift

**LLM-assisted commit triage for supply-chain security.**

Sift analyzes Git commits and pull requests with Claude to surface
security-relevant findings for maintainer review. It runs as a GitHub Action
that drops into any repository, or as a CLI for ad-hoc analysis and CI
pipelines.

Two complementary triage passes operate on the same evidence:

- **Intent triage** — "is this commit suspicious as the work of a malicious
  actor?" Calibrated for supply-chain backdoor patterns: identity anomalies,
  CI/build tampering, hidden network fetches, obfuscated payloads, secret
  exposure, dependency injection.
- **Assumption triage** — "for each meaningful change, what preconditions does
  the new code assume, and do they hold under all realistic inputs?"
  Calibrated for code-review-style precondition auditing.

Each finding is then independently re-evaluated by a verifier matrix
(`balanced` / `skeptical` / `counterexample` perspectives) before being
reported, and benign judgments can optionally be pressure-tested with a
deterministic challenger pass.

## Install

Python 3.10+. Stdlib only at runtime.

```bash
pip install -e .
# or with uv
uv pip install -e .
```

This exposes two CLI entry points:

| Command | Purpose |
|---|---|
| `sift-commit` | Analyze one commit by SHA |
| `sift-pr` | Analyze every commit in a pull request |

## Quickstart — GitHub Action

Drop this workflow into `.github/workflows/sift.yml` in any repo:

```yaml
name: Sift PR Review

on:
  pull_request_target:
    types: [opened, synchronize, reopened, ready_for_review]

permissions:
  checks: write
  contents: read
  pull-requests: read

concurrency:
  group: sift-pr-${{ github.event.pull_request.number }}
  cancel-in-progress: true

jobs:
  sift:
    runs-on: ubuntu-latest
    timeout-minutes: 90
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.base.ref }}
          fetch-depth: 0

      - uses: opensource-security/sift/action@v1
        with:
          api_key: ${{ secrets.ANTHROPIC_API_KEY }}
```

Findings appear as a non-blocking check-run summary on the PR, with the full
JSON artifact attached to the workflow run.

A copy lives at `action/workflow_examples/pr_review.yml`.

### Threat model — why `pull_request_target`

`pull_request_target` runs the workflow in the context of the **base** branch,
which means it has access to repository secrets (e.g. `ANTHROPIC_API_KEY`).
Using it naively is dangerous: the standard advice against
`pull_request_target` is that PRs from forks could exfiltrate those secrets if
the workflow checks out and executes PR code.

Sift is designed around that risk:

1. **Base branch only is checked out.** The workflow checks out
   `github.event.pull_request.base.ref` — never the PR head.
2. **PR objects are fetched, never checked out.** The action fetches the PR
   head SHA into the local object database with `git fetch
   +refs/pull/N/head:refs/remotes/origin/pr/N/head`. This populates
   `git cat-file` and `git log` but does not place PR files on disk.
3. **Read-only git tools only.** When the model uses tools, they are
   read-only views into the object database (`git_show_commit`,
   `git_show_file`, `git_log`). No PR file is written to the working tree
   and no PR script ever executes.

This pattern lets sift evaluate the PR's commit content with full trust in
its own analysis tooling, while keeping repository secrets safe from
fork-controlled code.

## Quickstart — CLI

```bash
export ANTHROPIC_API_KEY=...

# One commit
sift-commit \
    --repo-path /path/to/repo-or-bare-mirror \
    --sha <commit-sha> \
    --ref refs/heads/main \
    --output sift_commit.json

# Every commit in a PR (requires GitHub Actions event JSON, or pass --base/--head)
sift-pr \
    --repo-path /path/to/repo \
    --pr-number 42 \
    --base-sha <base> \
    --head-sha <head> \
    --output sift_pr.json
```

## Profiles

Three named profiles bundle model, thinking, effort, verifier count, tool
mode, and result policy into stable configurations:

| Profile | Model | Thinking | Effort | Verifiers | Tool mode |
|---|---|---|---|---|---|
| `maintainer_review_v1` (default) | Sonnet | adaptive | high | 3 | readonly |
| `maintainer_review_fast_v1` | Haiku | off | medium | 1 | none |
| `maintainer_review_max_v1` | Opus | adaptive | max | 5 | readonly |

```bash
sift-pr --profile maintainer_review_max_v1 ...
```

## Output shape

Each run writes a single JSON artifact containing:

- **Case envelope** — observed commit metadata, build/CI/dependency surface
  classification, file ownership concentration, optional PR/social context.
- **Primary findings** — list of intent-triage findings with severity,
  confidence, claim, and evidence references back into the case.
- **Verifier matrix** — per-finding votes from `balanced` / `skeptical` /
  `counterexample` perspectives, plus an aggregate `verification_ratio`.
- **Surviving findings** — those that passed the matrix threshold.
- **Optional benign-challenger** — pressure-tested benign judgments.
- **Token / round usage** — for cost auditing.

The render layer (`sift.render.github_summary`, `sift.render.github_check`)
turns the JSON into the GitHub markdown summary and check-run payload the
action posts.

## Pipeline

```
                 +--------------------+
   commit ------>| case_builder       |  ---+
   ref           +--------------------+     |
   observed_at        |                     |
                      v                     |
                 +--------------------+     |
                 | primary triage     |     |
                 | (intent prompt)    |     |
                 +--------------------+     |
                      |                     |
                      v                     v
                 +--------------------+   +-----------------+
                 | verifier matrix    |   | assumption      |
                 | balanced/skeptical/|   | triage          |
                 | counterexample     |   | (sibling pass)  |
                 +--------------------+   +-----------------+
                      |
                      v
                 +--------------------+
                 | benign challenger  |  (optional)
                 +--------------------+
                      |
                      v
                 JSON artifact + GitHub markdown summary + check run
```

Module map:

| Module | Role |
|---|---|
| `sift/runtime/case_builder.py` | Build bounded `CommitCase` from repo + ref + observed_at |
| `sift/runtime/primary.py` | Intent-triage prompt and 12 finding types |
| `sift/runtime/assumption_triage.py` | Code-review-shaped sibling pass (12 precondition kinds) |
| `sift/runtime/verifier.py` | 3-variant verifier matrix |
| `sift/runtime/benign_challenger.py` | Optional pressure-test of benign judgments |
| `sift/runtime/repo_tools.py` | Read-only git tools exposed to the model |
| `sift/runtime/sensitive_surfaces.py` | Path classification (CI / build / deps / release) |
| `sift/runtime/file_ownership.py` | Ownership-concentration metrics |
| `sift/runtime/pr_social.py` | Optional PR metadata enrichment via GitHub REST |
| `sift/runtime/providers.py` | Anthropic + Ollama model providers |
| `sift/runtime/analysis.py` | Top-level `analyze_commit()` orchestrator |
| `sift/cli/` | `sift-commit` / `sift-pr` entrypoints |
| `sift/render/` | GitHub markdown summary and check-run rendering |
| `action/action.yml` | Composite GitHub Action |

## Limitations

- Findings are advisory. Sift produces signals for human review, not
  automated merge gates. The action is non-blocking by design.
- Anthropic only by default. Ollama is supported (`--runner ollama`) but
  receives less calibration than the Claude path.
- The assumption-triage pass is standalone in this release: it has no
  verifier matrix and is not yet wired into `analyze_commit`. Run it via
  `run_assumption_triage()` directly.
- `pr_social.py` makes unauthenticated GitHub REST calls when no token is
  provided; expect the standard 60 req/hr rate limit.
- Large diffs are truncated at 12 kB by default (`--max-patch-chars`).

## Development

```bash
uv pip install -e .
```

No test suite yet. The `runtime/` package has no external runtime
dependencies; the CLI surface is stdlib only.

## License

MIT. See [LICENSE](LICENSE).
