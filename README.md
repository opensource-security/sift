# sift

**LLM-assisted commit triage for supply-chain security.**

Sift reads a Git commit or pull request, builds a bounded evidence package
around it (patch, author history, which sensitive surfaces it touches), and
asks Claude whether the change looks like the work of a malicious actor. Every
finding is then re-judged by independent verifier passes before it reaches a
maintainer. It runs as a GitHub Action that drops into any repository, or as a
CLI.

Sift is advisory. It produces signals for a human to review, never a merge
gate.

## Contents

- [How it works](#how-it-works)
- [Install](#install)
- [First run in five minutes](#first-run-in-five-minutes)
- [Reading the output](#reading-the-output)
- [GitHub Action](#github-action)
- [CLI reference](#cli-reference)
- [Profiles and defaults](#profiles-and-defaults)
- [Cost and runtime](#cost-and-runtime)
- [Optional evidence sources](#optional-evidence-sources)
- [Limitations](#limitations)
- [Contributing](#contributing)

## How it works

```
   commit + ref + observed_at
             |
             v
   +--------------------+
   | case builder       |  patch, file list, author history, timezone drift,
   |                    |  sensitive-surface classification, ownership metrics
   +--------------------+
             |
             v
   +--------------------+
   | primary triage     |  Claude: suspicious | benign, with 0-3 typed findings
   +--------------------+
             |
             v
   +--------------------+
   | verifier matrix    |  balanced / skeptical / counterexample, each votes
   |                    |  on every finding independently
   +--------------------+
             |
             v
   +--------------------+
   | benign challenger  |  optional: pressure-tests a "benign" verdict
   +--------------------+
             |
             v
   JSON artifact  ->  GitHub markdown summary + check run
```

The primary pass looks for twelve kinds of finding: `dependency_injection`,
`build_ci_change`, `hidden_network_fetch`, `suspicious_execution_primitive`,
`identity_anomaly`, `maintainer_behavior_deviation`, `obfuscated_payload`,
`secret_exposure`, `suspicious_persistence`, `release_process_tampering`,
`security_boundary_change`, and `other`. Each carries a severity
(`low`/`medium`/`high`) and evidence references back into the case.

When tool mode is on, the model can call three read-only git tools
(`git_show_commit`, `git_show_file`, `git_log`) to look beyond the truncated
patch. Nothing it reads is ever written to disk or executed.

## Install

Python 3.10 or newer. The core pipeline uses the standard library only.

```bash
# core: sift-commit and sift-pr
uv pip install -e .            # or: pip install -e .

# optional: adds sift-domain and live domain-provenance checks
uv pip install -e '.[provenance]'
```

You need an API key for one provider:

| Provider | Env var | Notes |
|---|---|---|
| Anthropic (default) | `ANTHROPIC_API_KEY` | the calibrated path |
| OpenAI | `OPENAI_API_KEY` | text completion only, no tool use |
| Ollama | none | local or over SSH, see `--ollama-*` flags |

## First run in five minutes

Point sift at its own repository and analyze the current commit:

```bash
export ANTHROPIC_API_KEY=...      # or however you inject secrets

git clone https://github.com/opensource-security/sift
cd sift
uv pip install -e .

sift-commit \
    --repo-path . \
    --sha "$(git rev-parse HEAD)" \
    --ref refs/heads/main \
    --profile maintainer_review_fast_v1 \
    --output first_run.json
```

The fast profile uses the cheapest model with one verifier and no tool use,
which makes it the cheapest configuration to try first. When it finishes you
will see something like:

```
classification=benign
confidence=high
findings=0
total_input_tokens=...
total_output_tokens=...
```

Then open `first_run.json` and read on.

## Reading the output

Every run writes one JSON document. The parts a reader cares about, in order:

| Key | What it holds |
|---|---|
| `primary_result.classification` | `suspicious`, `benign`, or `unknown` (the model's answer did not parse) |
| `primary_result.confidence` | the model's own confidence in that call |
| `primary_result.reasoning` | its explanation, in prose |
| `findings` | every finding the primary pass raised, before verification |
| `verifier_results` | one entry per finding: the verifier votes and a `matrix.status` verdict |
| `benign_challenge_result` | present only when the challenger ran |
| `case` | the evidence the model saw: patch, history, surface classification |
| `total_usage` | input and output tokens across all calls, for cost auditing |

Each verifier votes `verify`, `disprove`, or `abstain` on a finding. The
matrix status summarizes the votes:

| `matrix.status` | Rule |
|---|---|
| `valid` | at least three verifications and no disproofs |
| `weak` | some verifications, no disproofs, fewer than three |
| `contested` | verifications and disproofs both present |
| `lean_rejected` | disproofs only, fewer than three |
| `rejected` | at least three disproofs and no verifications |
| `insufficient` | no usable votes |

Note that `valid` needs three agreeing verifiers, so a profile with one
verifier can never produce it. `weak` is the best a single verifier can say.

For a PR run, `sift-pr` wraps the per-commit payloads and adds two lists and a
`summary`. `surviving_findings` holds every finding whose status is `valid`,
`weak`, or `contested`. `verified_findings` holds only the `valid` ones.
`summary.surviving_findings_total` drives the GitHub check-run conclusion:
any surviving finding makes the check `neutral`, otherwise `success`. It is
never `failure`.

## GitHub Action

### Quickstart

Drop this into `.github/workflows/sift.yml`:

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

Findings appear as a non-blocking check run on the PR. The full JSON artifact
is attached to the workflow run. A copy of this workflow lives at
`action/workflow_examples/pr_review.yml`.

### Inputs

| Input | Default | Meaning |
|---|---|---|
| `api_key` | required | provider key; exported as `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` |
| `profile` | none | a named profile; when set it overrides the five rows below |
| `provider` | `anthropic` | `anthropic`, `openai`, or `ollama` |
| `model` | `claude-sonnet-4-20250514` | model ID for the chosen provider |
| `thinking` | `adaptive` | `adaptive` or `off` (Anthropic only) |
| `effort` | `high` | Anthropic `low`/`medium`/`high`/`max`; OpenAI `minimal`/`low`/`medium`/`high` |
| `verifier_count` | `3` | verifier passes per finding |
| `tool_mode` | `readonly` | `readonly` or `none` |
| `max_commits` | `0` | cap on PR commits analyzed; `0` means all |
| `pr_social_mode` | `off` | `current_pr` adds PR metadata via the GitHub REST API |
| `domain_provenance` | `off` | `on` enables live email-domain provenance lookups |
| `artifact_retention` | `30` | days to keep the uploaded artifact |

### Outputs

`artifact_path`, `summary_path`, `commits_analyzed`, `surviving_findings`,
and `review_recommended` (true when `surviving_findings` is above zero).

### Threat model: why `pull_request_target`

`pull_request_target` runs the workflow in the context of the **base** branch,
so it can read repository secrets. The usual warning is that a fork PR could
exfiltrate those secrets if the workflow checks out and executes PR code. Sift
never does:

1. **Only the base branch is checked out.** The workflow checks out
   `github.event.pull_request.base.ref`, never the PR head.
2. **PR objects are fetched, never checked out.** The action fetches the PR
   head into the local object database. `git cat-file` and `git log` can see
   it, but no PR file lands on disk.
3. **The model's tools are read-only.** They are views into the object
   database. No PR file is written to the working tree and no PR script runs.

## CLI reference

Three commands. Each prints `--help` with the full flag list.

**`sift-commit`**: one commit.

```bash
sift-commit --repo-path PATH --sha SHA --ref REF [--profile NAME] [--output FILE]
```

`--repo-path` accepts a working checkout or a bare mirror. `--ref` is the
branch the commit was observed on and feeds the author-history baseline.

**`sift-pr`**: every commit in a pull request.

```bash
# inside GitHub Actions: reads the event payload
sift-pr --repo-path . --event-json "$GITHUB_EVENT_PATH" --output sift_pr.json

# anywhere else: name the range yourself
sift-pr --repo-path . --pr-number 42 --base-sha BASE --head-sha HEAD --output sift_pr.json
```

**`sift-domain`**: has a contributor's email domain changed hands since they
started using it? Requires the `provenance` extra.

```bash
sift-domain --email someone@example.org --repo-path . [--json] [--public]
```

Flags shared by the first two commands that you may want early:
`--runner {anthropic,openai,ollama}`, `--verifier-count N`,
`--max-patch-chars N` (default 12000; larger diffs are truncated),
`--benign-challenge-mode if_primary_benign`.

## Profiles and defaults

A profile bundles model, thinking, effort, verifier count, tool mode, and
result policy into one name, so that a run is reproducible.

| Profile | Model | Thinking | Effort | Verifiers | Tools |
|---|---|---|---|---|---|
| `maintainer_review_v1` | Sonnet 4 | adaptive | high | 3 | readonly |
| `maintainer_review_fast_v1` | Haiku 4.5 | off | medium | 1 | none |
| `maintainer_review_max_v1` | Opus 4.6 | adaptive | max | 5 | readonly |

Two things catch newcomers:

- **No profile is applied unless you pass one.** Without `--profile`, the CLI
  falls back to raw defaults: Opus 4.6, adaptive thinking, **max** effort,
  three verifiers. That is the most expensive configuration, not the
  "standard" one. The Action's raw defaults differ again (Sonnet 4, high
  effort). Pass a profile when you want predictable cost.
- **Model IDs are pinned in `sift/profiles/__init__.py`.** They are a
  snapshot of what was calibrated, not a claim about the newest model. Any
  Anthropic model ID can be given with `--anthropic-model`.

## Cost and runtime

One commit means one primary call, one call per verifier, plus any tool rounds
the model requests. The CLI prints total input and output tokens when it
finishes, and the JSON carries the same numbers under `total_usage`, so
measure a few commits in your own repository before deciding on a profile for
CI. As a rough scale, a benign commit under a tool-enabled profile has been
observed to consume on the order of a hundred thousand input tokens across all
calls; the fast profile is a small fraction of that.

Wall-clock time is dominated by the model. Use the Action's
`timeout-minutes` and `max_commits` to bound a large PR.

## Optional evidence sources

Off by default. Each adds evidence the model reads; none emits a finding by
itself.

- **PR social context** (`pr_social_mode: current_pr`, or `--pr-social-json`):
  the author's association and repository permission, non-author review
  activity, the branch's review policy, and draft state. Unauthenticated
  calls are rate-limited to 60 per hour; set `GITHUB_TOKEN` in CI.
- **Domain provenance** (`SIFT_DOMAIN_PROVENANCE=1`, `provenance` extra):
  checks RDAP, Certificate Transparency and GPG key history to tell whether an
  author's email domain was dropped and re-registered after they began using
  it. This is the maintainer-domain takeover vector behind npm `node-ipc`
  (2026) and PyPI `ctx` (2022). It is the only part of case building that
  makes outbound network requests.
- **Email-domain snapshot** (`email_domain_intel` argument to the library
  API): offline classification of author domains against a snapshot you
  supply. Not reachable from the CLI or the Action yet.

## Limitations

- Findings are advisory. The check run is never `failure`.
- Anthropic is the calibrated path. OpenAI and Ollama run the same prompts
  but without tool use, and have had far less tuning.
- The assumption-triage pass (`sift/runtime/assumption_triage.py`), which
  audits preconditions the new code assumes, is standalone. It has no verifier
  matrix and is not called by `analyze_commit`.
- Patches are truncated at 12 kB by default. With tool mode on, the model can
  fetch the rest; with it off, it cannot.
- Timezone-drift and identity-drift signals need author history in the
  repository. A first-time contributor has no baseline, so drift is unknown
  rather than zero. A shallow clone is flagged to the model with a
  `visible_history_is_shallow` caveat.

## Contributing

### Layout

```
sift/runtime/      case building, triage, verification  (stdlib only)
sift/render/       GitHub markdown summary and check-run payload
sift/cli/          sift-commit, sift-pr, sift-domain
sift/profiles/     named profiles
sift/provenance/   domain-provenance engine  (optional extra; may use third-party packages)
action/            composite GitHub Action and example workflow
tests/             regression fixtures pinned to real incidents
docs/              design notes, plans/, findings/
scripts/           measurement probes; nothing here is wired into the product
```

### Rules

- `sift/runtime`, `render`, `cli` and `profiles` stay standard-library only.
  Only `sift/provenance` may import third-party packages, and
  `provenance` may import `runtime`, never the reverse.
  `tests/test_provenance_extra_isolation.py` enforces both.
- Fixture repositories contain live credential stealers. Fixtures read commit
  metadata and patches only. Never check one out into a working directory, and
  never point a package manager or an editor at one.
- Attacker infrastructure in prose is written defanged
  (`example[.]xyz`). Captured run records stay verbatim.

### Tests

```bash
for t in tests/test_*.py; do python "$t" || break; done     # or: pytest tests
```

There is no pytest dependency; each file is a script. All tests are offline
by default: provenance tests replay recorded RDAP and CT responses, and the
three that need real commit objects (`test_author_timezone_anomaly`,
`test_backdated_graft_evasion`, `test_asyncapi_patch_budget`) resolve them
from a local bare mirror, then a cache under `~/.cache/sift-fixtures`, then
GitHub. Set `SIFT_FIXTURE_MIRRORS` to a colon-separated list of mirror
directories if you keep them somewhere other than `../upstream-mirrors`.
`docs/testing.md` explains why mirrors come first.

Assertions that call a live model are opt-in behind `SIFT_FIXTURE_LIVE=1`.

### Docs

Plans go in `docs/plans/` and measurement write-ups in `docs/findings/`, both
named `YYYY-MM-DD-NNN-slug.md`. A finding states how to reproduce it in its
first lines.

## License

MIT. See [LICENSE](LICENSE).
