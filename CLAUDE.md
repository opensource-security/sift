# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Sift is an LLM-assisted commit triage system for supply-chain security. It analyzes Git commits and pull requests using Claude to surface security-relevant findings for maintainer review. It runs as a GitHub Action or via CLI.

## Build & Development

Uses `uv` with `hatchling` backend. No external runtime dependencies (stdlib only).

```bash
uv pip install -e .          # install in dev mode
sift-commit                  # analyze a single commit
sift-pr                      # analyze all commits in a PR
```

No linting configuration exists yet. There is no general test suite — `tests/`
holds regression fixtures pinned to specific real incidents, runnable directly
(`python tests/<file>.py`) or under pytest, with no pytest dependency required.
Level-1 assertions are deterministic and free; level-2 assertions that call a
live model are opt-in behind `SIFT_FIXTURE_LIVE=1`.

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
- `sift/runtime/email_domain.py` — offline email-domain enrichment (forged-bot domain mismatch, domain age, expired-domain resurrection); consumes a DNS/RDAP snapshot passed to the case builders as `email_domain_intel`, never does live lookups
- `sift/runtime/file_ownership.py` — git log analysis for ownership concentration metrics

### CLI Entry Points (defined in pyproject.toml)

- `sift-commit` → `sift.cli.analyze_commit:main`
- `sift-pr` → `sift.cli.analyze_pr:main` (supports GitHub event.json parsing)

### GitHub Action

`action/action.yml` is a composite action. Key design decision: uses `pull_request_target` trigger so the action runs on the base branch (trusted code) while analyzing untrusted PR commits read-only — PR code is never checked out or executed.

### Environment Variables

- `ANTHROPIC_API_KEY` — required for the anthropic provider
- `GITHUB_TOKEN` — for PR social context fetching
- `GITHUB_EVENT_PATH` / `GITHUB_WORKSPACE` — set automatically in GitHub Actions
