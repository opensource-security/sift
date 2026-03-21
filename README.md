# sift

LLM-assisted commit triage for supply-chain security.

Sift analyzes Git commits and pull requests using Claude to surface security-relevant findings for maintainer review. It runs as a GitHub Action or via CLI.

## Context

Sift is the tool layer extracted from the [stars](https://github.com/opensource-security/stars) monitoring system. For background on the project — what it is, why it's built the way it is, how to access the dashboard and feeds — see the **[handbook](https://github.com/opensource-security/handbook)**.

Key handbook docs:

- [What the commit analysis flow looks like](https://github.com/opensource-security/handbook/blob/main/commit-analysis-flow.md)
- [Why we are not trying to build a perfect detector](https://github.com/opensource-security/handbook/blob/main/perfect-oracle-framing.md)

## Usage

```bash
uv pip install -e .

# Analyze a single commit
sift-commit --repo-path /path/to/repo --sha <commit-sha>

# Analyze all commits in a PR
sift-pr --repo-path /path/to/repo --pr-number 42
```

## GitHub Action

See `action/action.yml` and the example workflow in `action/workflow_examples/pr_review.yml`.

The action uses `pull_request_target` so it runs on trusted base-branch code while analyzing PR commits read-only — PR code is never checked out or executed.

## Development

```bash
uv pip install -e .
```

No test suite exists yet. See `CLAUDE.md` for architecture guidance.
