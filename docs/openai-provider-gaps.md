# OpenAI provider — known gaps and follow-ups

Status as of the change that added the `openai` provider (sift 0.1.2). These
are the items a follow-up needs to resolve before this ships as an installable
release, plus the deliberate scope boundaries.

## BLOCKING: store.py / release_case.py seam

sift HEAD (`2f02ead`) deleted `sift/runtime/store.py` and
`sift/runtime/release_case.py`. This change did **not** restore them.

- The `stars` repo still imports both modules (e.g. `shadow_pr_run.py`,
  `shadow_commit_run.py`, `shadow_release_run.py`).
- The `stars` venv currently runs a pre-deletion sift **0.1.1** snapshot, where
  both files still exist under
  `.../site-packages/sift/runtime/{store,release_case}.py`. So stars is
  **currently unaffected**.
- The moment sift **0.1.2** (or any post-deletion build) is installed into an
  environment stars depends on, stars breaks at import time.

This work only modified the sift working tree — no `pip install` / `uv pip
install` was run into the stars venv, and no wheel was built. Before releasing
0.1.2 as installable, resolve the seam one of two ways:

1. Restore `store.py` and `release_case.py` in sift, or
2. Coordinate with Evan to vendor them into stars first.

## Scope boundaries (intentional, not gaps to fix silently)

- **Chat Completions only.** No Responses-API migration.
- **Text completion only.** The Anthropic tool loop has no OpenAI counterpart
  in this pass. `openai_complete()` takes no tools/tool_runner, and the OpenAI
  path never receives `anthropic_tools` / `anthropic_tool_runner` (those are
  only wired for `runner == "anthropic"`).
- **No prompt caching for OpenAI.** `evidence_block` (the cached prefix) is only
  computed for the anthropic runner, so OpenAI prompts carry full evidence
  inline. Correct, but the OpenAI path pays full input tokens on every call.
- **No OpenAI profile.** Provider choice is an advanced override only; the
  shipped profiles remain anthropic-backed.
- **No new third-party dependencies.** Still stdlib-only (`urllib`).

## Smaller caveats

- **Model access.** The project key currently only has `gpt-5.4`; smaller tiers
  return 403 `model_not_found` until enabled in OpenAI project settings.
  `gpt-5.4` is the default.
- **`effort=max` + openai.** `--openai-effort` is free-form (valid:
  `minimal`/`low`/`medium`/`high`, empty to omit). The GitHub Action's `effort`
  default of `high` is valid, but passing `effort=max` with `provider=openai`
  makes OpenAI reject `reasoning_effort=max` at request time (HTTP 400,
  surfaced as a runner error — not a crash).
- **Auth-error fast-abort is anthropic-only.** `_abort_if_auth_error()` in
  `analysis.py` matches Anthropic's error string. An OpenAI 401 does not
  hard-abort the run; it degrades to an `unknown` classification via the
  normal runner-error path. Generalizing this was left out of scope.
