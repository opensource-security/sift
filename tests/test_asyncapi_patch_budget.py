#!/usr/bin/env python3
"""Regression fixture: a 1-line payload buried in ~950KB of lockfile churn.

The 2026-07-14 AsyncAPI compromise (`asyncapi/generator` 3eab3ec9) is the only
known real commit that poses the needle-in-noise problem: an obfuscated payload
occupying ONE modified line, padded with 880 leading spaces, inside a
30,597-line diff that is ~97% `package-lock.json` churn.

Two levels:

  Level 1 (default) -- deterministic, offline after a ~1s shallow fetch, no API
  key, no cost. Pins how `case_builder.load_patch` truncation interacts with
  this commit. This is the regression guard.

  Level 2 (opt-in) -- set SIFT_FIXTURE_LIVE=1 and ANTHROPIC_API_KEY to actually
  run the analysis and assert the payload is surfaced. Costs money.

Run:
    python tests/test_asyncapi_patch_budget.py       # level 1
    pytest tests/test_asyncapi_patch_budget.py       # same, via pytest
    SIFT_FIXTURE_LIVE=1 python tests/test_asyncapi_patch_budget.py

The headline finding this pins: the payload survives truncation ONLY because
`validator.js` sorts first alphabetically. `git show` emits files in path order,
so what reaches the model is decided by sort order rather than by relevance --
two of the three infected files and the whole dropper fall past the cut. This
fixture fails loudly if that fragile property changes.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).parent))

from fixture_repos import ensure_commits  # noqa: E402

from sift.runtime.case_builder import load_patch  # noqa: E402

FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "asyncapi_lockfile_noise_2026.json").read_text()
)
DEFAULT_BUDGET = FIXTURE["pinned_behavior"]["default_max_patch_chars"]


def ensure_commit() -> Path:
    """Locate the fixture commit and its parent -- local mirror first.

    This used to shallow-fetch straight from GitHub. Recovering the 2026 incident
    corpus showed why that is not safe to rely on: malicious commits get reaped
    after disclosure, sometimes network-wide while the repository stays live, and
    the fixture only finds out when it starts erroring. See fixture_repos.py.
    """
    return ensure_commits(FIXTURE["repo"], [FIXTURE["sha"], FIXTURE["parent_sha"]])


def file_offsets(patch: str) -> dict[str, int]:
    return {m.group(1): m.start()
            for m in re.finditer(r"^diff --git a/(\S+)", patch, re.M)}


def test_payload_survives_default_budget() -> None:
    """At the default budget the payload IS visible -- but only just, and only
    because of alphabetical luck. Pins both halves of that."""
    repo = ensure_commit()
    shape = FIXTURE["commit_shape"]
    full = load_patch(repo, FIXTURE["sha"], max_patch_chars=10**9)
    patch = full["patch"]
    offsets = file_offsets(patch)

    assert len(offsets) == shape["files_changed"], \
        f"expected {shape['files_changed']} files, saw {len(offsets)}"

    first_payload = shape["payload_files"][0]
    assert offsets[first_payload] < DEFAULT_BUDGET, (
        f"REGRESSION: {first_payload} now starts at {offsets[first_payload]}, "
        f"past the {DEFAULT_BUDGET}-char budget. The payload is no longer "
        f"visible to the model at default settings."
    )

    truncated = load_patch(repo, FIXTURE["sha"], max_patch_chars=DEFAULT_BUDGET)
    assert truncated["patch_truncated"] is True
    assert "_0x" in truncated["patch"], \
        "REGRESSION: obfuscated payload no longer reaches the model at default budget"

    # The fragile half: most of the attack is NOT visible.
    at_default = FIXTURE["pinned_behavior"]["at_default_budget"]
    visible = [f for f in shape["payload_files"] if offsets[f] < DEFAULT_BUDGET]
    assert len(visible) == at_default["payload_copies_visible"], (
        f"payload copies visible changed: expected "
        f"{at_default['payload_copies_visible']}, got {len(visible)}"
    )
    dropper_visible = offsets[shape["dropper_file"]] < DEFAULT_BUDGET
    assert dropper_visible == at_default["dropper_visible"], \
        "dropper visibility changed"

    print(f"  ok  payload visible at default budget ({len(visible)}/"
          f"{len(shape['payload_files'])} infected files, "
          f"dropper_visible={dropper_visible}, patch is {len(patch):,} chars)")


def test_truncation_is_sort_order_dependent() -> None:
    """The load-bearing risk: `git show` emits files in path order, so a payload
    in a late-sorting file is invisible at any sane budget. Documents the
    counterfactual so nobody mistakes the pass above for robustness."""
    repo = ensure_commit()
    full = load_patch(repo, FIXTURE["sha"], max_patch_chars=10**9)
    offsets = file_offsets(full["patch"])
    total = len(full["patch"])

    late = "packages/helpers/src/utils.js"
    depth = 100.0 * offsets[late] / total
    assert depth > 95.0, (
        f"{late} sits at {depth:.1f}% depth; the sort-order hazard this fixture "
        f"documents may no longer hold"
    )
    budget_needed = offsets[late]
    assert budget_needed > 50 * DEFAULT_BUDGET, (
        "reaching the last payload copy should require an implausible budget"
    )
    print(f"  ok  identical payload in {late} sits at {depth:.1f}% depth "
          f"({budget_needed:,} chars needed vs {DEFAULT_BUDGET:,} default "
          f"= {budget_needed / DEFAULT_BUDGET:.0f}x)")


def test_live_analysis_surfaces_payload() -> None:
    """Level 2, opt-in: run the real pipeline and assert it flags the commit."""
    if os.environ.get("SIFT_FIXTURE_LIVE") != "1":
        print("  skip  live analysis (set SIFT_FIXTURE_LIVE=1 and ANTHROPIC_API_KEY)")
        return
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise RuntimeError("SIFT_FIXTURE_LIVE=1 requires ANTHROPIC_API_KEY")

    from sift.runtime.analysis import analyze_commit

    repo = ensure_commit()
    result = analyze_commit(repo_path=repo, sha=FIXTURE["sha"])
    findings = getattr(result, "findings", None) or []
    assert findings, (
        "REGRESSION: no findings surfaced for a commit that injects an "
        "obfuscated payload into three source files"
    )
    print(f"  ok  live analysis surfaced {len(findings)} finding(s)")


def main() -> int:
    tests = [
        test_payload_survives_default_budget,
        test_truncation_is_sort_order_dependent,
        test_live_analysis_surfaces_payload,
    ]
    failed = 0
    print(f"{FIXTURE['fixture']}: {FIXTURE['question']}\n")
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"  FAIL  {t.__name__}\n        {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  ERROR {t.__name__}: {type(e).__name__}: {e}")
    print()
    print("FAILED" if failed else "PASSED")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
