#!/usr/bin/env python3
"""Regression: gap-activity evidence must never come from attacker-pushable refs.

Pins the fix for docs/domain-provenance-plan.md open question 1 (confirmed in
production on the endee mirror): `gap_activity` used `git log --all`, so a
contributor who could push any branch could manufacture the in-gap commits
that flip their own verdict from `dormant` (supporting a takeover) to
`continuous` (counter-evidence). Under `pull_request_target` the PR head is
always such a ref.

The temp repo reproduces that exact shape: a maintainer with commits before
and after the ownership gap on the default branch, and a same-author commit
*inside* the gap that exists only on a side branch. Requires the `provenance`
extra (imports sift.provenance). Fully offline.

Run:
    python tests/test_gap_activity_ref_scope.py
    pytest tests/test_gap_activity_ref_scope.py
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sift.provenance.identity import _trusted_revisions, gap_activity  # noqa: E402
from sift.provenance.verdict import CONTINUOUS, DORMANT  # noqa: E402

AUTHOR = ("Old Maintainer", "dev@resurrected-fixture.net")
GAP_START = datetime(2021, 6, 1, tzinfo=timezone.utc)   # anchor: first use of the domain
GAP_END = datetime(2026, 6, 1, tzinfo=timezone.utc)     # current registration date


def _git(repo: Path, *args: str, date: str | None = None) -> None:
    cmd = ["git", "-C", str(repo), "-c", f"user.name={AUTHOR[0]}", "-c", f"user.email={AUTHOR[1]}"]
    env = None
    if date:
        import os
        env = dict(os.environ, GIT_AUTHOR_DATE=date, GIT_COMMITTER_DATE=date)
    subprocess.run(cmd + list(args), check=True, capture_output=True, env=env)


def _build_repo(tmp: str) -> Path:
    repo = Path(tmp) / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "a.txt").write_text("pre-gap\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "pre-gap work", date="2021-05-01T12:00:00Z")
    # The attacker-pushable ref: a same-author commit INSIDE the gap, on a side
    # branch only (the endee shape: an unrelated branch the PR does not touch).
    _git(repo, "checkout", "-q", "-b", "sift-test-continuous")
    (repo / "b.txt").write_text("in-gap\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "in-gap commit on side branch", date="2023-05-01T12:00:00Z")
    _git(repo, "checkout", "-q", "main")
    (repo / "c.txt").write_text("post-gap\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "post-gap work", date="2026-07-01T12:00:00Z")
    return repo


def _verdict(repo: Path, revisions: list[str] | None) -> str:
    gap = gap_activity(
        repo,
        author_email=AUTHOR[1],
        gap_start=GAP_START,
        gap_end=GAP_END,
        history_revisions=revisions,
    )
    assert gap is not None
    return gap.verdict


def test_side_branch_cannot_suppress_discontinuity() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo = _build_repo(tmp)
        # Default scope resolves to the default branch: the side-branch commit is
        # invisible and the dormant-then-resumed shape survives.
        assert _verdict(repo, None) == DORMANT
        assert _verdict(repo, ["refs/heads/main"]) == DORMANT
        # The pre-fix behavior, reproduced explicitly: scoped to the attacker's
        # ref, the same repo reads CONTINUOUS. This is what --all allowed.
        assert _verdict(repo, ["refs/heads/sift-test-continuous"]) == CONTINUOUS
    print("  ok  side-branch in-gap commit no longer flips dormant -> continuous")


def test_trusted_revisions_resolve_head_without_origin() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo = _build_repo(tmp)
        revs = _trusted_revisions(repo)
        assert revs == ["refs/heads/main"], revs
    print("  ok  trusted scope falls back to HEAD's branch when origin/HEAD is absent")


def main() -> int:
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}: {exc}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
