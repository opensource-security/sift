#!/usr/bin/env python3
"""Regression fixture: the default branch must be established, never invented.

`resolve_default_branch_ref` used to return whatever HEAD symbolically pointed
at, unvalidated. A bare repo's HEAD points at git's init default
(refs/heads/master) whether or not that branch was ever fetched, so the resolver
returned a branch name that does not exist in the repository.

That is not a cosmetic defect, because the value is not merely displayed. Author
temporal history is gated on `observed_ref == default_branch_ref` and returns an
empty block when they differ, so a phantom default silently decides whether the
model sees author baselines at all -- and it decides wrongly in both directions:

  a repo whose real default is `main`, analyzed at `refs/heads/main`, loses its
  temporal block entirely, because the phantom `refs/heads/master` mismatches;

  a commit on a genuinely non-default branch (`master` where the real default is
  `develop`) is handed a full-confidence block, because the phantom happens to
  match what was observed.

The case that deserved a caveat is trusted and the ordinary case is blanked. Both
failures are silent: no error, no caveat, just a thinner prompt.

These tests build small repos with `git`, so they are deterministic, offline, and
free. No fixture objects, no network, no API key.

Run:
    python tests/test_default_branch_resolution.py
    pytest tests/test_default_branch_resolution.py
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sift.runtime.case_builder import (  # noqa: E402
    branch_ref_exists,
    resolve_default_branch_ref,
)


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
        env={
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_AUTHOR_NAME": "Fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "Fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            "PATH": "/usr/bin:/bin:/usr/local/bin",
        },
    )
    return result.stdout.strip()


def make_source_repo(tmp: Path, branches: tuple[str, ...], default: str) -> Path:
    """A normal working repo with `branches`, checked out at `default`."""
    src = tmp / "source"
    src.mkdir()
    git(src, "init", "-q", "-b", default)
    (src / "README").write_text("x\n")
    git(src, "add", "README")
    git(src, "commit", "-qm", "initial")
    for branch in branches:
        if branch != default:
            git(src, "branch", branch)
    return src


def make_bare_mirror(tmp: Path, src: Path, remote: str, refspec: str) -> Path:
    """A bare repo populated by fetching a refspec, as fixture capture does.

    Crucially this never sets HEAD, so HEAD keeps git's init default.
    """
    bare = tmp / f"mirror-{remote}.git"
    git(tmp, "init", "-q", "--bare", str(bare))
    git(bare, "fetch", "-q", str(src), refspec)
    return bare


def test_phantom_head_is_not_returned() -> None:
    """The core defect: a bare mirror whose branches live under refs/remotes/
    must not yield the unfetched refs/heads/master that HEAD points at."""
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        src = make_source_repo(tmp, ("main", "develop"), "main")
        bare = make_bare_mirror(tmp, src, "gh", "+refs/heads/*:refs/remotes/gh/*")

        head_target = git(bare, "symbolic-ref", "HEAD")
        assert head_target == "refs/heads/master", (
            f"fixture premise broken: expected the bare init default, got {head_target!r}"
        )
        assert not branch_ref_exists(bare, "refs/heads/master"), (
            "fixture premise broken: refs/heads/master should not exist in this mirror"
        )

        resolved = resolve_default_branch_ref(bare)
        assert resolved != "refs/heads/master", (
            "REGRESSION: the resolver returned the phantom refs/heads/master that HEAD "
            "points at but which was never fetched. Downstream this silently keeps or "
            "drops author temporal evidence on the strength of a branch nobody has."
        )
        assert resolved == "", (
            f"with two candidate branches and no declared default, the honest answer is "
            f'"" (unknown); got {resolved!r}'
        )
    print("  ok  bare mirror: phantom refs/heads/master rejected, returns unknown")


def test_sole_branch_is_unambiguous() -> None:
    """One branch and no declared default is not a guess."""
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        src = make_source_repo(tmp, ("main",), "main")
        bare = tmp / "solo.git"
        git(tmp, "init", "-q", "--bare", str(bare))
        git(bare, "fetch", "-q", str(src), "+refs/heads/main:refs/heads/main")

        assert resolve_default_branch_ref(bare) == "refs/heads/main"
    print("  ok  sole branch resolves without a declared default")


def test_non_origin_remote_head_is_honored() -> None:
    """normalize_git_ref only rewrites `origin`; a mirror fetched under any other
    remote name must still have its declared HEAD honored."""
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        src = make_source_repo(tmp, ("main", "develop"), "main")
        bare = make_bare_mirror(tmp, src, "gh", "+refs/heads/*:refs/remotes/gh/*")
        git(bare, "symbolic-ref", "refs/remotes/gh/HEAD", "refs/remotes/gh/develop")

        resolved = resolve_default_branch_ref(bare)
        assert resolved == "refs/heads/develop", (
            f"a non-origin remote's declared HEAD should resolve to its branch; "
            f"got {resolved!r}"
        )
    print("  ok  non-origin remote HEAD resolves to refs/heads/develop")


def test_working_clone_still_resolves() -> None:
    """The ordinary path must be unaffected by the added validation."""
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        src = make_source_repo(tmp, ("main", "develop"), "main")
        assert resolve_default_branch_ref(src) == "refs/heads/main"
    print("  ok  working clone resolves its checked-out default")


def test_branch_ref_exists_accepts_both_layouts() -> None:
    """A branch counts as existing whether it sits under refs/heads/ or only
    under refs/remotes/<remote>/ -- the mirror layout must not read as absent."""
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        src = make_source_repo(tmp, ("main", "develop"), "main")
        bare = make_bare_mirror(tmp, src, "gh", "+refs/heads/*:refs/remotes/gh/*")

        assert branch_ref_exists(src, "refs/heads/develop"), "working clone layout"
        assert branch_ref_exists(bare, "refs/heads/develop"), (
            "REGRESSION: a branch present only under refs/remotes/gh/ now reads as "
            "absent; every mirror-based case would lose its default branch"
        )
        assert not branch_ref_exists(bare, "refs/heads/nonexistent")
        assert not branch_ref_exists(bare, "")
    print("  ok  branch existence recognized in both clone and mirror layouts")


def main() -> int:
    tests = [
        test_phantom_head_is_not_returned,
        test_sole_branch_is_unambiguous,
        test_non_origin_remote_head_is_honored,
        test_working_clone_still_resolves,
        test_branch_ref_exists_accepts_both_layouts,
    ]
    failed = 0
    print("default_branch_resolution: is the default branch established, or invented?\n")
    for test in tests:
        try:
            test()
        except AssertionError as exc:
            failed += 1
            print(f"  FAIL  {test.__name__}\n        {exc}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"  ERROR {test.__name__}: {type(exc).__name__}: {exc}")
    print()
    print("FAILED" if failed else "PASSED")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
