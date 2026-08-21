#!/usr/bin/env python3
"""Locate the commit objects a regression fixture pins, mirror first.

Fixtures used to shallow-fetch straight from GitHub on first run. That is a
timebomb, and we watched it go off: recovering the 2026 incident corpus found
`icflorescu/mantine-datatable@f72462d9` -- a commit with a full 40-char SHA
published in vendor writeups, in a repository that is still live -- purged
network-wide. `git upload-pack` answers "not our ref", the REST API answers 422,
and all ten post-incident forks answer the same. Nothing warns you first; the
fixture simply starts erroring one day, and the regression it guarded silently
stops being guarded.

Malicious commits are the objects most likely to be reaped, because cleanup is
exactly what maintainers and GitHub do after a disclosure. Several commits in
this corpus are already unreachable from any branch and survive only because
GitHub still serves unreachable objects by full SHA -- a property we do not
control and should not depend on.

So resolution order is:

  1. a local bare mirror, if it already has every required object
  2. the fixture cache under ~/.cache/sift-fixtures
  3. upstream GitHub (populating the cache)

Mirrors are searched at $SIFT_FIXTURE_MIRRORS (colon-separated) and then at
`../upstream-mirrors` relative to the repo root. They are read, never written:
the mirror is somebody's durable capture, not this test suite's scratch space.

Populate one with:

    git init --bare upstream-mirrors/keyv.git
    git -C upstream-mirrors/keyv.git remote add origin https://github.com/jaredwray/keyv
    git -C upstream-mirrors/keyv.git fetch origin <full-sha>
    git -C upstream-mirrors/keyv.git update-ref refs/mirror/<full-sha> <full-sha>

That last `update-ref` is load-bearing for unreachable objects -- without a ref
pinning it, the next `git gc` in that mirror reaps the very commit you captured.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

DEFAULT_CACHE = Path(
    os.environ.get("SIFT_FIXTURE_CACHE", str(Path.home() / ".cache" / "sift-fixtures"))
)


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )


def _has_all(repo: Path, shas: list[str]) -> bool:
    if not repo.exists():
        return False
    return all(_git(repo, "cat-file", "-e", f"{sha}^{{commit}}").returncode == 0 for sha in shas)


def mirror_candidates(repo_slug: str) -> list[Path]:
    """Bare-mirror paths to try for `owner/name`, most specific first."""
    name = repo_slug.split("/")[-1]
    roots: list[Path] = []
    for entry in (os.environ.get("SIFT_FIXTURE_MIRRORS") or "").split(":"):
        if entry.strip():
            roots.append(Path(entry.strip()).expanduser())
    roots.append(ROOT.parent / "upstream-mirrors")
    out: list[Path] = []
    for root in roots:
        out.append(root / f"{name}.git")
        out.append(root / f"{repo_slug.replace('/', '__')}.git")
    return out


def ensure_commits(repo_slug: str, shas: list[str], *, depth: int = 2) -> Path:
    """Return a bare repo containing every sha in `shas`.

    `depth` applies only to the upstream fallback; a mirror is used as-is.
    Raises RuntimeError if the objects cannot be obtained anywhere, with the
    reason each source failed -- for a purged object that message is the
    finding, so it should not be swallowed.
    """
    wanted = [s for s in shas if s]
    if not wanted:
        raise ValueError("ensure_commits requires at least one sha")

    for candidate in mirror_candidates(repo_slug):
        if _has_all(candidate, wanted):
            return candidate

    cache = DEFAULT_CACHE / (repo_slug.replace("/", "__") + ".git")
    if _has_all(cache, wanted):
        return cache

    cache.parent.mkdir(parents=True, exist_ok=True)
    if not cache.exists():
        subprocess.run(["git", "init", "-q", "--bare", str(cache)], check=True)

    failures: list[str] = []
    for sha in wanted:
        if _git(cache, "cat-file", "-e", f"{sha}^{{commit}}").returncode == 0:
            continue
        fetched = _git(cache, "fetch", "-q", "--depth", str(depth),
                       f"https://github.com/{repo_slug}", sha)
        if fetched.returncode != 0:
            failures.append(f"{sha[:12]}: {fetched.stderr.strip().splitlines()[-1:] or ['?']}")
            continue
        # Unreachable objects need a ref or the next gc reaps them.
        _git(cache, "update-ref", f"refs/fixture/{sha}", sha)

    if failures:
        raise RuntimeError(
            f"could not obtain {len(failures)} object(s) for {repo_slug}; upstream may have "
            f"purged them (this is a finding, not a flake) -- capture them into a mirror and "
            f"set SIFT_FIXTURE_MIRRORS. Failures: {'; '.join(failures)}"
        )
    return cache


def describe_source(repo: Path) -> str:
    kind = "mirror" if repo.parent.name == "upstream-mirrors" else "cache"
    return f"{kind}:{repo}"


if __name__ == "__main__":
    slug = sys.argv[1] if len(sys.argv) > 1 else "jaredwray/keyv"
    print(f"mirror candidates for {slug}:")
    for c in mirror_candidates(slug):
        print(f"  {'HIT ' if c.exists() else '    '}{c}")
