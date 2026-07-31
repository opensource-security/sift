#!/usr/bin/env python3
"""The path from `case_builder` history to a verdict, which fixtures skipped.

`test_domain_provenance.py` builds `UseAnchor`s by hand and calls `assess_domain`
directly. That pins the band ladder but skips the wiring that actually runs in a
PR: repo history -> `anchors_from_identity_history` -> `assess_identity` ->
`gap_activity` -> band. Three defects lived in that gap simultaneously while every
fixture passed, all found by pointing the pipeline at a real repository (endee) with
a synthetic committer.

Each test here pins one of them. They are deterministic, offline, and free -- no
RDAP or CT call is made; the anchor and gap layers are exercised directly.

Run:
    python tests/test_provenance_pipeline_anchors.py
    pytest tests/test_provenance_pipeline_anchors.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

try:
    import httpx  # noqa: F401
    import idna  # noqa: F401
    import tldextract  # noqa: F401
    from dateutil import parser as _date_parser  # noqa: F401

    _HAVE_EXTRA = True
except ImportError:  # pragma: no cover - base install
    _HAVE_EXTRA = False


def _utc(text: str) -> datetime:
    return datetime.fromisoformat(text).replace(tzinfo=timezone.utc)


def _commit(repo: Path, *, email: str, when: str, message: str) -> None:
    (repo / "file.txt").write_text(message, encoding="utf-8")
    env = dict(
        os.environ,
        GIT_AUTHOR_NAME="Contributor",
        GIT_AUTHOR_EMAIL=email,
        GIT_AUTHOR_DATE=when,
        GIT_COMMITTER_NAME="Contributor",
        GIT_COMMITTER_EMAIL=email,
        GIT_COMMITTER_DATE=when,
    )
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", message],
        cwd=repo,
        check=True,
        capture_output=True,
        env=env,
    )


def test_single_address_contributor_still_gets_an_anchor() -> None:
    """`author_email_variants` holds only the *alternate* addresses.

    A contributor who has always used one address has an empty variants list, and
    their earliest date lives in the flat `author_email_first_seen_at` field. Reading
    only the variants left that contributor -- the common case, and precisely the one
    this check exists for -- with no anchor, hence a permanent UNKNOWN regardless of
    what RDAP returned.
    """
    from sift.provenance.identity import anchors_from_identity_history

    history = {
        "current_author": {
            "email": "dev@example-corp.net",
            "email_domain": "example-corp.net",
        },
        "author_email_first_seen_at": "2023-03-11T10:00:00+00:00",
        "author_email_variants": [],
    }

    anchors = anchors_from_identity_history(history)
    assert "example-corp.net" in anchors, (
        "a contributor with one consistent email must still yield an anchor; "
        f"got {sorted(anchors)}"
    )
    anchor = anchors["example-corp.net"]
    assert anchor.first_seen == _utc("2023-03-11T10:00:00")
    assert anchor.strength == "weak", f"author dates are forgeable; got {anchor.strength}"
    print("  ok  single-address contributor anchors off author_email_first_seen_at")


def test_anchor_commit_does_not_count_as_activity_inside_its_own_gap() -> None:
    """The gap starts *at* the anchor, and `git log --since` is inclusive.

    So the anchoring commit fell inside the window it defines, every repo-local
    anchor read as CONTINUOUS, and a takeover was reported as counter-evidence --
    the worst direction for this check to fail. Dormancy was unreachable by this
    path.
    """
    from sift.provenance.identity import gap_activity

    email = "dev@example-corp.net"
    anchor_at = _utc("2023-03-11T10:00:00")
    registered_at = _utc("2024-03-08T00:00:00")

    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp) / "takeover"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True, capture_output=True)
        # The dormant shape: the anchor commit, silence across the gap, then a
        # commit after the domain changed hands.
        _commit(repo, email=email, when="2023-03-11T10:00:00+0000", message="anchor")
        _commit(repo, email=email, when="2026-07-31T10:00:00+0000", message="resumed")

        result = gap_activity(
            repo, author_email=email, gap_start=anchor_at, gap_end=registered_at
        )
        assert result is not None
        assert result.commits_in_gap == 0, (
            "the anchoring commit defines the gap start and must not be counted "
            f"as activity within it; got {result.commits_in_gap}"
        )
        assert result.verdict == "dormant", (
            f"expected the takeover shape (dormant), got {result.verdict}"
        )

        # A genuine in-gap commit must still register as continuous.
        _commit(repo, email=email, when="2023-09-01T10:00:00+0000", message="in gap")
        result = gap_activity(
            repo, author_email=email, gap_start=anchor_at, gap_end=registered_at
        )
        assert result is not None
        assert result.commits_in_gap == 1, f"got {result.commits_in_gap}"
        assert result.verdict == "continuous", f"got {result.verdict}"

    print("  ok  anchor commit excluded from its own gap; dormant reachable again")


def test_anchor_seeded_domain_keeps_its_email() -> None:
    """`assess_identity` seeds candidate domains from anchors with an empty email.

    `setdefault` then could not fill it in from `emails`, so `author_email` stayed
    empty, and `gap_activity` -- which needs an address for `git log --author` --
    was skipped entirely. The dormant-vs-continuous discriminator silently did no
    work whenever an anchor existed, which is whenever it mattered.
    """
    import sift.provenance as provenance
    from sift.provenance.verdict import DomainRegistration

    seen: dict[str, str] = {}

    def fake_lookup(domain, **_kwargs):
        return DomainRegistration(
            domain=domain,
            registered_at=_utc("2024-03-08T00:00:00"),
            source="fixture",
        )

    def fake_gap_activity(_repo_path, *, author_email, gap_start, gap_end, **_kwargs):
        seen["author_email"] = author_email
        return None

    real_lookup = provenance.rdap.lookup
    real_gap = provenance.identity.gap_activity
    real_corroborate = provenance.ct.corroborate
    provenance.rdap.lookup = fake_lookup
    provenance.identity.gap_activity = fake_gap_activity
    provenance.ct.corroborate = lambda *a, **k: ()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            provenance.assess_identity(
                "",
                now=_utc("2026-07-31T00:00:00"),
                emails=["dev@example-corp.net"],
                identity_history={
                    "current_author": {"email": "dev@example-corp.net"},
                    "author_email_first_seen_at": "2023-03-11T10:00:00+00:00",
                    "author_email_variants": [],
                },
                repo_path=Path(tmp),
                with_corroboration=False,
            )
    finally:
        provenance.rdap.lookup = real_lookup
        provenance.identity.gap_activity = real_gap
        provenance.ct.corroborate = real_corroborate

    assert seen.get("author_email") == "dev@example-corp.net", (
        "gap_activity must receive the address the domain was seen at; got "
        f"{seen.get('author_email')!r} (empty means the discriminator never ran)"
    )
    print("  ok  anchor-seeded domain retains its email for the gap-activity query")


def main() -> int:
    if not _HAVE_EXTRA:
        print("skip: needs the provenance extra (uv pip install -e '.[provenance]')")
        return 0

    tests = [
        test_single_address_contributor_still_gets_an_anchor,
        test_anchor_commit_does_not_count_as_activity_inside_its_own_gap,
        test_anchor_seeded_domain_keeps_its_email,
    ]
    failed = 0
    print("provenance pipeline wiring: history -> anchor -> gap -> verdict\n")
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
