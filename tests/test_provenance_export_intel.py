#!/usr/bin/env python3
"""Shape test for the v2 intel exporter (the provenance -> runtime data seam).

Requires the `provenance` extra, like the other provenance suites. Fully
offline: the RDAP lookup and the band assessment are injected stubs built from
the real dataclasses, so this pins the snapshot *shape* and the wiring, not
registry behavior (test_domain_provenance owns that).

Run:
    python tests/test_provenance_export_intel.py
    pytest tests/test_provenance_export_intel.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sift.provenance.export_intel import SNAPSHOT_VERSION_V2, export_intel  # noqa: E402
from sift.provenance.verdict import (  # noqa: E402
    LIKELY,
    DomainRegistration,
    DomainVerdict,
    GapActivity,
    UseAnchor,
)
from sift.runtime.email_domain import build_email_domain_context  # noqa: E402

NOW = datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)
HELD = datetime(2026, 6, 1, tzinfo=timezone.utc)
USED = datetime(2021, 3, 1, tzinfo=timezone.utc)

ANCHOR = UseAnchor(domain="resurrected-fixture.net", first_seen=USED,
                   kind="commit_author_date", strength="weak", evidence="repo history")


def _stub_lookup(domain, *, client=None):
    return DomainRegistration(domain=domain, registered_at=HELD, expires_at=None,
                              statuses=("active",), rdap_server="stub", source="fixture")


def _stub_assess(domain, *, anchor, now, repo_path=None, author_email="", client=None):
    gap = GapActivity(gap_start=USED, gap_end=HELD, commits_in_gap=0,
                      same_signing_key=False, scope="repo_local", verdict="dormant")
    return DomainVerdict(domain=domain, band=LIKELY, confidence="medium", role="supporting",
                         held_since=HELD, used_since=anchor, gap_activity=gap)


def test_export_shape_and_reader_roundtrip() -> None:
    snapshot = export_intel(
        ["dev@resurrected-fixture.net", "friend@gmail.com", "bot@users.noreply.github.com"],
        now=NOW,
        anchors={"resurrected-fixture.net": ANCHOR},
        with_dns=False,
        lookup_fn=_stub_lookup,
        assess_fn=_stub_assess,
    )
    assert snapshot["snapshot_version"] == SNAPSHOT_VERSION_V2
    assert snapshot["writer"] == "provenance"
    entry = snapshot["domains"]["resurrected-fixture.net"]
    assert entry["registrable_domain"] == "resurrected-fixture.net"
    assert entry["rdap"]["registered"] is True
    assert entry["rdap"]["registered_at"] == "2026-06-01T00:00:00Z"
    assert entry["provenance"]["band"] == "LIKELY"
    assert entry["provenance"]["used_since"] == "2021-03-01T00:00:00Z"
    assert entry["provenance"]["gap_verdict"] == "dormant"
    # constant-classified domains carry taxonomy only, never lookups
    assert snapshot["domains"]["gmail.com"]["classification"] == "freemail"
    assert snapshot["domains"]["users.noreply.github.com"]["classification"] == "github_infra"
    assert snapshot["domains"]["gmail.com"]["rdap"] is None

    # the stdlib reader consumes the exporter's output directly
    commit = {"author_name": "Old Maintainer", "author_email": "dev@resurrected-fixture.net",
              "committer_name": "Old Maintainer", "committer_email": "dev@resurrected-fixture.net"}
    history = {"anchor_timestamp_utc": "2026-07-01T00:00:00Z",
               "author_first_seen_same_email_at": "2021-03-01T00:00:00Z"}
    author = build_email_domain_context(commit, history, snapshot, "realtime")["author"]
    assert author["provenance_band"] == "LIKELY"
    assert author["domain_registered_after_author_first_seen"] is True


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
