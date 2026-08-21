#!/usr/bin/env python3
"""Regression fixtures for domain-provenance ownership-discontinuity detection.

Pinned to two real maintainer-domain takeovers:

  npm `node-ipc` (2026) -- maintainer account `atiertant`'s recovery email was on
  `atlantis-software.net`, which lapsed 2025-01-10 and was re-registered
  2026-05-07; malicious versions were published 2026-05-14. The recorded RDAP
  response in this fixture set independently confirms the re-registration date
  from Verisign: `registration` = 2026-05-07T11:49:33Z.

  PyPI `ctx` (2022) -- maintainer's `figlief.com` lapsed, was re-registered
  2022-05-14T18:40:05Z, and the PyPI account was reset twelve minutes later.
  Live RDAP no longer shows that event: the domain changed hands *again* and now
  reads `registration` = 2023-01-01. The recorded response is therefore used to
  exercise the same detector against the later re-registration, with the 2022
  event asserted separately from a reconstructed record.

Two levels:

  Level 1 (default) -- deterministic, offline, free. Replays recorded RDAP/CT/
  Wayback responses from tests/fixtures/provenance/ against a pinned `now`. This
  is the regression guard.

  Level 2 (opt-in) -- SIFT_FIXTURE_LIVE=1 re-fetches live and records on miss.
  Costs no money but hits third-party registries; expect drift as domains change
  hands again.

Run:
    python tests/test_domain_provenance.py
    pytest tests/test_domain_provenance.py
    SIFT_FIXTURE_LIVE=1 python tests/test_domain_provenance.py

What these pin, beyond "it works": corroboration must never gate a band. Both
incident domains have zero Certificate Transparency history and no archived
captures after their re-registration, because abandoned single-maintainer domains
never held a TLS certificate. A detector that required corroboration to reach
CRITICAL could not flag either real incident.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Replay is opt-in now that production defaults to live network access. Without
# this, running the fixtures offline would silently start making real RDAP/CT
# requests instead of failing loudly on a missing recording.
if not os.environ.get("SIFT_FIXTURE_LIVE"):
    os.environ["SIFT_FIXTURE_REPLAY"] = "1"


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


# Incident record. Dates from the registry (RDAP) and the public incident
# writeups; see module docstring.
NODE_IPC = {
    "domain": "atlantis-software.net",
    "expired_at": _utc("2025-01-10T00:00:00"),
    "reregistered_at": _utc("2026-05-07T11:49:33"),
    "malicious_publish_at": _utc("2026-05-14T14:25:00"),
    # The maintainer had been using the domain for years before the lapse.
    "identity_used_since": _utc("2013-06-01T00:00:00"),
}

CTX = {
    "domain": "figlief.com",
    "reregistered_at_2022": _utc("2022-05-14T18:40:05"),
    "pypi_reset_at": _utc("2022-05-14T18:52:40"),
    "identity_used_since": _utc("2015-01-01T00:00:00"),
}


def main() -> int:
    if not _HAVE_EXTRA:
        print("  skip  domain provenance (install with: uv pip install -e '.[provenance]')")
        print("PASSED")
        return 0

    tests = [
        test_node_ipc_registration_date_matches_incident_record,
        test_node_ipc_dormant_identity_lands_critical,
        test_critical_does_not_require_corroboration,
        test_ctx_domain_changed_hands_again,
        test_ctx_2022_event_reconstructed,
        test_stable_domain_is_clean_counter_evidence,
        test_continuous_activity_downgrades_to_note,
        test_weak_anchor_cannot_reach_critical,
        test_no_rdap_service_is_unknown_not_clean,
        test_failed_lookup_is_unknown_not_clean,
        test_missing_anchor_is_unknown_not_clean,
        test_declined_and_rejected_inputs_make_no_requests,
        test_gap_activity_on_a_real_repo,
        test_prospective_notes_are_separate_from_band,
    ]
    failed = 0
    print("domain-provenance: does a contributor's email domain show an ownership gap?\n")
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


# -- helpers -------------------------------------------------------------------


def _anchor(domain: str, when: datetime, *, kind="gpg_uid", strength="strong"):
    from sift.provenance.verdict import UseAnchor

    return UseAnchor(
        domain=domain, first_seen=when, kind=kind, strength=strength, evidence="fixture"
    )


def _gap(start: datetime, end: datetime, verdict: str, *, commits=0, same_key=False):
    from sift.provenance.verdict import GapActivity

    return GapActivity(
        gap_start=start,
        gap_end=end,
        commits_in_gap=commits,
        same_signing_key=same_key,
        scope="repo_local",
        verdict=verdict,
    )


def _lookup(domain: str):
    """Recorded RDAP lookup through the fixture transport."""
    from sift.provenance import rdap
    from sift.provenance.http_cache import RecordingTransport, build_client

    transport = RecordingTransport()
    with build_client(transport=transport) as client:
        return rdap.lookup(domain, client=client, sleep=lambda _s: None)


# -- node-ipc ------------------------------------------------------------------


def test_node_ipc_registration_date_matches_incident_record() -> None:
    """The registry itself confirms the re-registration date from the writeups."""
    registration = _lookup(NODE_IPC["domain"])
    assert registration.ok, f"lookup failed: {registration.error}"
    assert registration.registered_at == NODE_IPC["reregistered_at"], (
        f"RDAP registration date {registration.registered_at} no longer matches the "
        f"incident record {NODE_IPC['reregistered_at']}; the domain may have changed "
        f"hands again"
    )
    assert registration.registered_at > NODE_IPC["expired_at"], (
        "re-registration must postdate the lapse"
    )
    print(
        f"  ok  {NODE_IPC['domain']} registration {registration.registered_at.date()} "
        f"matches incident record (lapsed {NODE_IPC['expired_at'].date()})"
    )


def test_node_ipc_dormant_identity_lands_critical() -> None:
    """The real shape: long-standing use, dormant across the gap, resumed after."""
    from sift.provenance.verdict import CRITICAL, ROLE_SUPPORTING, assess_domain

    registration = _lookup(NODE_IPC["domain"])
    anchor = _anchor(NODE_IPC["domain"], NODE_IPC["identity_used_since"])
    verdict = assess_domain(
        NODE_IPC["domain"],
        now=NODE_IPC["malicious_publish_at"],
        registration=registration,
        anchor=anchor,
        gap_activity=_gap(
            NODE_IPC["identity_used_since"], NODE_IPC["reregistered_at"], "dormant"
        ),
        corroboration=(),
    )
    assert verdict.band == CRITICAL, f"expected CRITICAL, got {verdict.band}"
    assert verdict.role == ROLE_SUPPORTING
    assert verdict.gap_activity is not None
    print(
        f"  ok  node-ipc shape -> {verdict.band} ({verdict.confidence} confidence), "
        f"registration {(NODE_IPC['malicious_publish_at'] - NODE_IPC['reregistered_at']).days} "
        f"days before the malicious publish"
    )


def test_critical_does_not_require_corroboration() -> None:
    """Regression on the design flaw this fixture set exists to prevent.

    Both incident domains have no CT history and no post-event archive captures.
    If corroboration gated the band, neither real takeover could reach CRITICAL.
    """
    from sift.provenance import ct
    from sift.provenance.http_cache import RecordingTransport, build_client
    from sift.provenance.verdict import CRITICAL, assess_domain

    registration = _lookup(NODE_IPC["domain"])
    transport = RecordingTransport()
    with build_client(transport=transport) as client:
        corroboration = ct.corroborate(
            NODE_IPC["domain"],
            registered_at=registration.registered_at,
            client=client,
        )
    assert corroboration == (), (
        f"expected no corroboration for an abandoned single-maintainer domain, "
        f"got {len(corroboration)}"
    )

    verdict = assess_domain(
        NODE_IPC["domain"],
        now=NODE_IPC["malicious_publish_at"],
        registration=registration,
        anchor=_anchor(NODE_IPC["domain"], NODE_IPC["identity_used_since"]),
        gap_activity=_gap(
            NODE_IPC["identity_used_since"], NODE_IPC["reregistered_at"], "dormant"
        ),
        corroboration=corroboration,
    )
    assert verdict.band == CRITICAL, (
        f"CRITICAL must not depend on CT/Wayback corroboration; got {verdict.band}"
    )
    assert verdict.confidence == "medium", (
        f"uncorroborated CRITICAL should carry medium confidence, got {verdict.confidence}"
    )
    print("  ok  uncorroborated dormant discontinuity still reaches CRITICAL (medium)")


# -- ctx -----------------------------------------------------------------------


def test_ctx_domain_changed_hands_again() -> None:
    """figlief.com has been re-registered since the 2022 attack.

    Documents why these fixtures replay recorded responses instead of doing live
    lookups: the live registry state for an incident domain drifts.
    """
    registration = _lookup(CTX["domain"])
    assert registration.ok, f"lookup failed: {registration.error}"
    assert registration.registered_at is not None
    assert registration.registered_at > CTX["reregistered_at_2022"], (
        "recorded registration should postdate the 2022 takeover, showing the "
        "domain turned over again"
    )
    print(
        f"  ok  {CTX['domain']} now registered {registration.registered_at.date()}, "
        f"after the 2022 takeover ({CTX['reregistered_at_2022'].date()})"
    )


def test_ctx_2022_event_reconstructed() -> None:
    """The 2022 state, reconstructed, must produce the same detection."""
    from sift.provenance.verdict import CRITICAL, DomainRegistration, assess_domain

    registration = DomainRegistration(
        domain=CTX["domain"],
        registered_at=CTX["reregistered_at_2022"],
        expires_at=CTX["reregistered_at_2022"] + timedelta(days=365),
        statuses=("client transfer prohibited",),
        rdap_server="reconstructed",
        source="reconstructed-from-incident-record",
    )
    verdict = assess_domain(
        CTX["domain"],
        now=CTX["pypi_reset_at"],
        registration=registration,
        anchor=_anchor(CTX["domain"], CTX["identity_used_since"]),
        gap_activity=_gap(
            CTX["identity_used_since"], CTX["reregistered_at_2022"], "dormant"
        ),
    )
    assert verdict.band == CRITICAL, f"expected CRITICAL, got {verdict.band}"
    minutes = (CTX["pypi_reset_at"] - CTX["reregistered_at_2022"]).total_seconds() / 60
    print(
        f"  ok  ctx 2022 shape -> {verdict.band}; PyPI reset came {minutes:.0f} "
        f"minutes after re-registration"
    )


# -- known negatives -----------------------------------------------------------


def test_stable_domain_is_clean_counter_evidence() -> None:
    """A long-held domain is affirmative counter-evidence, not silence."""
    from sift.provenance.verdict import CLEAN, ROLE_COUNTER, assess_domain

    registration = _lookup("python.org")
    assert registration.ok, f"lookup failed: {registration.error}"
    verdict = assess_domain(
        "python.org",
        now=_utc("2026-07-01T00:00:00"),
        registration=registration,
        anchor=_anchor("python.org", _utc("2018-05-16T00:00:00")),
    )
    assert verdict.band == CLEAN, f"expected CLEAN, got {verdict.band}"
    assert verdict.role == ROLE_COUNTER, (
        f"a clean result must be usable as counter-evidence, got role {verdict.role}"
    )
    print(f"  ok  python.org -> {verdict.band} as {verdict.role} evidence")


def test_continuous_activity_downgrades_to_note() -> None:
    """A maintainer who committed across the gap re-bought their own domain."""
    from sift.provenance.verdict import NOTE, ROLE_COUNTER, assess_domain

    registration = _lookup(NODE_IPC["domain"])
    verdict = assess_domain(
        NODE_IPC["domain"],
        now=NODE_IPC["malicious_publish_at"],
        registration=registration,
        anchor=_anchor(NODE_IPC["domain"], NODE_IPC["identity_used_since"]),
        gap_activity=_gap(
            NODE_IPC["identity_used_since"],
            NODE_IPC["reregistered_at"],
            "continuous",
            commits=41,
            same_key=True,
        ),
    )
    assert verdict.band == NOTE, f"expected NOTE, got {verdict.band}"
    assert verdict.role == ROLE_COUNTER, (
        "continuity across the gap is counter-evidence"
    )
    print(f"  ok  same discontinuity + continuous activity -> {verdict.band} ({verdict.role})")


def test_weak_anchor_cannot_reach_critical() -> None:
    """Attacker-settable author dates are not sturdy enough for CRITICAL."""
    from sift.provenance.verdict import LIKELY, assess_domain

    registration = _lookup(NODE_IPC["domain"])
    verdict = assess_domain(
        NODE_IPC["domain"],
        now=NODE_IPC["malicious_publish_at"],
        registration=registration,
        anchor=_anchor(
            NODE_IPC["domain"],
            NODE_IPC["identity_used_since"],
            kind="commit_author_date",
            strength="weak",
        ),
        gap_activity=_gap(
            NODE_IPC["identity_used_since"], NODE_IPC["reregistered_at"], "dormant"
        ),
    )
    assert verdict.band == LIKELY, (
        f"a weak anchor should cap at LIKELY, got {verdict.band}"
    )
    assert verdict.confidence == "low"
    print("  ok  weak (author-date) anchor caps at LIKELY/low")


# -- failure semantics ---------------------------------------------------------


def test_no_rdap_service_is_unknown_not_clean() -> None:
    """DENIC publishes no RDAP service; that is UNKNOWN, never CLEAN."""
    from sift.provenance.verdict import ROLE_UNAVAILABLE, UNKNOWN, assess_domain

    registration = _lookup("denic.de")
    assert not registration.ok, "expected .de to have no RDAP service"
    verdict = assess_domain(
        "denic.de",
        now=_utc("2026-07-01T00:00:00"),
        registration=registration,
        anchor=_anchor("denic.de", _utc("2005-01-01T00:00:00")),
    )
    assert verdict.band == UNKNOWN, f"expected UNKNOWN, got {verdict.band}"
    assert verdict.role == ROLE_UNAVAILABLE
    print(f"  ok  .de (no RDAP service) -> {verdict.band}/{verdict.role}: {registration.error}")


def test_failed_lookup_is_unknown_not_clean() -> None:
    """The single most important property: an unreachable registry is not a pass."""
    from sift.provenance.verdict import (
        ROLE_UNAVAILABLE,
        UNKNOWN,
        DomainRegistration,
        assess_domain,
    )

    verdict = assess_domain(
        "example-corp.net",
        now=_utc("2026-07-01T00:00:00"),
        registration=DomainRegistration(
            domain="example-corp.net", error="RDAP lookup failed: rate limited (429)"
        ),
        anchor=_anchor("example-corp.net", _utc("2010-01-01T00:00:00")),
        gap_activity=_gap(
            _utc("2010-01-01T00:00:00"), _utc("2026-01-01T00:00:00"), "dormant"
        ),
    )
    assert verdict.band == UNKNOWN, (
        f"a failed lookup must be UNKNOWN even with a dormant gap; got {verdict.band}"
    )
    assert verdict.role == ROLE_UNAVAILABLE
    print("  ok  failed RDAP lookup -> UNKNOWN/unavailable, never CLEAN")


def test_missing_anchor_is_unknown_not_clean() -> None:
    """No evidence of first use means we cannot compare timelines."""
    from sift.provenance.verdict import ROLE_UNAVAILABLE, UNKNOWN, assess_domain

    verdict = assess_domain(
        NODE_IPC["domain"],
        now=NODE_IPC["malicious_publish_at"],
        registration=_lookup(NODE_IPC["domain"]),
        anchor=None,
    )
    assert verdict.band == UNKNOWN, f"expected UNKNOWN, got {verdict.band}"
    assert verdict.role == ROLE_UNAVAILABLE
    print("  ok  no use-anchor -> UNKNOWN/unavailable")


def test_declined_and_rejected_inputs_make_no_requests() -> None:
    """names.py is the security boundary: hostile input must not reach the network."""
    from sift.provenance import names
    from sift.provenance.http_cache import RecordingTransport

    transport = RecordingTransport()

    declined = ["nobody@users.noreply.github.com", "someone@gmail.com"]
    rejected = [
        "x@evil.com/../../admin",
        "x@[::1]",
        "x@10.0.0.1",
        "x@localhost",
        "x@foo..bar.com",
        "x@" + "a" * 300 + ".com",
        "x@exam\nple.com",
        "x@example.zzzznotatld",
    ]

    for email in declined:
        resolved = names.resolve_email(email)
        assert resolved.status == names.SKIPPED, (
            f"{email} should be declined, got {resolved.status}: {resolved.reason}"
        )
    for email in rejected:
        resolved = names.resolve_email(email)
        assert resolved.status == names.REJECTED, (
            f"{email!r} should be rejected, got {resolved.status}: {resolved.reason}"
        )

    assert transport.stats.lookups == 0, (
        f"validation must not touch the network; saw {transport.stats.lookups} lookups"
    )
    print(
        f"  ok  {len(declined)} declined + {len(rejected)} rejected inputs, zero egress"
    )


def test_prospective_notes_are_separate_from_band() -> None:
    """Expiry warnings are about a trusted person's future, not this PR's past."""
    from sift.provenance.verdict import CLEAN, DomainRegistration, assess_domain

    now = _utc("2026-07-01T00:00:00")
    verdict = assess_domain(
        "maintainer-example.net",
        now=now,
        registration=DomainRegistration(
            domain="maintainer-example.net",
            registered_at=_utc("2009-01-01T00:00:00"),
            expires_at=now + timedelta(days=20),
            statuses=("redemptionPeriod",),
        ),
        anchor=_anchor("maintainer-example.net", _utc("2012-01-01T00:00:00")),
    )
    assert verdict.band == CLEAN, f"expiry must not change the band; got {verdict.band}"
    assert verdict.prospective, "expected prospective notes for a redemption-period domain"
    assert any("redemption" in note.lower() for note in verdict.prospective)
    assert any("expires in 20 days" in note for note in verdict.prospective)
    print(f"  ok  CLEAN band with {len(verdict.prospective)} prospective note(s) held aside")


# -- gap activity against real git --------------------------------------------


def test_gap_activity_on_a_real_repo() -> None:
    """Exercise the dormancy discriminator against real git history."""
    from sift.provenance.identity import gap_activity

    author = "maintainer@example-corp.net"
    gap_start = _utc("2019-01-01T00:00:00")
    gap_end = _utc("2022-01-01T00:00:00")

    def commit(repo: Path, when: str, message: str) -> None:
        (repo / "file.txt").write_text(message, encoding="utf-8")
        env = dict(
            os.environ,
            GIT_AUTHOR_NAME="Maintainer",
            GIT_AUTHOR_EMAIL=author,
            GIT_AUTHOR_DATE=when,
            GIT_COMMITTER_NAME="Maintainer",
            GIT_COMMITTER_EMAIL=author,
            GIT_COMMITTER_DATE=when,
        )
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", message], cwd=repo, check=True, capture_output=True, env=env
        )

    with tempfile.TemporaryDirectory() as tmp:
        # Dormant: commits before and after the gap, none inside it.
        dormant = Path(tmp) / "dormant"
        dormant.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=dormant, check=True, capture_output=True)
        commit(dormant, "2016-05-01T00:00:00+0000", "before the gap")
        commit(dormant, "2023-03-01T00:00:00+0000", "after the gap")
        result = gap_activity(
            dormant, author_email=author, gap_start=gap_start, gap_end=gap_end
        )
        assert result is not None
        assert result.verdict == "dormant", f"expected dormant, got {result.verdict}"
        assert result.commits_in_gap == 0
        assert result.scope == "repo_local"

        # Continuous: commits inside the gap too.
        continuous = Path(tmp) / "continuous"
        continuous.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=continuous, check=True, capture_output=True)
        commit(continuous, "2016-05-01T00:00:00+0000", "before the gap")
        commit(continuous, "2020-06-01T00:00:00+0000", "during the gap")
        commit(continuous, "2023-03-01T00:00:00+0000", "after the gap")
        result = gap_activity(
            continuous, author_email=author, gap_start=gap_start, gap_end=gap_end
        )
        assert result is not None
        assert result.verdict == "continuous", f"expected continuous, got {result.verdict}"
        assert result.commits_in_gap == 1

        # First-time contributor: no history at all, so unknown by construction.
        empty = Path(tmp) / "empty"
        empty.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=empty, check=True, capture_output=True)
        commit(empty, "2020-01-01T00:00:00+0000", "someone else entirely")
        result = gap_activity(
            empty, author_email="newcomer@other-example.net",
            gap_start=gap_start, gap_end=gap_end,
        )
        assert result is not None
        assert result.verdict == "unknown", (
            f"a contributor with no repo-local history must be unknown, not "
            f"{result.verdict}"
        )

    print("  ok  gap activity: dormant / continuous / unknown all distinguished on real git")


if __name__ == "__main__":
    raise SystemExit(main())
