#!/usr/bin/env python3
"""The band ladder as a table: every shape, its expected band and evidence role.

`test_domain_provenance.py` pins the two real incidents. This file pins the
*shape space* around them -- what happens for each combination of anchor strength,
gap-activity verdict, corroboration, and registry answer -- so that a change to
`assess_domain` shows up as a diff in a table rather than as a surprise in
production.

Everything here is level-1: deterministic, offline, free. RDAP is stubbed so
registration dates are exact and no registry is contacted; git history is real,
built in temp repos; the GPG rows generate a throwaway backdated key so
`parse_gpg_packets` runs against real packet output rather than a stub, and skip
when `gpg` is unavailable.

What the table is for, beyond regression: the ladder's two deliberate caps are
easy to weaken by accident. A weak (commit-author-date) anchor must never reach
CRITICAL however much corroboration piles up, because author dates are settable by
whoever wrote the commit; and corroboration must never move a band in either
direction, because it is absent for the domain profile this attack targets. Both
are asserted here as their own rows.

Run:
    python tests/test_provenance_scenarios.py
    pytest tests/test_provenance_scenarios.py
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Replay is opt-in now that production defaults to live network access. Nothing
# in this file should reach the network at all; this is belt and braces.
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

DOMAIN = "example-corp.net"
EMAIL = "dev@example-corp.net"

# The identity used the domain from 2023-03-11; the current registration began
# 2024-03-08. `used < held` is the discontinuity every "supporting" row rests on.
USED = datetime(2023, 3, 11, tzinfo=timezone.utc)
HELD = datetime(2024, 3, 8, tzinfo=timezone.utc)
NOW = datetime(2026, 7, 31, tzinfo=timezone.utc)


def _utc(text: str) -> datetime:
    return datetime.fromisoformat(text).replace(tzinfo=timezone.utc)


# -- table helpers -------------------------------------------------------------


def _anchor(strength: str, *, kind: str = "gpg_uid", first_seen: datetime = USED):
    from sift.provenance.verdict import UseAnchor

    return UseAnchor(
        domain=DOMAIN, first_seen=first_seen, kind=kind, strength=strength,
        evidence="scenario table",
    )


def _gap(verdict: str, *, same_key: bool = False, scope: str = "repo_local"):
    from sift.provenance.verdict import GapActivity

    return GapActivity(
        gap_start=USED,
        gap_end=HELD,
        commits_in_gap=0 if verdict == "dormant" else 2,
        same_signing_key=same_key,
        scope=scope,
        verdict=verdict,
    )


def _ct_bracketing():
    """A CT discontinuity that brackets the registration date.

    Only a bracketing discontinuity counts: sparse archive crawling produces many
    raw gaps that are not ownership changes, so corroboration confirms an event
    RDAP already found rather than discovering one.
    """
    from sift.provenance.verdict import Discontinuity

    return (
        Discontinuity(
            start=_utc("2023-11-01T00:00:00"),
            end=_utc("2024-04-01T00:00:00"),
            kind="ct_issuer_change",
        ),
    )


def _assess(*, anchor, gap=None, registered=HELD, corroboration=(), error=""):
    from sift.provenance.verdict import DomainRegistration, assess_domain

    return assess_domain(
        DOMAIN,
        now=NOW,
        registration=DomainRegistration(
            domain=DOMAIN, registered_at=registered, source="fixture", error=error
        ),
        anchor=anchor,
        gap_activity=gap,
        corroboration=corroboration,
    )


def _check(label: str, verdict, *, band: str, role: str, confidence: str = "") -> None:
    assert verdict.band == band, f"{label}: expected band {band}, got {verdict.band}"
    assert verdict.role == role, f"{label}: expected role {role}, got {verdict.role}"
    if confidence:
        assert verdict.confidence == confidence, (
            f"{label}: expected confidence {confidence}, got {verdict.confidence}"
        )


# -- the ladder ----------------------------------------------------------------


def test_anchor_strength_ladder() -> None:
    """Anchor strength gates the band; the gap verdict decides supporting vs counter."""
    from sift.provenance.verdict import (
        CRITICAL,
        LIKELY,
        NOTE,
        ROLE_COUNTER,
        ROLE_SUPPORTING,
        STRONG,
        WEAK,
    )

    rows = [
        # label                      anchor            gap            band      role
        ("strong + dormant", _anchor(STRONG), _gap("dormant"), CRITICAL, ROLE_SUPPORTING),
        ("weak + dormant", _anchor(WEAK, kind="commit_author_date"), _gap("dormant"), LIKELY, ROLE_SUPPORTING),
        ("strong + continuous", _anchor(STRONG), _gap("continuous"), NOTE, ROLE_COUNTER),
        ("weak + continuous", _anchor(WEAK, kind="commit_author_date"), _gap("continuous"), NOTE, ROLE_COUNTER),
        ("strong, gap untestable", _anchor(STRONG), None, NOTE, ROLE_SUPPORTING),
    ]
    for label, anchor, gap, band, role in rows:
        _check(label, _assess(anchor=anchor, gap=gap), band=band, role=role)
        print(f"  ok  {label:<28} -> {band}/{role}")

    # Stated as its own assertion because it is the single most load-bearing rule
    # in the ladder: CRITICAL is reachable only from an anchor an attacker cannot
    # set. Commit author dates are attacker-settable, so they cap at LIKELY no
    # matter what else is true.
    forged = _assess(
        anchor=_anchor(WEAK, kind="commit_author_date", first_seen=_utc("2010-01-01T00:00:00")),
        gap=_gap("dormant"),
        corroboration=_ct_bracketing(),
    )
    assert forged.band == LIKELY, (
        "a discontinuity resting on attacker-settable author dates must never "
        f"reach CRITICAL, even fully corroborated; got {forged.band}"
    )
    print("  ok  weak anchor caps at LIKELY even with corroboration")


def test_corroboration_moves_confidence_never_the_band() -> None:
    """Both real incident domains have no CT and no post-event captures.

    Gating the band on corroboration would make the true-positive shape
    unreachable, so corroboration is a confidence modifier only. This asserts both
    halves: the band does not move, and the confidence does.
    """
    from sift.provenance.verdict import STRONG

    without = _assess(anchor=_anchor(STRONG), gap=_gap("dormant"))
    with_ct = _assess(anchor=_anchor(STRONG), gap=_gap("dormant"), corroboration=_ct_bracketing())

    assert without.band == with_ct.band, (
        f"corroboration must not move the band: {without.band} -> {with_ct.band}"
    )
    assert without.confidence == "medium", f"got {without.confidence}"
    assert with_ct.confidence == "high", f"got {with_ct.confidence}"
    print(f"  ok  band pinned at {without.band}; confidence medium -> high with corroboration")


def test_benign_and_unavailable_shapes_stay_quiet() -> None:
    """A failed measurement must never render as a clean one."""
    from sift.provenance.verdict import (
        CLEAN,
        ROLE_COUNTER,
        ROLE_UNAVAILABLE,
        STRONG,
        UNKNOWN,
        WEAK,
    )

    # used_since AFTER held_since: the normal ordering, affirmative counter-evidence.
    _check(
        "used after held",
        _assess(anchor=_anchor(WEAK, kind="commit_author_date",
                               first_seen=_utc("2026-01-28T00:00:00")), gap=_gap("dormant")),
        band=CLEAN, role=ROLE_COUNTER,
    )
    # Long-held domain: renewal and voluntary transfer do not reset the date.
    _check(
        "long-held domain",
        _assess(anchor=_anchor(WEAK, kind="commit_author_date"),
                registered=_utc("2019-01-01T00:00:00"), gap=_gap("continuous")),
        band=CLEAN, role=ROLE_COUNTER,
    )
    # The three ways a measurement can fail. None may be CLEAN.
    _check("no anchor", _assess(anchor=None, gap=_gap("dormant")),
           band=UNKNOWN, role=ROLE_UNAVAILABLE)
    _check("no creation date", _assess(anchor=_anchor(STRONG), gap=_gap("dormant"), registered=None),
           band=UNKNOWN, role=ROLE_UNAVAILABLE)
    _check("rdap failed", _assess(anchor=_anchor(STRONG), gap=_gap("dormant"),
                                  registered=None, error="timeout"),
           band=UNKNOWN, role=ROLE_UNAVAILABLE)
    print("  ok  2 benign shapes -> CLEAN/counter; 3 failure shapes -> UNKNOWN/unavailable")


def test_same_signing_key_is_not_yet_consumed_when_dormant() -> None:
    """Documents a known gap rather than asserting desired behaviour.

    A maintainer who was dormant across the gap but signs with the *same* key on
    both sides is the benign self-rebuy case -- a domain takeover does not convey
    the private key. Today that still reads CRITICAL: `same_signing_key` only
    modifies confidence on the CONTINUOUS branch and is ignored on DORMANT.

    This is deliberately NOT fixed here. `%GK` reports a *claimed* issuer key id
    whether or not the signature verifies (`%G?` is `E` whenever the public key is
    absent from the keyring, which on a CI runner it always is), so downgrading a
    band on key continuity today would be an attacker-settable suppression
    primitive. Verify the signature first; then change the ladder.

    When that lands, this test should be inverted, not deleted.
    """
    from sift.provenance.verdict import CRITICAL, ROLE_SUPPORTING, STRONG

    same_key = _assess(anchor=_anchor(STRONG), gap=_gap("dormant", same_key=True))
    _check("dormant + same key", same_key, band=CRITICAL, role=ROLE_SUPPORTING)

    # On the continuous branch it does move confidence, which is the behaviour the
    # dormant branch is missing.
    continuous_same = _assess(anchor=_anchor(STRONG), gap=_gap("continuous", same_key=True))
    continuous_diff = _assess(anchor=_anchor(STRONG), gap=_gap("continuous"))
    assert continuous_same.confidence == "medium", continuous_same.confidence
    assert continuous_diff.confidence == "low", continuous_diff.confidence
    print("  ok  dormant+same-key still CRITICAL (known gap); continuous consumes it")


# -- real inputs ---------------------------------------------------------------


def test_input_handling_makes_no_requests() -> None:
    """Domains arrive from attacker-controlled PR metadata and are interpolated
    into URLs, so validation runs before any egress."""
    from sift.provenance import names

    skipped = [
        "someone@users.noreply.github.com",
        "someone@gmail.com",
        "someone@outlook.com",
    ]
    rejected = [
        "not-an-email",
        "a@b",
        "someone@localhost",
        "someone@127.0.0.1",
        "someone@example-corp.net.evil.tld.",
        "someone@" + "a" * 300 + ".com",
    ]
    resolved = {
        "someone@example-corp.net": "example-corp.net",
        "someone@sub.example-corp.net": "example-corp.net",
        "someone@endee.io": "endee.io",
    }

    for address in skipped:
        r = names.resolve_email(address)
        assert r.status == names.SKIPPED, f"{address}: expected skipped, got {r.status}"
    for address in rejected:
        r = names.resolve_email(address)
        assert r.status == names.REJECTED, f"{address}: expected rejected, got {r.status}"
    for address, registrable in resolved.items():
        r = names.resolve_email(address)
        assert r.ok and r.registrable == registrable, f"{address}: got {r.status}/{r.registrable}"

    print(f"  ok  {len(skipped)} declined, {len(rejected)} rejected, "
          f"{len(resolved)} resolved to registrable domains")


def test_gpg_uid_yields_a_strong_anchor_from_real_packets() -> None:
    """The only path to CRITICAL, exercised against real `gpg --list-packets` output.

    Generates a throwaway key whose UID binding signature is backdated with
    `--faked-system-time`, so this asserts the per-UID binding date is read (not
    the key-wide creation date) and that it carries STRONG.
    """
    from sift.provenance import identity, names
    from sift.provenance.verdict import CRITICAL, ROLE_SUPPORTING, STRONG

    if not shutil.which("gpg"):
        print("  skip  gpg not available")
        return

    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp) / "gnupg"
        home.mkdir(mode=0o700)
        gen = subprocess.run(
            ["gpg", "--batch", "--faked-system-time", "20230311T100000!",
             "--passphrase", "", "--quick-generate-key",
             f"Test Contributor <{EMAIL}>", "ed25519", "sign", "0"],
            env=dict(os.environ, GNUPGHOME=str(home)),
            capture_output=True, text=True, timeout=120,
        )
        if gen.returncode != 0:
            print(f"  skip  gpg could not generate a key: {gen.stderr.strip()[:120]}")
            return
        export = subprocess.run(
            ["gpg", "--export", "--armor", EMAIL],
            env=dict(os.environ, GNUPGHOME=str(home)),
            capture_output=True, text=True, timeout=60,
        )
        armored = export.stdout

    uids = identity.parse_gpg_packets(armored)
    assert uids, "no UIDs parsed from a freshly generated key"
    bound = {uid: when for uid, when in uids}
    when = next(iter(bound.values()))
    assert when.date().isoformat() == "2023-03-11", (
        f"expected the backdated binding signature, got {when.date().isoformat()}"
    )

    resolved = names.resolve_email(EMAIL)
    assert resolved.ok
    anchor = _anchor(STRONG, kind="gpg_uid", first_seen=when)
    _check("gpg anchor + dormant", _assess(anchor=anchor, gap=_gap("dormant")),
           band=CRITICAL, role=ROLE_SUPPORTING, confidence="medium")
    print(f"  ok  real GPG UID bound {when.date().isoformat()} -> STRONG -> CRITICAL reachable")


def test_gap_activity_against_real_git() -> None:
    """The dormant/continuous discriminator, on real history rather than a stub."""
    from sift.provenance.identity import gap_activity

    def commit(repo: Path, when: str) -> None:
        (repo / "f.txt").write_text(when, encoding="utf-8")
        env = dict(
            os.environ,
            GIT_AUTHOR_NAME="C", GIT_AUTHOR_EMAIL=EMAIL, GIT_AUTHOR_DATE=when,
            GIT_COMMITTER_NAME="C", GIT_COMMITTER_EMAIL=EMAIL, GIT_COMMITTER_DATE=when,
        )
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-q", "-m", when], cwd=repo, check=True,
                       capture_output=True, env=env)

    def build(tmp: Path, name: str, whens: list[str]) -> Path:
        repo = tmp / name
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True, capture_output=True)
        for when in whens:
            commit(repo, when)
        return repo

    before, after = "2022-06-01T10:00:00+0000", "2026-07-01T10:00:00+0000"
    inside = "2023-09-01T10:00:00+0000"

    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        cases = [
            ("dormant", [before, after], "dormant", 0),
            ("continuous", [before, inside, after], "continuous", 1),
            ("only before the gap", [before], "unknown", 0),
            ("only after the gap", [after], "unknown", 0),
        ]
        for name, whens, expected, in_gap in cases:
            repo = build(tmp, name.replace(" ", "_"), whens)
            result = gap_activity(repo, author_email=EMAIL, gap_start=USED, gap_end=HELD)
            assert result is not None, name
            assert result.verdict == expected, f"{name}: expected {expected}, got {result.verdict}"
            assert result.commits_in_gap == in_gap, f"{name}: got {result.commits_in_gap}"
            print(f"  ok  {name:<22} -> {expected}")


def main() -> int:
    if not _HAVE_EXTRA:
        print("skip: needs the provenance extra (uv pip install -e '.[provenance]')")
        return 0

    tests = [
        test_anchor_strength_ladder,
        test_corroboration_moves_confidence_never_the_band,
        test_benign_and_unavailable_shapes_stay_quiet,
        test_same_signing_key_is_not_yet_consumed_when_dormant,
        test_input_handling_makes_no_requests,
        test_gpg_uid_yields_a_strong_anchor_from_real_packets,
        test_gap_activity_against_real_git,
    ]
    failed = 0
    print("provenance scenario matrix: every shape, its band and its role\n")
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
