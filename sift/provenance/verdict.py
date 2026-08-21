"""Data model and the ownership-discontinuity decision function.

The question is whether a domain backing a contributor's identity changed hands
since that identity started using it. Drop-and-re-register resets a domain's
RDAP registration date; renewal and voluntary registrar transfer do not. So:

    used_since < held_since   =>   the domain left this identity's control

`node-ipc` (2026) is the reference case: an identity using
`atlantis-software.net` for years, against a registration date of 2026-05-07.

The discriminator between a takeover and a maintainer who let their own domain
lapse is not elapsed time -- it is whether the identity was active *across* the
ownership gap. Someone who kept committing throughout, signing with the same
key, was demonstrably still the same person.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

# Bands.
CRITICAL = "CRITICAL"
LIKELY = "LIKELY"
NOTE = "NOTE"
UNKNOWN = "UNKNOWN"
CLEAN = "CLEAN"

# Evidence roles. Four states, not two: a benign result and a failed lookup must
# never be indistinguishable downstream.
ROLE_SUPPORTING = "supporting"
ROLE_COUNTER = "counter"
ROLE_UNAVAILABLE = "unavailable"
ROLE_DECLINED = "declined"

# Gap-activity verdicts.
CONTINUOUS = "continuous"
DORMANT = "dormant"
INDETERMINATE = "unknown"

# Anchor strengths.
STRONG = "strong"
MEDIUM = "medium"
WEAK = "weak"

# Absorbs clock skew and a maintainer who renewed a day or two late through a
# registrar that re-created rather than renewed the registration.
TOLERANCE = timedelta(days=14)

_STRENGTH_CONFIDENCE_CAP = {STRONG: "high", MEDIUM: "medium", WEAK: "low"}


@dataclass(frozen=True)
class DomainRegistration:
    """Current registration state of one domain, from RDAP."""

    domain: str
    registered_at: datetime | None = None  # None: registry publishes no creation date
    expires_at: datetime | None = None
    statuses: tuple[str, ...] = ()
    rdap_server: str = ""
    source: str = ""  # "live" | "fixture"
    error: str = ""  # non-empty means the lookup failed

    @property
    def ok(self) -> bool:
        return not self.error


@dataclass(frozen=True)
class UseAnchor:
    """Evidence that an identity was already using a domain at some date."""

    domain: str
    first_seen: datetime
    kind: str  # "gpg_uid" | "gharchive_push" | "commit_author_date"
    strength: str
    evidence: str


@dataclass(frozen=True)
class Discontinuity:
    """A hands-changed signal from CT or Wayback. Corroboration only."""

    kind: str  # "ct_issuer_change" | "ct_gap" | "wayback_parking"
    start: datetime | None = None
    end: datetime | None = None
    detail: str = ""


@dataclass(frozen=True)
class GapActivity:
    """Was the identity active across the ownership gap?

    Scope is repo-local in v1: `case_builder` already computes repo-local author
    history, and it needs no new data source. The consequence is that a
    first-time contributor has no history at all, so their verdict is
    `unknown` by construction and can never reach `dormant`.
    """

    gap_start: datetime
    gap_end: datetime
    commits_in_gap: int
    same_signing_key: bool
    scope: str  # "repo_local" | "account_wide"
    verdict: str


@dataclass(frozen=True)
class DomainVerdict:
    domain: str
    band: str
    confidence: str
    role: str
    held_since: datetime | None = None
    used_since: UseAnchor | None = None
    gap_activity: GapActivity | None = None
    corroboration: tuple[Discontinuity, ...] = ()
    reasons: tuple[str, ...] = ()
    # Expiry / redemption findings. About a trusted person's future risk, not an
    # untrusted PR's past. Never rendered to a public surface.
    prospective: tuple[str, ...] = ()

    @property
    def is_anomaly(self) -> bool:
        return self.band in (CRITICAL, LIKELY)


@dataclass
class IdentityAssessment:
    """All domain verdicts for one identity, plus what was skipped and why."""

    login: str = ""
    verdicts: list[DomainVerdict] = field(default_factory=list)
    declined: list[tuple[str, str]] = field(default_factory=list)  # (raw, reason)
    rejected: list[tuple[str, str]] = field(default_factory=list)

    @property
    def worst(self) -> DomainVerdict | None:
        order = {CRITICAL: 0, LIKELY: 1, NOTE: 2, UNKNOWN: 3, CLEAN: 4}
        if not self.verdicts:
            return None
        return sorted(self.verdicts, key=lambda v: order.get(v.band, 9))[0]


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _cap_confidence(level: str, cap: str) -> str:
    ladder = ["low", "medium", "high"]
    return ladder[min(ladder.index(level), ladder.index(cap))]


def _prospective_notes(
    registration: DomainRegistration, now: datetime, horizon_days: int = 60
) -> tuple[str, ...]:
    notes: list[str] = []
    lifecycle = {"redemptionperiod", "pendingdelete", "clienthold", "serverhold"}
    hit = [s for s in registration.statuses if s.replace(" ", "").lower() in lifecycle]
    if hit:
        notes.append(f"domain is in registry status {', '.join(sorted(hit))}")
    if registration.expires_at is not None:
        remaining = registration.expires_at - now
        if remaining <= timedelta(0):
            notes.append(
                f"registration expired {abs(remaining).days} days ago and has not been renewed"
            )
        elif remaining <= timedelta(days=horizon_days):
            notes.append(f"registration expires in {remaining.days} days")
    return tuple(notes)


def assess_domain(
    domain: str,
    *,
    now: datetime,
    registration: DomainRegistration,
    anchor: UseAnchor | None,
    gap_activity: GapActivity | None = None,
    corroboration: tuple[Discontinuity, ...] = (),
) -> DomainVerdict:
    """Decide one domain's band.

    `now` is a parameter and never `datetime.now()`: fixtures replay historical
    incidents against a pinned clock.
    """
    now = _as_utc(now)
    reasons: list[str] = []
    prospective = _prospective_notes(registration, now) if registration.ok else ()

    # A lookup that failed is UNKNOWN. It must never read as a clean bill of
    # health -- an unreachable registry is the difference between "we checked"
    # and "we could not check".
    if not registration.ok:
        return DomainVerdict(
            domain=domain,
            band=UNKNOWN,
            confidence="low",
            role=ROLE_UNAVAILABLE,
            reasons=(f"RDAP lookup failed: {registration.error}",),
        )

    corroborated = bool(corroboration)
    held = _as_utc(registration.registered_at) if registration.registered_at else None

    if anchor is None:
        return DomainVerdict(
            domain=domain,
            band=UNKNOWN,
            confidence="low",
            role=ROLE_UNAVAILABLE,
            held_since=held,
            corroboration=corroboration,
            reasons=("no evidence of when this identity began using the domain",),
            prospective=prospective,
        )

    used = _as_utc(anchor.first_seen)

    # No creation date published (DENIC and a number of ccTLDs). CT/Wayback are
    # all we have, and they can only ever produce a low-confidence note.
    if held is None:
        gap_after_use = [
            d for d in corroboration if d.start is not None and _as_utc(d.start) > used
        ]
        if gap_after_use:
            return DomainVerdict(
                domain=domain,
                band=UNKNOWN,
                confidence="low",
                role=ROLE_SUPPORTING,
                used_since=anchor,
                corroboration=corroboration,
                reasons=(
                    "registry publishes no creation date; "
                    "certificate or archive history shows a discontinuity after "
                    f"this identity began using the domain ({used.date().isoformat()})",
                ),
                prospective=prospective,
            )
        return DomainVerdict(
            domain=domain,
            band=UNKNOWN,
            confidence="low",
            role=ROLE_UNAVAILABLE,
            used_since=anchor,
            corroboration=corroboration,
            reasons=("registry publishes no creation date; cannot compare timelines",),
            prospective=prospective,
        )

    # No discontinuity: the domain has been held continuously since before this
    # identity first used it. Affirmative counter-evidence, not silence.
    if used >= held - TOLERANCE:
        return DomainVerdict(
            domain=domain,
            band=CLEAN,
            confidence=_cap_confidence("high", _STRENGTH_CONFIDENCE_CAP[anchor.strength]),
            role=ROLE_COUNTER,
            held_since=held,
            used_since=anchor,
            corroboration=corroboration,
            reasons=(
                f"registered {held.date().isoformat()}, continuously held since before "
                f"this identity first used it ({used.date().isoformat()})",
            ),
            prospective=prospective,
        )

    # Discontinuity confirmed. Everything below is about how much it matters.
    age = now - held
    reasons.append(
        f"current registration began {held.date().isoformat()} "
        f"({age.days} days ago), but this identity was already using the domain "
        f"on {used.date().isoformat()} per {anchor.kind}"
    )
    if corroborated:
        reasons.append(
            "corroborated by " + ", ".join(sorted({d.kind for d in corroboration}))
        )

    gap_verdict = gap_activity.verdict if gap_activity else INDETERMINATE

    if gap_verdict == CONTINUOUS:
        # The identity kept committing while the domain was out of its hands,
        # signing with the same key. Almost certainly a self-rebuy.
        confidence = _cap_confidence(
            "medium" if gap_activity and gap_activity.same_signing_key else "low",
            _STRENGTH_CONFIDENCE_CAP[anchor.strength],
        )
        reasons.append(
            f"identity authored {gap_activity.commits_in_gap} commit(s) across the "
            f"ownership gap"
            + (" with an unchanged signing key" if gap_activity.same_signing_key else "")
            + "; consistent with the maintainer re-registering their own lapsed domain"
        )
        return DomainVerdict(
            domain=domain,
            band=NOTE,
            confidence=confidence,
            role=ROLE_COUNTER,
            held_since=held,
            used_since=anchor,
            gap_activity=gap_activity,
            corroboration=corroboration,
            reasons=tuple(reasons),
            prospective=prospective,
        )

    if gap_verdict == DORMANT:
        reasons.append(
            "identity was dormant across the ownership gap and resumed afterwards; "
            "this is the account-takeover shape"
        )
        # Corroboration moves confidence, never the band. Measured against the two
        # known incidents, CT and Wayback have nothing to say about the small
        # abandoned domains this attack actually targets (see ct.py), so gating
        # CRITICAL on corroboration would make the true-positive shape
        # unreachable. What does gate the band is anchor strength: a discontinuity
        # established only from attacker-settable commit author dates is not
        # sturdy enough to call CRITICAL.
        band = CRITICAL if anchor.strength in (STRONG, MEDIUM) else LIKELY
        confidence = _cap_confidence(
            "high" if corroborated else "medium",
            _STRENGTH_CONFIDENCE_CAP[anchor.strength],
        )
        if not corroborated:
            reasons.append(
                "no certificate or archive corroboration available, which is "
                "typical for abandoned single-maintainer domains"
            )
        return DomainVerdict(
            domain=domain,
            band=band,
            confidence=confidence,
            role=ROLE_SUPPORTING,
            held_since=held,
            used_since=anchor,
            gap_activity=gap_activity,
            corroboration=corroboration,
            reasons=tuple(reasons),
            prospective=prospective,
        )

    # Indeterminate gap activity -- most often a contributor with no prior
    # history in this repository, where repo-local scope cannot see continuity
    # either way.
    if gap_activity is None:
        reasons.append("no repo-local history available to test activity across the gap")
    else:
        reasons.append("insufficient history to test activity across the gap")
    band = LIKELY if corroborated else NOTE
    confidence = _cap_confidence("low", _STRENGTH_CONFIDENCE_CAP[anchor.strength])
    return DomainVerdict(
        domain=domain,
        band=band,
        confidence=confidence,
        role=ROLE_SUPPORTING,
        held_since=held,
        used_since=anchor,
        gap_activity=gap_activity,
        corroboration=corroboration,
        reasons=tuple(reasons),
        prospective=prospective,
    )
