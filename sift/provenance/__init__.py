"""Domain-provenance checks: did a contributor's email domain change hands?

Deliberately outside `sift.runtime`: this package makes no model calls, needs no
`ANTHROPIC_API_KEY`, and is fully deterministic given a fixture cache. The
dependency direction is one-way -- `provenance` may read `runtime`, never the
reverse -- so that the core commit-triage pipeline stays installable without the
`sift[provenance]` extra.

Entry points:

    assess_domain_provenance(domain, anchor=..., now=...)   one domain
    assess_identity(login, ..., now=...)                    every domain for an identity

See docs/domain-provenance-plan.md for the design and its measured limitations.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from sift.provenance import ct, identity, names, rdap
from sift.provenance.http_cache import build_client
from sift.provenance.verdict import (
    CLEAN,
    CRITICAL,
    LIKELY,
    NOTE,
    ROLE_COUNTER,
    ROLE_DECLINED,
    ROLE_SUPPORTING,
    ROLE_UNAVAILABLE,
    UNKNOWN,
    Discontinuity,
    DomainRegistration,
    DomainVerdict,
    GapActivity,
    IdentityAssessment,
    UseAnchor,
    assess_domain,
)

__all__ = [
    "CLEAN",
    "CRITICAL",
    "LIKELY",
    "NOTE",
    "UNKNOWN",
    "ROLE_COUNTER",
    "ROLE_DECLINED",
    "ROLE_SUPPORTING",
    "ROLE_UNAVAILABLE",
    "Discontinuity",
    "DomainRegistration",
    "DomainVerdict",
    "GapActivity",
    "IdentityAssessment",
    "UseAnchor",
    "assess_domain",
    "assess_domain_provenance",
    "assess_identity",
    "ct",
    "identity",
    "names",
    "rdap",
]


def assess_domain_provenance(
    registrable_domain: str,
    *,
    anchor: UseAnchor | None,
    now: datetime,
    repo_path: Path | None = None,
    author_email: str = "",
    client=None,
    with_corroboration: bool = True,
) -> DomainVerdict:
    """Full pipeline for one already-validated registrable domain."""
    owns_client = client is None
    client = client or build_client()
    try:
        registration = rdap.lookup(registrable_domain, client=client)

        gap = None
        if (
            registration.ok
            and registration.registered_at is not None
            and anchor is not None
            and repo_path is not None
            and author_email
            and anchor.first_seen < registration.registered_at
        ):
            gap = identity.gap_activity(
                repo_path,
                author_email=author_email,
                gap_start=anchor.first_seen,
                gap_end=registration.registered_at,
            )

        corroboration: tuple[Discontinuity, ...] = ()
        if with_corroboration and registration.ok:
            corroboration = ct.corroborate(
                registrable_domain,
                registered_at=registration.registered_at,
                after=anchor.first_seen if anchor else None,
                client=client,
            )

        return assess_domain(
            registrable_domain,
            now=now,
            registration=registration,
            anchor=anchor,
            gap_activity=gap,
            corroboration=corroboration,
        )
    finally:
        if owns_client:
            client.close()


def assess_identity(
    login: str,
    *,
    now: datetime,
    emails: list[str] | None = None,
    identity_history: dict | None = None,
    account_created_at: datetime | None = None,
    repo_path: Path | None = None,
    client=None,
    with_corroboration: bool = True,
) -> IdentityAssessment:
    """Assess every domain an identity is known by.

    `emails` and `identity_history` are additive: the former is usually the PR's
    author addresses, the latter `case_builder`'s repo-local history. GPG UIDs are
    fetched from the login when one is given.
    """
    assessment = IdentityAssessment(login=login)

    owns_client = client is None
    client = client or build_client()
    try:
        anchor_sources = []
        if login:
            anchor_sources.append(identity.gpg_anchors(login, client=client))
        if identity_history:
            anchor_sources.append(
                identity.anchors_from_identity_history(
                    identity_history, account_created_at=account_created_at
                )
            )
        anchors = identity.merge_anchors(*anchor_sources)

        # Candidate domains: everything we have an anchor for, plus anything the
        # caller passed in directly.
        candidates: dict[str, str] = {domain: "" for domain in anchors}
        for email in emails or []:
            resolved = names.resolve_email(email)
            if resolved.status == names.SKIPPED:
                assessment.declined.append((email, resolved.reason))
                continue
            if resolved.status == names.REJECTED:
                assessment.rejected.append((email, resolved.reason))
                continue
            candidates.setdefault(resolved.registrable, email)

        for domain in sorted(candidates):
            assessment.verdicts.append(
                assess_domain_provenance(
                    domain,
                    anchor=anchors.get(domain),
                    now=now,
                    repo_path=repo_path,
                    author_email=candidates.get(domain, ""),
                    client=client,
                    with_corroboration=with_corroboration,
                )
            )
    finally:
        if owns_client:
            client.close()

    return assessment
