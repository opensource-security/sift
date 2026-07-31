"""Corroboration from Certificate Transparency and the Wayback Machine.

A free stand-in for the passive-DNS approach in Lever et al., "Domain-Z: 28
Registrations Later" (IEEE S&P 2016), whose Alembic algorithm inferred ownership
change from DNS record churn. We do not have passive DNS, but CT issuance history
and archived content history leave similar fingerprints:

  * a run of certificates, a gap, then certificates from a different issuer
  * archived content, a parking-page interval, then different content

Neither ever fires an alert on its own. Both move confidence, and both cover for
registries that publish no creation date. An empty result is normal -- plenty of
domains never used TLS or were never archived -- and must lower confidence rather
than produce a finding.

Measured limitation, and it is a large one. Checked against the two known
incidents (`atlantis-software.net`, `figlief.com`), both returned **zero** CT
entries and no archived captures after the re-registration event. Small,
abandoned, single-maintainer domains -- the exact profile this attack targets --
tend never to have held a TLS certificate and are crawled by the Internet Archive
only sporadically. Corroboration is therefore *usually absent for true
positives*, which is why `verdict.assess_domain` treats it strictly as a
confidence modifier and never as a gate on the band.

Raw capture gaps are also far too noisy to use directly: sparse archive crawling
gave `atlantis-software.net` sixteen 90-day-plus "gaps" across its history, none
of which were ownership changes. So a discontinuity counts only when it
*brackets* the registration date already established by RDAP -- confirmation of a
known event, not independent discovery of one.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
from dateutil import parser as date_parser

from sift.provenance import names
from sift.provenance.http_cache import CacheMiss, build_client
from sift.provenance.verdict import Discontinuity

_CRTSH_HOST = "crt.sh"
_WAYBACK_HOST = "web.archive.org"

# A quiet stretch long enough to be a lifecycle event rather than a lapsed
# renewal. ICANN's expiry-to-release path runs roughly 30 (grace) + 30
# (redemption) + 5 (pending delete) days, so a gap shorter than that cannot be a
# drop-and-reacquire.
_MIN_GAP = timedelta(days=90)

# Archive crawls are sparse enough that a 90-day hole means nothing, so Wayback
# needs a longer quiet stretch than CT before it is worth reporting at all.
_MIN_WAYBACK_GAP = timedelta(days=180)

# How far outside a discontinuity's bounds the RDAP registration date may fall
# and still count as bracketed. Generous because the last pre-drop capture can
# predate the actual lapse by months.
_BRACKET_SLACK = timedelta(days=120)

# Parked domains are commonly served by a small number of registrar parking
# hosts; their fingerprint in archived URLs and CT SANs is a wildcard or a
# registrar hostname.
_PARKING_MARKERS = (
    "sedoparking",
    "parkingcrew",
    "bodis",
    "afternic",
    "dan.com",
    "godaddysites",
    "domaincontrol",
    "hugedomains",
    "buydomains",
    "namecheap-parking",
    "parklogic",
)


def _parse_ts(raw: str) -> datetime | None:
    text = (raw or "").strip()
    if not text:
        return None
    try:
        parsed = date_parser.isoparse(text)
    except (ValueError, OverflowError):
        try:
            parsed = date_parser.parse(text)
        except (ValueError, OverflowError, TypeError):
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


# -- Certificate Transparency --------------------------------------------------


def _crtsh_url(domain: str) -> str:
    # No `exclude=expired`: expired certificates are the entire point here, since
    # the prior owner's certificates are what establish the earlier regime.
    return f"https://{_CRTSH_HOST}/?q={domain}&output=json"


def fetch_ct_entries(
    registrable_domain: str, *, client: httpx.Client | None = None
) -> list[dict]:
    """Certificate issuance history for a domain. Best effort.

    crt.sh has no stability guarantee and rate-limits aggressively; every failure
    yields an empty list, which the caller reads as "no corroboration available".
    """
    url = _crtsh_url(registrable_domain)
    try:
        names.assert_url_host(url, _CRTSH_HOST)
    except ValueError:
        return []

    owns_client = client is None
    client = client or build_client(timeout=25.0)
    try:
        response = client.get(url, headers={"Accept": "application/json"})
    except (CacheMiss, httpx.HTTPError):
        # Both sources here are corroboration-only and can never raise a band, so
        # an unreachable service and an unrecorded fixture are equivalent to "no
        # corroboration available" -- the documented normal case. RDAP does NOT
        # get this treatment: there, a missing answer is load-bearing and must
        # surface as UNKNOWN.
        #
        # crt.sh in particular is measurably flaky: back-to-back probes returned
        # HTTP 200 and then a 30-second read timeout.
        return []
    finally:
        if owns_client:
            client.close()

    if response.status_code != 200:
        return []
    try:
        payload = response.json()
    except ValueError:
        return []
    return payload if isinstance(payload, list) else []


def ct_discontinuities(entries: list[dict]) -> tuple[Discontinuity, ...]:
    """Find issuance gaps and issuer regime changes."""
    observations: list[tuple[datetime, str, str]] = []
    for entry in entries:
        when = _parse_ts(str(entry.get("not_before") or entry.get("entry_timestamp") or ""))
        if when is None:
            continue
        issuer = str(entry.get("issuer_name") or "").strip()
        common_name = str(entry.get("common_name") or "").strip().lower()
        observations.append((when, issuer, common_name))

    if len(observations) < 2:
        return ()

    observations.sort(key=lambda item: item[0])
    found: list[Discontinuity] = []

    for (prev_when, prev_issuer, _), (when, issuer, _) in zip(
        observations, observations[1:]
    ):
        if when - prev_when < _MIN_GAP:
            continue
        issuer_changed = _issuer_org(prev_issuer) != _issuer_org(issuer)
        found.append(
            Discontinuity(
                kind="ct_issuer_change" if issuer_changed else "ct_gap",
                start=prev_when,
                end=when,
                detail=(
                    f"{(when - prev_when).days}-day gap in certificate issuance"
                    + (
                        f", issuer changed from {_issuer_org(prev_issuer)!r} "
                        f"to {_issuer_org(issuer)!r}"
                        if issuer_changed
                        else ""
                    )
                ),
            )
        )

    parked = [
        (when, cn)
        for when, _, cn in observations
        if any(marker in cn for marker in _PARKING_MARKERS)
    ]
    if parked:
        found.append(
            Discontinuity(
                kind="ct_gap",
                start=parked[0][0],
                end=parked[-1][0],
                detail=f"certificate issued for a registrar parking host ({parked[0][1]})",
            )
        )

    return tuple(found)


def _issuer_org(issuer_name: str) -> str:
    """Pull the O= field out of an X.509 issuer DN, falling back to the whole DN."""
    for chunk in issuer_name.split(","):
        chunk = chunk.strip()
        if chunk.upper().startswith("O="):
            return chunk[2:].strip().strip('"')
    return issuer_name.strip()


# -- Wayback -------------------------------------------------------------------


def _wayback_url(domain: str) -> str:
    return (
        f"https://{_WAYBACK_HOST}/cdx/search/cdx?url={domain}&output=json"
        "&fl=timestamp,original,digest,statuscode&collapse=timestamp:6&limit=3000"
    )


def fetch_wayback_captures(
    registrable_domain: str, *, client: httpx.Client | None = None
) -> list[dict]:
    url = _wayback_url(registrable_domain)
    try:
        names.assert_url_host(url, _WAYBACK_HOST)
    except ValueError:
        return []

    owns_client = client is None
    client = client or build_client(timeout=25.0)
    try:
        response = client.get(url, headers={"Accept": "application/json"})
    except (CacheMiss, httpx.HTTPError):
        # Both sources here are corroboration-only and can never raise a band, so
        # an unreachable service and an unrecorded fixture are equivalent to "no
        # corroboration available" -- the documented normal case. RDAP does NOT
        # get this treatment: there, a missing answer is load-bearing and must
        # surface as UNKNOWN.
        #
        # crt.sh in particular is measurably flaky: back-to-back probes returned
        # HTTP 200 and then a 30-second read timeout.
        return []
    finally:
        if owns_client:
            client.close()

    if response.status_code != 200:
        return []
    try:
        payload = response.json()
    except ValueError:
        return []
    if not isinstance(payload, list) or len(payload) < 2:
        return []
    header, *rows = payload
    if not isinstance(header, list):
        return []
    return [dict(zip(header, row)) for row in rows if isinstance(row, list)]


def wayback_discontinuities(captures: list[dict]) -> tuple[Discontinuity, ...]:
    """Find capture gaps that also come with a content change.

    A gap alone is worthless -- the Internet Archive simply does not crawl small
    sites often. Requiring the content digest to differ across the gap filters out
    crawl sparsity, since a domain that went away and came back under new
    ownership serves different bytes afterwards.
    """
    observations: list[tuple[datetime, str]] = []
    for capture in captures:
        raw = str(capture.get("timestamp") or "").strip()
        if len(raw) < 8 or not raw.isdigit():
            continue
        try:
            when = datetime(int(raw[0:4]), int(raw[4:6]), int(raw[6:8]), tzinfo=timezone.utc)
        except ValueError:
            continue
        observations.append((when, str(capture.get("digest") or "").strip()))

    if len(observations) < 2:
        return ()

    observations.sort(key=lambda item: item[0])
    found: list[Discontinuity] = []
    for (prev_when, prev_digest), (when, digest) in zip(observations, observations[1:]):
        if when - prev_when < _MIN_WAYBACK_GAP:
            continue
        if not prev_digest or not digest or prev_digest == digest:
            continue
        found.append(
            Discontinuity(
                kind="wayback_parking",
                start=prev_when,
                end=when,
                detail=(
                    f"{(when - prev_when).days}-day gap in archived captures, "
                    "with different content served afterwards"
                ),
            )
        )
    return tuple(found)


# -- combined ------------------------------------------------------------------


def brackets(discontinuity: Discontinuity, moment: datetime) -> bool:
    """Does this discontinuity span `moment`, within slack?"""
    if discontinuity.start is None or discontinuity.end is None:
        return False
    return (
        discontinuity.start - _BRACKET_SLACK
        <= moment
        <= discontinuity.end + _BRACKET_SLACK
    )


def corroborate(
    registrable_domain: str,
    *,
    registered_at: datetime | None = None,
    after: datetime | None = None,
    client: httpx.Client | None = None,
) -> tuple[Discontinuity, ...]:
    """Corroborating discontinuities for a domain.

    When `registered_at` is known, only discontinuities that *bracket* it are
    returned: the job is to confirm an ownership change RDAP already established,
    not to discover ownership changes independently. Without that constraint,
    archive-crawl sparsity alone produces a dozen spurious hits per domain.

    When `registered_at` is None -- a registry that publishes no creation date --
    fall back to `after` (the identity's first use), which is the only case where
    these sources are asked to stand on their own, and where the caller must keep
    confidence low.
    """
    owns_client = client is None
    client = client or build_client(timeout=25.0)
    try:
        found = list(ct_discontinuities(fetch_ct_entries(registrable_domain, client=client)))
        found.extend(
            wayback_discontinuities(
                fetch_wayback_captures(registrable_domain, client=client)
            )
        )
    finally:
        if owns_client:
            client.close()

    if registered_at is not None:
        moment = (
            registered_at
            if registered_at.tzinfo
            else registered_at.replace(tzinfo=timezone.utc)
        )
        found = [d for d in found if brackets(d, moment)]
    elif after is not None:
        cutoff = after if after.tzinfo else after.replace(tzinfo=timezone.utc)
        found = [d for d in found if d.start is None or d.start >= cutoff]

    found.sort(key=lambda d: (d.start or datetime.min.replace(tzinfo=timezone.utc)))
    return tuple(found)
