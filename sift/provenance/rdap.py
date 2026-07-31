"""RDAP client: registration date, expiry, and lifecycle status.

RDAP is the structured replacement for WHOIS (RFC 7482/9082/9083): HTTPS, JSON,
an `events` array with `registration` and `expiration` dates, and standard
`status` codes. Registration date is the load-bearing field -- it resets when a
domain is dropped and re-registered, which is precisely the event this package
detects.

Every failure mode here returns a `DomainRegistration` carrying an `error`
string, which `verdict.assess_domain` maps to UNKNOWN. Nothing in this module may
turn a failed lookup into an absent-but-fine result: an unreachable registry
must not read as a clean bill of health.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
from dateutil import parser as date_parser

from sift.provenance import names
from sift.provenance.http_cache import CacheMiss, build_client
from sift.provenance.verdict import DomainRegistration

_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_BOOTSTRAP_HOST = "data.iana.org"
_BOOTSTRAP_SNAPSHOT = Path(__file__).resolve().parent / "data" / "rdap_bootstrap.json"

_MAX_ATTEMPTS = 3
_BACKOFF_BASE_SEC = 1.5

# Lifecycle statuses worth surfacing. RDAP status strings are lowercase with
# spaces in the spec but registries emit camelCase too, so compare normalized.
_INTERESTING_STATUSES = {
    "redemptionperiod",
    "pendingdelete",
    "clienthold",
    "serverhold",
    "clienttransferprohibited",
    "servertransferprohibited",
    "autorenewperiod",
    "renewperiod",
    "inactive",
}


class RDAPError(RuntimeError):
    """Shaped like `runtime.pr_social.GitHubAPIError` for consistency."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        body: str = "",
        retry_after: str = "",
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body
        self.retry_after = retry_after


# -- bootstrap -----------------------------------------------------------------


_bootstrap_cache: dict[str, str] | None = None


def _parse_bootstrap(payload: dict) -> dict[str, str]:
    """IANA's dns.json maps groups of TLDs to lists of RDAP base URLs."""
    mapping: dict[str, str] = {}
    for entry in payload.get("services") or []:
        if len(entry) < 2:
            continue
        tlds, urls = entry[0], entry[1]
        base = next((u for u in urls if u.startswith("https://")), None)
        if not base:
            continue
        for tld in tlds:
            mapping[tld.strip().lower().lstrip(".")] = base.rstrip("/")
    return mapping


def load_bootstrap(client: httpx.Client | None = None) -> dict[str, str]:
    """TLD -> RDAP base URL.

    Prefers the bundled snapshot so an offline run still works, then tries the
    live IANA registry only when a snapshot is absent.
    """
    global _bootstrap_cache
    if _bootstrap_cache is not None:
        return _bootstrap_cache

    if _BOOTSTRAP_SNAPSHOT.is_file():
        try:
            _bootstrap_cache = _parse_bootstrap(
                json.loads(_BOOTSTRAP_SNAPSHOT.read_text(encoding="utf-8"))
            )
            return _bootstrap_cache
        except (OSError, ValueError):
            pass

    names.assert_url_host(_BOOTSTRAP_URL, _BOOTSTRAP_HOST)
    owns_client = client is None
    client = client or build_client()
    try:
        response = client.get(_BOOTSTRAP_URL, headers={"Accept": "application/json"})
        response.raise_for_status()
        _bootstrap_cache = _parse_bootstrap(response.json())
    finally:
        if owns_client:
            client.close()
    return _bootstrap_cache


def refresh_bootstrap_snapshot() -> Path:
    """Re-record the bundled IANA snapshot. Called by tools/, not at runtime."""
    names.assert_url_host(_BOOTSTRAP_URL, _BOOTSTRAP_HOST)
    with build_client() as client:
        response = client.get(_BOOTSTRAP_URL, headers={"Accept": "application/json"})
        response.raise_for_status()
        payload = response.json()
    _BOOTSTRAP_SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
    _BOOTSTRAP_SNAPSHOT.write_text(
        json.dumps(payload, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    global _bootstrap_cache
    _bootstrap_cache = None
    return _BOOTSTRAP_SNAPSHOT


# -- parsing -------------------------------------------------------------------


def _parse_event_date(raw: str) -> datetime | None:
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


def _collect_events(payload: dict) -> dict[str, datetime]:
    """Flatten `events[]`, keeping the earliest date per action.

    Registries sometimes repeat an action; for `registration` the earliest is the
    conservative reading, since a later duplicate would understate how long the
    current holder has had the domain.
    """
    found: dict[str, datetime] = {}
    for event in payload.get("events") or []:
        if not isinstance(event, dict):
            continue
        action = str(event.get("eventAction") or "").strip().lower().replace(" ", "")
        parsed = _parse_event_date(str(event.get("eventDate") or ""))
        if not action or parsed is None:
            continue
        if action not in found or parsed < found[action]:
            found[action] = parsed
    return found


def _collect_statuses(payload: dict) -> tuple[str, ...]:
    raw = payload.get("status") or []
    if isinstance(raw, str):
        raw = [raw]
    out: list[str] = []
    for item in raw:
        text = str(item).strip()
        if text and text.replace(" ", "").lower() in _INTERESTING_STATUSES:
            out.append(text)
    return tuple(sorted(set(out)))


def parse_rdap_payload(
    domain: str, payload: dict, *, rdap_server: str = "", source: str = ""
) -> DomainRegistration:
    events = _collect_events(payload)
    # `registration` is the spec name; `create`/`created` appear in the wild.
    registered = events.get("registration") or events.get("create") or events.get("created")
    expires = events.get("expiration") or events.get("expiry") or events.get("expires")
    return DomainRegistration(
        domain=domain,
        registered_at=registered,
        expires_at=expires,
        statuses=_collect_statuses(payload),
        rdap_server=rdap_server,
        source=source,
    )


# -- lookup --------------------------------------------------------------------


def lookup(
    registrable_domain: str,
    *,
    client: httpx.Client | None = None,
    sleep=time.sleep,
) -> DomainRegistration:
    """Fetch and parse one domain's RDAP record.

    Never raises for network or protocol problems: those become a
    `DomainRegistration` with `error` set, which becomes an UNKNOWN verdict.
    """
    domain = (registrable_domain or "").strip().lower()
    if not domain:
        return DomainRegistration(domain=domain, error="empty domain")

    tld = domain.rsplit(".", 1)[-1]
    try:
        bootstrap = load_bootstrap(client)
    except (httpx.HTTPError, CacheMiss, ValueError, OSError) as exc:
        return DomainRegistration(
            domain=domain, error=f"RDAP bootstrap unavailable: {type(exc).__name__}"
        )

    base = bootstrap.get(tld)
    if not base:
        # No RDAP service for this TLD. Common for ccTLDs and the ex-Freenom
        # namespaces; a real coverage gap, not an error to hide.
        return DomainRegistration(
            domain=domain, error=f"no RDAP service published for .{tld}"
        )

    url = f"{base}/domain/{domain}"
    try:
        expected_host = httpx.URL(url).host
        names.assert_url_host(url, expected_host)
    except ValueError as exc:
        return DomainRegistration(domain=domain, error=str(exc))

    owns_client = client is None
    client = client or build_client()
    try:
        last_error = "unknown failure"
        for attempt in range(1, _MAX_ATTEMPTS + 1):
            try:
                response = client.get(url, headers={"Accept": "application/rdap+json"})
            except CacheMiss:
                raise
            except httpx.HTTPError as exc:
                last_error = f"{type(exc).__name__}"
                if attempt < _MAX_ATTEMPTS:
                    sleep(_BACKOFF_BASE_SEC * attempt)
                    continue
                break

            if response.status_code == 404:
                # Authoritative: no such registration. Distinct from a failure --
                # it means the domain is not currently registered at all.
                return DomainRegistration(
                    domain=domain,
                    rdap_server=base,
                    source="fixture" if _is_replayed(client) else "live",
                    error="not currently registered (RDAP 404)",
                )

            if response.status_code == 429:
                retry_after = response.headers.get("retry-after", "")
                last_error = "rate limited (429)"
                if attempt < _MAX_ATTEMPTS:
                    delay = _BACKOFF_BASE_SEC * attempt
                    if retry_after.isdigit():
                        delay = max(delay, min(float(retry_after), 30.0))
                    sleep(delay)
                    continue
                break

            if response.status_code >= 400:
                last_error = f"HTTP {response.status_code}"
                if response.status_code >= 500 and attempt < _MAX_ATTEMPTS:
                    sleep(_BACKOFF_BASE_SEC * attempt)
                    continue
                break

            try:
                payload = response.json()
            except ValueError:
                last_error = "response was not valid JSON"
                break
            if not isinstance(payload, dict):
                last_error = "response JSON was not an object"
                break

            return parse_rdap_payload(
                domain,
                payload,
                rdap_server=base,
                source="fixture" if _is_replayed(client) else "live",
            )

        return DomainRegistration(
            domain=domain, rdap_server=base, error=f"RDAP lookup failed: {last_error}"
        )
    finally:
        if owns_client:
            client.close()


def _is_replayed(client: httpx.Client) -> bool:
    transport = getattr(client, "_transport", None)
    return bool(getattr(transport, "stats", None) and getattr(transport, "mode", "") == "replay")
