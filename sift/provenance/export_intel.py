"""Export an email-domain intel snapshot (v2) from the provenance engine.

This is the data seam between the live provenance engine and the stdlib
evidence path (`sift/runtime/email_domain.py`): the engine writes a snapshot;
the runtime — which may never import this package — only ever reads the file
(docs/plans/2026-08-21-001-merge-domain-provenance-plan.md, KTD2).

Schema v2 = v1 plus, per custom domain:

    "registrable_domain": "example.co.uk",      # names.py reduction, not naive
    "provenance": {                             # present only when assessed
        "band": "likely_takeover",
        "confidence": "...", "role": "...",
        "used_since": "...", "used_anchor_kind": "gpg_uid",
        "held_since": "...", "gap_verdict": "dormant",
        "assessed_at": "..."
    }

v1 snapshots (written by the stdlib fetcher) remain valid; readers treat every
v2 field as optional.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from sift.provenance import rdap
from sift.provenance.http_cache import build_client
from sift.provenance.names import resolve_email
from sift.provenance.verdict import DomainVerdict, UseAnchor
from sift.runtime.email_domain import classify_email_domain, email_domain_of

SNAPSHOT_VERSION_V2 = "email_domain_intel_v2"


def _iso(value: datetime | None) -> str | None:
    return value.isoformat().replace("+00:00", "Z") if value else None


def _dns_presence(registrable: str) -> dict[str, Any]:
    """MX/NS/A presence via dnspython; every failure degrades to None."""
    out: dict[str, Any] = {"ns_present": None, "mx_present": None, "a_present": None}
    try:
        import dns.resolver
    except ImportError:
        return out
    for rrtype, key in (("NS", "ns_present"), ("MX", "mx_present"), ("A", "a_present")):
        try:
            answers = dns.resolver.resolve(registrable, rrtype, lifetime=5)
            out[key] = len(list(answers)) > 0
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            out[key] = False
        except Exception:
            out[key] = None
    return out


def _provenance_block(verdict: DomainVerdict, now: datetime) -> dict[str, Any]:
    anchor = verdict.used_since
    gap = verdict.gap_activity
    return {
        "band": verdict.band,
        "confidence": verdict.confidence,
        "role": verdict.role,
        "used_since": _iso(anchor.first_seen) if anchor else None,
        "used_anchor_kind": anchor.kind if anchor else None,
        "held_since": _iso(verdict.held_since),
        "gap_verdict": gap.verdict if gap else None,
        "assessed_at": _iso(now),
    }


def export_intel(
    emails: list[str],
    *,
    now: datetime,
    repo_path: Path | None = None,
    anchors: dict[str, UseAnchor] | None = None,
    client=None,
    out_path: Path | str | None = None,
    with_dns: bool = True,
    lookup_fn: Callable[..., Any] | None = None,
    assess_fn: Callable[..., DomainVerdict] | None = None,
) -> dict[str, Any]:
    """Build (and optionally write) a v2 snapshot for the given emails.

    `anchors` maps a registrable domain (or the full email) to a UseAnchor;
    domains with an anchor get a full band assessment, others get RDAP facts
    only. `lookup_fn`/`assess_fn` exist for tests; production uses the real
    engine.
    """
    from sift.provenance import assess_domain_provenance

    lookup = lookup_fn or rdap.lookup
    assess = assess_fn or assess_domain_provenance
    anchors = anchors or {}

    owns_client = client is None and lookup_fn is None
    if owns_client:
        client = build_client()
    try:
        domains: dict[str, Any] = {}
        sources: dict[str, list[str]] = {}
        for email in emails:
            domain = email_domain_of(email)
            if not domain or domain in domains:
                if domain:
                    sources.setdefault(domain, []).append(email)
                continue
            sources.setdefault(domain, []).append(email)
            classification = classify_email_domain(domain)
            if classification != "custom":
                domains[domain] = {"classification": classification, "dns": None, "rdap": None, "errors": []}
                continue
            resolved = resolve_email(email)
            entry: dict[str, Any] = {
                "classification": "custom",
                "registrable_domain": resolved.registrable if resolved.ok else None,
                "dns": None,
                "rdap": None,
                "errors": [] if resolved.ok else [f"names: {resolved.status}: {resolved.reason}"],
            }
            if resolved.ok:
                registration = lookup(resolved.registrable, client=client)
                entry["rdap"] = {
                    "source": registration.rdap_server or registration.source,
                    "registered": registration.ok and registration.registered_at is not None,
                    "registered_at": _iso(registration.registered_at),
                    "expires_at": _iso(registration.expires_at),
                    "status": sorted(registration.statuses),
                }
                if registration.error:
                    entry["errors"].append(f"rdap: {registration.error}")
                if with_dns:
                    entry["dns"] = _dns_presence(resolved.registrable)
                anchor = anchors.get(resolved.registrable) or anchors.get(email)
                if anchor is not None:
                    verdict = assess(
                        resolved.registrable,
                        anchor=anchor,
                        now=now,
                        repo_path=repo_path,
                        author_email=email,
                        client=client,
                    )
                    entry["provenance"] = _provenance_block(verdict, now)
            domains[domain] = entry

        snapshot = {
            "snapshot_version": SNAPSHOT_VERSION_V2,
            "observed_at": _iso(now),
            "writer": "provenance",
            "domain_sources": {d: sorted(set(s)) for d, s in sorted(sources.items())},
            "domains": domains,
        }
        if out_path is not None:
            path = Path(out_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return snapshot
    finally:
        if owns_client and client is not None:
            client.close()
