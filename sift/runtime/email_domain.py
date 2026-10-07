"""Email-domain enrichment evidence for commit cases.

Deterministic, offline classification of committer/author email domains against
a snapshot produced out-of-band (DNS + RDAP facts). The runtime never performs
live network lookups: callers load a snapshot with ``load_email_domain_intel``
and pass it into the case builders, which attach an ``email_domain_context``
evidence block and a rendered prompt section.

Signal design: the load-bearing fact
(measured on the 2026 megalodon corpus): forged automation identities sit on
non-platform email domains (``build-system@noreply.dev``) while every genuine
bot commits from GitHub noreply infrastructure — a lexical check that is safe
in realtime mode. Registration event dates from RDAP are historical facts and
also realtime-safe; current DNS state (MX/NS) is a post-anchor observation and
is only exposed in retrospective mode.

Temporal-honesty contract:
- ``domain_registered_at`` / ``domain_age_at_commit_days`` /
  ``domain_registered_after_author_first_seen``: available in both modes.
- ``mx_present`` / ``ns_present``: retrospective mode only; ``None`` otherwise.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EMAIL_DOMAIN_INTEL_SNAPSHOT_VERSION = "email_domain_intel_v1"
EMAIL_DOMAIN_YOUNG_DAYS = 30

GITHUB_INFRA_EMAIL_DOMAINS = {
    "github.com",
    "noreply.github.com",
    "users.noreply.github.com",
}

FREEMAIL_EMAIL_DOMAINS = {
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "yahoo.com",
    "proton.me",
    "protonmail.com",
    "pm.me",
    "gmx.com",
    "gmx.de",
    "icloud.com",
    "qq.com",
    "163.com",
    "126.com",
    "yandex.com",
    "yandex.ru",
    "aol.com",
    "mail.ru",
}

BOT_NAME_HINTS = (
    "[bot]",
    "dependabot",
    "github-actions",
    "github actions",
    "renovate",
    "mergify",
)


def _normalize_name(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip()).casefold()


def _normalize_email(value: str) -> str:
    return (value or "").strip().casefold()


def email_domain_of(email: str) -> str:
    normalized = _normalize_email(email)
    if "@" not in normalized:
        return ""
    return normalized.rsplit("@", 1)[-1].strip(".")


def classify_email_domain(domain: str) -> str:
    if not domain:
        return "none"
    if domain in GITHUB_INFRA_EMAIL_DOMAINS:
        return "github_infra"
    if domain in FREEMAIL_EMAIL_DOMAINS:
        return "freemail"
    return "custom"


def bot_shaped_identity(name: str, email: str) -> bool:
    """True for identities presenting as automation, including unbracketed
    forged names like 'build-bot' / 'pipeline-bot' that hint lists miss."""
    normalized_name = _normalize_name(name)
    local_part = _normalize_email(email).split("@", 1)[0]
    combined = f"{normalized_name} {local_part}"
    if any(hint in combined for hint in BOT_NAME_HINTS):
        return True
    for token in (normalized_name, local_part):
        if not token:
            continue
        if token == "bot" or token.endswith(("[bot]", "-bot", "_bot", ".bot", " bot")):
            return True
        if token.startswith(("bot-", "bot_")):
            return True
    return False


def parse_rdap_datetime(value: str) -> datetime | None:
    text = (value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def load_email_domain_intel(path: Path | str) -> dict[str, Any] | None:
    """Load a snapshot written by a fetch script; None on any failure."""
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("domains"), dict):
        return None
    return payload


def _role_context(
    name: str,
    email: str,
    intel: dict[str, Any],
    anchor_iso: str,
    temporal_mode: str,
    author_first_seen_iso: str,
) -> dict[str, Any]:
    domain = email_domain_of(email)
    classification = classify_email_domain(domain)
    bot_shaped = bot_shaped_identity(name, email)
    context: dict[str, Any] = {
        "email_domain": domain,
        "domain_classification": classification,
        "bot_shaped_identity": bot_shaped,
        "bot_identity_on_nonplatform_domain": bool(bot_shaped and domain and classification != "github_infra"),
        "domain_registered": None,
        "domain_registered_at": None,
        "domain_expires_at": None,
        "domain_age_at_commit_days": None,
        "domain_registered_after_author_first_seen": None,
        "mx_present": None,
        "ns_present": None,
        "registrable_domain": None,
        "provenance_band": None,
        "provenance_gap_verdict": None,
        "provenance_used_since": None,
        "provenance_held_since": None,
    }
    entry = intel.get("domains", {}).get(domain) if domain else None
    if not entry or classification != "custom":
        return context
    # v2 fields (provenance-written snapshots); every one is optional.
    context["registrable_domain"] = entry.get("registrable_domain")
    provenance = entry.get("provenance") or {}
    context["provenance_band"] = provenance.get("band")
    context["provenance_gap_verdict"] = provenance.get("gap_verdict")
    context["provenance_used_since"] = provenance.get("used_since")
    context["provenance_held_since"] = provenance.get("held_since")
    rdap = entry.get("rdap") or {}
    context["domain_registered"] = rdap.get("registered")
    context["domain_registered_at"] = rdap.get("registered_at")
    context["domain_expires_at"] = rdap.get("expires_at")
    registered_at = parse_rdap_datetime(rdap.get("registered_at") or "")
    anchor = parse_rdap_datetime(anchor_iso)
    if registered_at and anchor:
        context["domain_age_at_commit_days"] = round((anchor - registered_at).total_seconds() / 86400, 1)
    first_seen = parse_rdap_datetime(author_first_seen_iso)
    if registered_at and first_seen:
        context["domain_registered_after_author_first_seen"] = registered_at > first_seen
    if temporal_mode == "retrospective":
        dns = entry.get("dns") or {}
        context["mx_present"] = dns.get("mx_present")
        context["ns_present"] = dns.get("ns_present")
    return context


def build_email_domain_context(
    commit: dict[str, Any],
    history: dict[str, Any],
    intel: dict[str, Any],
    temporal_mode: str,
) -> dict[str, Any]:
    anchor_iso = str(history.get("anchor_timestamp_utc") or "")
    author_first_seen = str(history.get("author_first_seen_same_email_at") or "")
    return {
        "snapshot_observed_at": str(intel.get("observed_at") or ""),
        "temporal_mode": temporal_mode,
        "author": _role_context(
            str(commit.get("author_name") or ""),
            str(commit.get("author_email") or ""),
            intel,
            anchor_iso,
            temporal_mode,
            author_first_seen,
        ),
        "committer": _role_context(
            str(commit.get("committer_name") or ""),
            str(commit.get("committer_email") or ""),
            intel,
            anchor_iso,
            temporal_mode,
            "",  # history is author-centric; no committer first-seen available
        ),
    }


def render_email_domain_evidence(context: dict[str, Any]) -> str:
    observed_at = context.get("snapshot_observed_at") or "unknown time"
    mode = context.get("temporal_mode") or "retrospective"
    lines = [
        "",
        "EMAIL DOMAIN EVIDENCE",
        f"(offline snapshot observed at {observed_at}; registration dates are historical registry facts"
        + ("; DNS state omitted in realtime mode)" if mode == "realtime" else "; DNS state is as-observed at snapshot time, not commit time)"),
    ]
    for role in ("author", "committer"):
        role_ctx = context.get(role) or {}
        domain = role_ctx.get("email_domain") or "(none)"
        parts = [f"- {role} email domain: {domain} ({role_ctx.get('domain_classification')})"]
        if role_ctx.get("bot_identity_on_nonplatform_domain"):
            parts.append("bot-shaped identity on a NON-platform domain")
        elif role_ctx.get("bot_shaped_identity"):
            parts.append("bot-shaped identity on platform infrastructure")
        if role_ctx.get("domain_registered") is False:
            parts.append("domain NOT registered per RDAP")
        elif role_ctx.get("domain_registered_at"):
            age = role_ctx.get("domain_age_at_commit_days")
            parts.append(
                f"domain registered {role_ctx['domain_registered_at']}"
                + (f" ({age} days before this commit)" if age is not None else "")
            )
        if role_ctx.get("domain_registered_after_author_first_seen"):
            parts.append("domain registration POSTDATES this author's first appearance in repo history (possible domain resurrection)")
        if role_ctx.get("provenance_band"):
            band_text = f"provenance verdict: {role_ctx['provenance_band']}"
            if role_ctx.get("provenance_used_since") and role_ctx.get("provenance_held_since"):
                band_text += (
                    f" (identity used domain since {role_ctx['provenance_used_since']}, "
                    f"current registration since {role_ctx['provenance_held_since']}"
                    + (f"; gap {role_ctx['provenance_gap_verdict']}" if role_ctx.get("provenance_gap_verdict") else "")
                    + ")"
                )
            parts.append(band_text)
        if role_ctx.get("mx_present") is not None:
            parts.append(f"MX present: {role_ctx['mx_present']}")
        lines.append("; ".join(parts))
    return "\n".join(lines) + "\n"
