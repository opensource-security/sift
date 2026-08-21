from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import median, pstdev
from typing import Any

from .email_domain import build_email_domain_context, render_email_domain_evidence
from .file_ownership import query_sensitive_path_owners
from .pr_social import render_pr_social_history_lines
from .sensitive_surfaces import (
    classify_paths,
    path_class_order,
    sensitive_surface_profile,
    top_level_directory,
)
from .types import (
    CommitCase,
    GHArchiveEventLookup,
    GHArchiveEventsByRepo,
    GHArchivePushEvent,
    GroundTruthCommit,
)


MIRROR_DIR_SEARCH_ORDER = ("mirrors_repair", "mirrors")
REPLAY_CASE_SCHEMA_VERSION = "replay_case_v1"
REALTIME_CASE_SCHEMA_VERSION = "realtime_case_v4"
WEEKDAY_NAMES = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
WEEKDAY_LABEL_MAP = {index: name for index, name in enumerate(WEEKDAY_NAMES)}


def run_cmd(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


def run_git(repo_path: Path, *args: str) -> tuple[int, str, str]:
    return run_cmd(["git", "-C", str(repo_path), *args])


def slug_repo(repo_id: str) -> str:
    return repo_id.replace("/", "__")


def mirror_path_for(repo_id: str, clone_dir: Path) -> Path:
    mirror_name = f"{slug_repo(repo_id)}.git"
    for mirror_dir in MIRROR_DIR_SEARCH_ORDER:
        candidate = clone_dir / mirror_dir / mirror_name
        if candidate.exists():
            return candidate
    return clone_dir / "mirrors" / mirror_name


def normalize_remote_repo_id(remote_url: str) -> str:
    text = (remote_url or "").strip()
    if not text:
        return ""
    text = text.rstrip("/")
    if text.endswith(".git"):
        text = text[:-4]
    if "://" in text:
        _, _, remainder = text.partition("://")
        _, _, path = remainder.partition("/")
        return path.strip("/")
    if ":" in text and "@" in text.split(":", 1)[0]:
        _, _, path = text.partition(":")
        return path.strip("/")
    return text.strip("/")


def infer_repo_id(repo_path: Path) -> str:
    preferred_remotes = ["upstream", "origin"]
    remote_names: list[str] = []

    code, out, _ = run_git(repo_path, "remote")
    if code == 0:
        remote_names = [line.strip() for line in out.splitlines() if line.strip()]

    for name in [*preferred_remotes, *remote_names]:
        if name not in remote_names and name not in preferred_remotes:
            continue
        code, out, _ = run_git(repo_path, "config", "--get", f"remote.{name}.url")
        if code != 0:
            continue
        repo_id = normalize_remote_repo_id(out)
        if repo_id:
            return repo_id

    fallback = repo_path.name
    if fallback.endswith(".git"):
        fallback = fallback[:-4]
    return fallback


def normalize_git_ref(ref: str) -> str:
    text = (ref or "").strip()
    if not text:
        return ""
    if text.startswith("refs/remotes/origin/"):
        return f"refs/heads/{text[len('refs/remotes/origin/'):]}"
    if text.startswith("refs/heads/"):
        return text
    if text.startswith("refs/"):
        return text
    return f"refs/heads/{text}"


def parse_iso_datetime(value: str) -> datetime | None:
    text = (value or "").strip()
    if not text:
        return None
    if text.endswith(" UTC"):
        return datetime.strptime(text, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


def normalize_iso_datetime(value: str) -> str:
    dt = parse_iso_datetime(value)
    if dt is None:
        raise RuntimeError(f"invalid ISO timestamp: {value!r}")
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_int_maybe(value: str) -> int | None:
    text = (value or "").strip()
    if not text or text == "-":
        return None
    try:
        return int(text)
    except ValueError:
        return None


def strict_before_iso(anchor_iso: str) -> str:
    dt = parse_iso_datetime(anchor_iso)
    if not dt:
        return anchor_iso
    return (dt - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")


def normalize_commit_message_text(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip())


def count_message_tokens(value: str) -> int:
    return len(re.findall(r"\S+", normalize_commit_message_text(value)))


def total_changed_lines(stats: dict[str, Any]) -> int:
    return int(stats.get("total_added_lines") or 0) + int(stats.get("total_deleted_lines") or 0)


def normalize_identity_name(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip()).casefold()


def normalize_identity_email(value: str) -> str:
    return (value or "").strip().casefold()


def identity_email_domain(value: str) -> str:
    email = normalize_identity_email(value)
    if "@" not in email:
        return ""
    return email.rsplit("@", 1)[-1]


def identity_email_is_noreply(value: str) -> bool:
    domain = identity_email_domain(value)
    local_part = normalize_identity_email(value).split("@", 1)[0]
    return bool(local_part == "noreply" or "noreply" in domain)


def identity_looks_like_bot(name: str, email: str) -> bool:
    normalized_name = normalize_identity_name(name)
    normalized_email = normalize_identity_email(email)
    local_part = normalized_email.split("@", 1)[0]
    return bool(
        normalized_name.endswith("[bot]")
        or local_part.endswith("[bot]")
        or local_part.endswith("-bot")
    )


def escape_git_basic_regex(value: str) -> str:
    escaped = (value or "").replace("\\", "\\\\")
    for char in ".[]^$*{}":
        escaped = escaped.replace(char, f"\\{char}")
    return escaped


def exact_author_email_pattern(email: str) -> str:
    text = (email or "").strip()
    if not text:
        return ""
    return escape_git_basic_regex(text)


def exact_author_name_pattern(name: str) -> str:
    text = (name or "").strip()
    if not text:
        return ""
    return rf"^{escape_git_basic_regex(text)} <"


def summarize_identity_variants(
    commits: list[dict[str, Any]],
    *,
    value_key: str,
    normalize_value,
    exclude_normalized: str,
    limit: int = 8,
) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for item in commits:
        raw_value = str(item.get(value_key, "")).strip()
        normalized_value = normalize_value(raw_value)
        if not normalized_value or normalized_value == exclude_normalized:
            continue
        entry = grouped.get(normalized_value)
        timestamp = commit_timestamp_iso(item)
        if entry is None:
            entry = {
                "value": raw_value,
                "normalized_value": normalized_value,
                "commit_count": 0,
                "first_seen_at": "",
                "previous_seen_at": "",
            }
            grouped[normalized_value] = entry
        entry["commit_count"] += 1
        if timestamp:
            if not entry["previous_seen_at"]:
                entry["previous_seen_at"] = timestamp
            entry["first_seen_at"] = timestamp
    return sorted(
        grouped.values(),
        key=lambda item: (-int(item.get("commit_count") or 0), str(item.get("value") or "")),
    )[:limit]


DOMAIN_PROVENANCE_ENV = "SIFT_DOMAIN_PROVENANCE"


def build_domain_provenance_evidence(
    repo_path: Path,
    *,
    commit_payload: dict[str, Any],
    author_identity_history: dict[str, Any],
) -> dict[str, Any] | None:
    """Did the author's email domain change hands since they started using it?

    Off unless `SIFT_DOMAIN_PROVENANCE=1`: this is the only part of case building
    that makes outbound network requests, and enabling it silently would add
    third-party egress to every existing analysis.

    Returns None when disabled or unavailable so the evidence section is *absent*
    rather than present-and-clean. A model told "provenance: clean" when the
    lookup actually failed is worse off than a model told nothing, so the four
    states are kept distinct:

        supporting   a discontinuity was found
        counter      the domain was held continuously, or the gap was committed across
        unavailable  the lookup was attempted and failed
        declined     no measurable domain (noreply address, shared mailbox provider)

    The `sift[provenance]` extra is imported lazily. Nothing in `sift.runtime` may
    import `sift.provenance` at module scope, or the base install breaks.
    """
    import os

    if (os.environ.get(DOMAIN_PROVENANCE_ENV) or "").strip() != "1":
        return None

    try:
        from sift.provenance import assess_identity
        from sift.provenance.verdict import (
            CLEAN,
            ROLE_COUNTER,
            ROLE_DECLINED,
            ROLE_UNAVAILABLE,
        )
    except ImportError as exc:
        return {
            "role": "unavailable",
            "status": "extra_not_installed",
            "detail": f"install sift[provenance] to enable ({exc})",
        }

    author_email = str(commit_payload.get("author_email", "")).strip()
    if not author_email:
        return None

    now = datetime.now(timezone.utc)
    try:
        assessment = assess_identity(
            "",
            now=now,
            emails=[author_email],
            identity_history=author_identity_history,
            repo_path=repo_path,
        )
    except Exception as exc:  # noqa: BLE001 - never let a side check break triage
        return {
            "role": ROLE_UNAVAILABLE,
            "status": "lookup_error",
            "detail": f"{type(exc).__name__}",
        }

    if assessment.declined and not assessment.verdicts:
        raw, reason = assessment.declined[0]
        return {
            "role": ROLE_DECLINED,
            "status": "no_measurable_domain",
            "detail": reason,
        }

    worst = assessment.worst
    if worst is None:
        return {
            "role": ROLE_UNAVAILABLE,
            "status": "no_candidate_domains",
            "detail": "",
        }

    gap = worst.gap_activity
    days_since_acquisition = (
        (now - worst.held_since).days if worst.held_since is not None else None
    )
    return {
        "role": worst.role,
        "status": worst.band,
        "confidence": worst.confidence,
        "domain": worst.domain,
        "registration_began_at": (
            worst.held_since.date().isoformat() if worst.held_since else ""
        ),
        "days_since_registration": days_since_acquisition,
        "identity_first_used_domain_at": (
            worst.used_since.first_seen.date().isoformat() if worst.used_since else ""
        ),
        "anchor_kind": worst.used_since.kind if worst.used_since else "",
        "anchor_strength": worst.used_since.strength if worst.used_since else "",
        "activity_across_gap": gap.verdict if gap else "",
        "commits_across_gap": gap.commits_in_gap if gap else None,
        "same_signing_key_across_gap": gap.same_signing_key if gap else None,
        "gap_activity_scope": gap.scope if gap else "",
        "corroborated_by": sorted({d.kind for d in worst.corroboration}),
        "reasons": list(worst.reasons),
        "is_counter_evidence": worst.role == ROLE_COUNTER or worst.band == CLEAN,
        # Expiry/redemption findings are deliberately excluded: they concern a
        # trusted person's future risk rather than this commit, and publishing
        # them is an attack roadmap. `sift-domain` surfaces them instead.
        "prospective_notes_withheld": len(worst.prospective),
    }


def render_domain_provenance_lines(author_identity_history: dict[str, Any]) -> list[str]:
    """Render the domain-provenance block for the model's evidence text.

    The model sees only the rendered evidence block, never the raw case JSON, so
    without these lines the `domain_provenance` evidence ref in `primary.py` would
    point at a field the model cannot read -- a silent no-op rather than a visible
    failure. An absent block renders nothing at all, which is deliberate: absent
    must not look like clean.
    """
    provenance = author_identity_history.get("domain_provenance")
    if not provenance:
        return []

    role = str(provenance.get("role") or "")
    status = str(provenance.get("status") or "")
    lines = ["", "## Author Email Domain Provenance"]

    if role in ("unavailable", "declined"):
        lines.append(
            f"- Result: {role} ({status}). This is NOT a clean result -- the check "
            f"could not answer. Do not treat it as evidence the identity is sound."
        )
        if provenance.get("detail"):
            lines.append(f"- Detail: {provenance.get('detail')}")
        return lines

    lines.append(
        f"- Result: {status} ({provenance.get('confidence') or 'unknown'} confidence), "
        f"role={role}"
    )
    lines.append(
        f"- Domain {provenance.get('domain') or '(unknown)'}: current registration began "
        f"{provenance.get('registration_began_at') or '(unknown)'}"
        + (
            f" ({provenance.get('days_since_registration')} days ago)"
            if provenance.get("days_since_registration") is not None
            else ""
        )
        + f"; identity first used it {provenance.get('identity_first_used_domain_at') or '(unknown)'}"
    )
    lines.append(
        f"- Use anchor: {provenance.get('anchor_kind') or '(none)'} "
        f"(strength {provenance.get('anchor_strength') or 'unknown'})"
    )
    if provenance.get("activity_across_gap"):
        lines.append(
            f"- Author activity across the ownership gap: "
            f"{provenance.get('activity_across_gap')} "
            f"({provenance.get('commits_across_gap')} commit(s), "
            f"same_signing_key={format_bool_unknown(provenance.get('same_signing_key_across_gap'))}, "
            f"scope={provenance.get('gap_activity_scope') or 'unknown'})"
        )
    corroborated = provenance.get("corroborated_by") or []
    lines.append(
        f"- Corroboration: {', '.join(corroborated) if corroborated else '(none available)'}"
    )
    for reason in provenance.get("reasons") or []:
        lines.append(f"- {reason}")
    if role == "counter":
        lines.append(
            "- This is counter-evidence: it argues against an account-takeover reading."
        )
    return lines


def summarize_author_identity_history(
    repo_path: Path,
    *,
    commit_payload: dict[str, Any],
    history_roots: list[str],
    observed_ref: str,
    default_branch_ref: str,
    repo_is_shallow: bool,
    max_author_history_commits: int,
) -> dict[str, Any]:
    author_name = str(commit_payload.get("author_name", "")).strip()
    author_email = str(commit_payload.get("author_email", "")).strip()
    committer_name = str(commit_payload.get("committer_name", "")).strip()
    committer_email = str(commit_payload.get("committer_email", "")).strip()

    author_name_normalized = normalize_identity_name(author_name)
    author_email_normalized = normalize_identity_email(author_email)
    committer_name_normalized = normalize_identity_name(committer_name)
    committer_email_normalized = normalize_identity_email(committer_email)
    current_author_domain = identity_email_domain(author_email)
    current_committer_domain = identity_email_domain(committer_email)

    observed_ref_normalized = normalize_git_ref(observed_ref)
    default_branch_ref_normalized = normalize_git_ref(default_branch_ref)
    baseline_revision = history_roots[0] if history_roots else ""

    if author_email_normalized:
        author_identity_basis = "email"
    elif author_name_normalized:
        author_identity_basis = "name"
    else:
        author_identity_basis = "none"

    author_email_pattern = exact_author_email_pattern(author_email)
    author_name_pattern = exact_author_name_pattern(author_name)
    committer_email_pattern = exact_author_email_pattern(committer_email)
    committer_name_pattern = exact_author_name_pattern(committer_name)

    same_email_raw = (
        load_recent_commit_summaries(
            repo_path,
            [baseline_revision],
            max_count=max_author_history_commits + 1,
            author_pattern=author_email_pattern,
        )
        if baseline_revision and author_email_pattern
        else []
    )
    same_name_raw = (
        load_recent_commit_summaries(
            repo_path,
            [baseline_revision],
            max_count=max_author_history_commits + 1,
            author_pattern=author_name_pattern,
        )
        if baseline_revision and author_name_pattern
        else []
    )
    committer_as_author_raw = (
        load_recent_commit_summaries(
            repo_path,
            [baseline_revision],
            max_count=max_author_history_commits + 1,
            author_pattern=committer_email_pattern or committer_name_pattern,
        )
        if baseline_revision and (committer_email_pattern or committer_name_pattern)
        else []
    )

    same_email_commits, same_email_truncated = truncate_bounded_window(same_email_raw, max_author_history_commits)
    same_name_commits, same_name_truncated = truncate_bounded_window(same_name_raw, max_author_history_commits)
    committer_as_author_commits, committer_as_author_truncated = truncate_bounded_window(
        committer_as_author_raw,
        max_author_history_commits,
    )

    exact_identity_commits = [
        item
        for item in same_email_commits
        if author_name_normalized
        and normalize_identity_name(item.get("author_name", "")) == author_name_normalized
    ]
    name_variants_raw = summarize_identity_variants(
        same_email_commits,
        value_key="author_name",
        normalize_value=normalize_identity_name,
        exclude_normalized=author_name_normalized,
    )
    email_variants_raw = summarize_identity_variants(
        same_name_commits,
        value_key="author_email",
        normalize_value=normalize_identity_email,
        exclude_normalized=author_email_normalized,
    )

    author_name_variants = [
        {
            "name": item["value"],
            "normalized_name": item["normalized_value"],
            "commit_count": item["commit_count"],
            "first_seen_at": item["first_seen_at"],
            "previous_seen_at": item["previous_seen_at"],
        }
        for item in name_variants_raw
    ]
    author_email_variants = [
        {
            "email": item["value"],
            "normalized_email": item["normalized_value"],
            "email_domain": identity_email_domain(item["value"]),
            "email_is_noreply": identity_email_is_noreply(item["value"]),
            "commit_count": item["commit_count"],
            "first_seen_at": item["first_seen_at"],
            "previous_seen_at": item["previous_seen_at"],
        }
        for item in email_variants_raw
    ]

    prior_email_domains = sorted(
        {
            variant["email_domain"]
            for variant in author_email_variants
            if variant.get("email_domain")
        }
    )
    domain_first_seen = None
    domain_first_seen_is_lower_bound = False
    if current_author_domain and author_email_variants:
        domain_first_seen = current_author_domain not in prior_email_domains
        domain_first_seen_is_lower_bound = bool(domain_first_seen and same_name_truncated)

    same_email_previous_seen_at = commit_timestamp_iso(same_email_commits[0]) if same_email_commits else ""
    same_name_previous_seen_at = commit_timestamp_iso(same_name_commits[0]) if same_name_commits else ""
    exact_identity_previous_seen_at = commit_timestamp_iso(exact_identity_commits[0]) if exact_identity_commits else ""

    same_email_first_seen_at = commit_timestamp_iso(same_email_commits[-1]) if same_email_commits and not same_email_truncated else ""
    same_name_first_seen_at = commit_timestamp_iso(same_name_commits[-1]) if same_name_commits and not same_name_truncated else ""
    exact_identity_first_seen_at = (
        commit_timestamp_iso(exact_identity_commits[-1])
        if exact_identity_commits and not same_email_truncated
        else ""
    )

    same_email = bool(author_email_normalized and same_email_commits)
    same_name = bool(author_name_normalized and same_name_commits)
    same_exact_identity: bool | None = None
    if author_email_normalized and author_name_normalized:
        if exact_identity_commits:
            same_exact_identity = True
        elif same_email_truncated:
            same_exact_identity = None
        else:
            same_exact_identity = False

    same_committer_email = None
    if author_email_normalized and committer_email_normalized:
        same_committer_email = author_email_normalized == committer_email_normalized
    same_committer_name = None
    if author_name_normalized and committer_name_normalized:
        same_committer_name = author_name_normalized == committer_name_normalized
    same_committer_identity = same_committer_email
    if same_committer_identity is None:
        same_committer_identity = same_committer_name

    identity_flags: list[str] = []
    if author_email_normalized and not same_email:
        identity_flags.append("author_email_first_seen_in_reachable_history")
    if author_name_normalized and not same_name:
        identity_flags.append("author_name_first_seen_in_reachable_history")
    if same_exact_identity is False:
        identity_flags.append("author_exact_identity_first_seen_in_reachable_history")
    if author_name_variants:
        identity_flags.append("author_email_seen_with_other_names")
    if author_email_variants:
        identity_flags.append("author_name_seen_with_other_emails")
    if current_author_domain and prior_email_domains and current_author_domain not in prior_email_domains:
        identity_flags.append("author_email_domain_new_for_seen_name")
    if same_committer_identity is False:
        identity_flags.append("author_committer_identity_mismatch")
    if identity_email_is_noreply(author_email):
        identity_flags.append("author_email_is_noreply")
    if identity_email_is_noreply(committer_email):
        identity_flags.append("committer_email_is_noreply")
    if identity_looks_like_bot(author_name, author_email):
        identity_flags.append("author_identity_looks_bot_like")
    if identity_looks_like_bot(committer_name, committer_email):
        identity_flags.append("committer_identity_looks_bot_like")
    if committer_as_author_commits and same_exact_identity is False and same_committer_identity is False:
        identity_flags.append("first_seen_author_identity_with_known_committer")

    history_caveats = ["reachable_history_only", "plus_addresses_not_collapsed"]
    if repo_is_shallow:
        history_caveats.append("visible_history_is_shallow")
    if observed_ref_normalized and default_branch_ref_normalized and observed_ref_normalized != default_branch_ref_normalized:
        history_caveats.append("observed_ref_differs_from_default_branch")
    if same_email_truncated:
        history_caveats.append("same_email_history_truncated")
    if same_name_truncated:
        history_caveats.append("same_name_history_truncated")
    if committer_as_author_truncated:
        history_caveats.append("committer_as_author_history_truncated")
    if author_name_normalized:
        history_caveats.append("name_based_variant_signals_can_merge_distinct_people")
    if not baseline_revision:
        history_caveats.append("no_parent_history_available")

    return {
        "history_source": "reachable_history_identity_v1",
        "baseline_ref": observed_ref_normalized or observed_ref,
        "default_branch_ref": default_branch_ref_normalized,
        "baseline_root_sha": baseline_revision,
        "identity_basis": author_identity_basis,
        "history_caveats": history_caveats,
        "current_author": {
            "name": author_name,
            "email": author_email,
            "normalized_name": author_name_normalized,
            "normalized_email": author_email_normalized,
            "email_domain": current_author_domain,
            "email_is_noreply": identity_email_is_noreply(author_email),
            "looks_bot_like": identity_looks_like_bot(author_name, author_email),
        },
        "current_committer": {
            "name": committer_name,
            "email": committer_email,
            "normalized_name": committer_name_normalized,
            "normalized_email": committer_email_normalized,
            "email_domain": current_committer_domain,
            "email_is_noreply": identity_email_is_noreply(committer_email),
            "looks_bot_like": identity_looks_like_bot(committer_name, committer_email),
        },
        "author_seen_before_exact": same_exact_identity,
        "author_name_seen_before": same_name if author_name_normalized else None,
        "author_email_seen_before": same_email if author_email_normalized else None,
        "author_exact_identity_first_seen": (not same_exact_identity) if same_exact_identity is not None else None,
        "author_email_first_seen": not same_email if author_email_normalized else None,
        "author_name_first_seen": not same_name if author_name_normalized else None,
        "author_prior_exact_identity_commits": len(exact_identity_commits),
        "author_prior_exact_identity_commits_is_lower_bound": bool(same_email_truncated and exact_identity_commits),
        "author_exact_identity_first_seen_at": exact_identity_first_seen_at,
        "author_exact_identity_previous_seen_at": exact_identity_previous_seen_at,
        "author_email_first_seen_at": same_email_first_seen_at,
        "author_email_previous_seen_at": same_email_previous_seen_at,
        "author_name_first_seen_at": same_name_first_seen_at,
        "author_name_previous_seen_at": same_name_previous_seen_at,
        "author_prior_name_variant_count": len(author_name_variants),
        "author_prior_name_variant_count_is_lower_bound": same_email_truncated,
        "author_prior_email_variant_count": len(author_email_variants),
        "author_prior_email_variant_count_is_lower_bound": same_name_truncated,
        "author_name_variants": author_name_variants,
        "author_email_variants": author_email_variants,
        "author_email_domain": current_author_domain,
        "author_prior_email_domains": prior_email_domains,
        "author_domain_first_seen": domain_first_seen,
        "author_domain_first_seen_is_lower_bound": domain_first_seen_is_lower_bound,
        "author_committer_split": {
            "same_identity": same_committer_identity,
            "same_email": same_committer_email,
            "same_name": same_committer_name,
            "committer_seen_before_as_author": bool(committer_as_author_commits),
            "committer_prior_author_commits_in_baseline": len(committer_as_author_commits),
            "committer_prior_author_commits_in_baseline_is_lower_bound": committer_as_author_truncated,
            "author_first_seen_but_committer_known": bool(
                committer_as_author_commits
                and same_exact_identity is False
                and same_committer_identity is False
            ),
        },
        "identity_flags": identity_flags,
    }


def commit_timestamp_iso(item: dict[str, Any]) -> str:
    return str(item.get("authored_at") or item.get("committed_at") or "").strip()


def commit_hour_utc(value: str) -> int | None:
    dt = parse_iso_datetime(value)
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).hour


def commit_weekday_utc(value: str) -> int | None:
    dt = parse_iso_datetime(value)
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).weekday()


def commit_timezone_offset_minutes(value: str) -> int | None:
    dt = parse_iso_datetime(value)
    if dt is None:
        return None
    offset = dt.utcoffset()
    if offset is None:
        return None
    return int(offset.total_seconds() // 60)


def round_float(value: float | int | None, *, digits: int = 3) -> float | None:
    if value is None:
        return None
    return round(float(value), digits)


def median_or_none(values: list[float | int], *, digits: int = 3) -> float | None:
    if not values:
        return None
    return round_float(median(values), digits=digits)


def pstdev_or_none(values: list[float | int], *, digits: int = 3) -> float | None:
    if len(values) < 2:
        return None
    return round_float(pstdev(values), digits=digits)


def circular_hour_distance(current_hour: int | None, prior_mode_hour: int | None) -> int | None:
    if current_hour is None or prior_mode_hour is None:
        return None
    delta = abs(current_hour - prior_mode_hour)
    return min(delta, 24 - delta)


def git_commit_exists(repo_path: Path, sha: str) -> bool:
    code, _, _ = run_git(repo_path, "cat-file", "-e", f"{sha}^{{commit}}")
    return code == 0


def git_object_exists(repo_path: Path, sha: str) -> bool:
    if not sha:
        return False
    code, _, _ = run_git(repo_path, "cat-file", "-e", f"{sha}^{{object}}")
    return code == 0


def git_repo_health(repo_path: Path) -> tuple[bool, str]:
    code, _, err = run_git(repo_path, "rev-list", "--max-count=1", "--all")
    return code == 0, err.strip()


def git_is_shallow_repository(repo_path: Path) -> bool:
    code, out, _ = run_git(repo_path, "rev-parse", "--is-shallow-repository")
    return code == 0 and out.strip() == "true"


def resolve_default_branch_ref(repo_path: Path) -> str:
    for ref_target in ("HEAD", "refs/remotes/origin/HEAD"):
        code, out, _ = run_git(repo_path, "symbolic-ref", ref_target)
        if code != 0:
            continue
        normalized = normalize_git_ref(out.strip())
        if normalized.startswith("refs/heads/"):
            return normalized
    return ""


def load_commit_header(repo_path: Path, sha: str) -> dict[str, Any]:
    fmt = "%H%x00%P%x00%an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI%x00%B"
    code, out, err = run_git(repo_path, "show", "-s", f"--format={fmt}", sha)
    if code != 0:
        raise RuntimeError(f"git show header failed for {sha} in {repo_path}: {err.strip()}")
    parts = out.split("\x00", 8)
    if len(parts) != 9:
        raise RuntimeError(f"unexpected git show header format for {sha} in {repo_path}")
    parent_shas = [item for item in parts[1].strip().split() if item]
    return {
        "sha": parts[0].strip(),
        "parent_shas": parent_shas,
        "author_name": parts[2].strip(),
        "author_email": parts[3].strip(),
        "authored_at": parts[4].strip(),
        "committer_name": parts[5].strip(),
        "committer_email": parts[6].strip(),
        "committed_at": parts[7].strip(),
        "message": parts[8].rstrip(),
    }


def _resolve_numstat_rename_path(path: str) -> tuple[str, str | None]:
    """Parse git --numstat rename notation into (new_path, old_path_or_none).

    git show --numstat renders renames as: prefix/{old => new}/suffix
    Returns the plain new_path and old_path when detected, else (path, None).
    """
    if "{" not in path or "=>" not in path:
        return path, None
    m = re.match(r"^(.*?)\{([^}]*?) => ([^}]*?)\}(.*)$", path)
    if not m:
        return path, None
    prefix, old_part, new_part, suffix = m.group(1), m.group(2), m.group(3), m.group(4)
    return f"{prefix}{new_part}{suffix}", f"{prefix}{old_part}{suffix}"


def load_numstat(repo_path: Path, sha: str, max_files: int, parent_sha: str = "") -> tuple[list[dict[str, Any]], dict[str, Any]]:
    code, out, err = run_git(repo_path, "show", "--numstat", "--format=", sha)
    if code != 0:
        raise RuntimeError(f"git show numstat failed for {sha} in {repo_path}: {err.strip()}")

    # Build change-type map from git diff-tree --name-status when parent_sha is available.
    # Maps canonical new_path -> (change_type_char, renamed_from_or_none).
    name_status_map: dict[str, tuple[str, str | None]] = {}
    if parent_sha:
        ns_code, ns_out, _ = run_git(repo_path, "diff-tree", "-r", "--name-status", parent_sha, sha)
        if ns_code == 0:
            for ns_line in ns_out.splitlines():
                ns_line = ns_line.strip()
                if not ns_line:
                    continue
                ns_parts = ns_line.split("\t")
                if len(ns_parts) < 2:
                    continue
                raw_status = ns_parts[0]
                # Normalize R100/C100 → R/C; keep first char for A/M/D/T
                status_char = raw_status[0].upper()
                if status_char in {"R", "C"} and len(ns_parts) >= 3:
                    old_path = ns_parts[1]
                    new_path = ns_parts[2]
                    name_status_map[new_path] = (status_char, old_path)
                elif len(ns_parts) >= 2:
                    name_status_map[ns_parts[1]] = (status_char, None)

    files: list[dict[str, Any]] = []
    total_added = 0
    total_deleted = 0
    binary_files = 0

    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t", 2)
        if len(parts) < 3:
            continue
        added = parse_int_maybe(parts[0])
        deleted = parse_int_maybe(parts[1])
        raw_path = parts[2]
        if added is None or deleted is None:
            binary_files += 1
        else:
            total_added += added
            total_deleted += deleted
        if len(files) < max_files:
            # Resolve rename notation in numstat path ({old => new} form).
            canonical_path, inferred_old_path = _resolve_numstat_rename_path(raw_path)
            entry: dict[str, Any] = {
                "path": canonical_path,
                "added_lines": added,
                "deleted_lines": deleted,
            }
            # Merge change_type from name-status when available.
            if name_status_map:
                status_entry = name_status_map.get(canonical_path)
                if status_entry is not None:
                    change_type_char, ns_old_path = status_entry
                    entry["change_type"] = change_type_char
                    if change_type_char == "R" and ns_old_path:
                        entry["renamed_from"] = ns_old_path
                    elif change_type_char == "R" and inferred_old_path:
                        # Fallback: use numstat-inferred old path
                        entry["renamed_from"] = inferred_old_path
            files.append(entry)

    total_files = sum(1 for line in out.splitlines() if line.strip())
    return files, {
        "files_changed": total_files,
        "files_list_truncated": len(files) < total_files,
        "total_added_lines": total_added,
        "total_deleted_lines": total_deleted,
        "binary_file_count": binary_files,
    }


def load_patch(repo_path: Path, sha: str, max_patch_chars: int) -> dict[str, Any]:
    code, out, err = run_git(repo_path, "show", "--format=", "--unified=3", sha)
    if code != 0:
        raise RuntimeError(f"git show patch failed for {sha} in {repo_path}: {err.strip()}")
    patch = out.rstrip()
    truncated = False
    if len(patch) > max_patch_chars:
        patch = patch[:max_patch_chars].rstrip() + "\n... [truncated]"
        truncated = True
    return {
        "patch": patch,
        "patch_char_count": len(out),
        "patch_truncated": truncated,
    }


def load_recent_commit_summaries(
    repo_path: Path,
    revisions: list[str],
    *,
    max_count: int,
    author_pattern: str = "",
    paths: list[str] | None = None,
) -> list[dict[str, Any]]:
    if max_count <= 0 or not revisions:
        return []

    fmt = "%H%x00%P%x00%aI%x00%cI%x00%an%x00%ae%x00%s"
    cmd = [
        "log",
        "--date-order",
        f"--max-count={max_count}",
        f"--format={fmt}",
    ]
    if author_pattern.strip():
        cmd.append(f"--author={author_pattern}")
    cmd.extend(revisions)
    if paths:
        cmd.append("--")
        cmd.extend(paths)

    code, out, err = run_git(repo_path, *cmd)
    if code != 0:
        criteria = []
        if author_pattern.strip():
            criteria.append("author filter")
        if paths:
            criteria.append("path filter")
        criteria_text = f" ({', '.join(criteria)})" if criteria else ""
        raise RuntimeError(
            f"git log summary failed for {repo_path}{criteria_text}: {err.strip()}"
        )

    summaries: list[dict[str, Any]] = []
    for line in out.splitlines():
        if not line:
            continue
        parts = (line.split("\x00", 6) + [""] * 7)[:7]
        sha, parents_raw, authored_at, committed_at, author_name, author_email, subject = parts
        parent_shas = [item for item in parents_raw.strip().split() if item]
        summaries.append(
            {
                "sha": sha.strip(),
                "short_sha": sha.strip()[:7],
                "parent_shas": parent_shas,
                "authored_at": authored_at.strip(),
                "committed_at": committed_at.strip(),
                "author_name": author_name.strip(),
                "author_email": author_email.strip(),
                "subject": subject.rstrip(),
            }
        )
    return summaries


def truncate_bounded_window(items: list[dict[str, Any]], limit: int) -> tuple[list[dict[str, Any]], bool]:
    if limit <= 0:
        return [], bool(items)
    if len(items) <= limit:
        return items, False
    return items[:limit], True


def count_recent_commits_within_minutes(
    commits: list[dict[str, Any]],
    *,
    anchor_iso: str,
    minutes: int,
    author_email: str = "",
) -> int:
    anchor_dt = parse_iso_datetime(anchor_iso)
    if anchor_dt is None:
        return 0

    author_email_norm = author_email.strip().lower()
    count = 0
    for item in commits:
        commit_dt = parse_iso_datetime(item.get("committed_at") or item.get("authored_at") or "")
        if commit_dt is None or commit_dt > anchor_dt:
            continue
        delta_minutes = (anchor_dt - commit_dt).total_seconds() / 60.0
        if not (0 <= delta_minutes <= minutes):
            continue
        if author_email_norm and (item.get("author_email") or "").strip().lower() != author_email_norm:
            continue
        count += 1
    return count


def summarize_bounded_author_history(
    raw_commits: list[dict[str, Any]],
    *,
    limit: int,
    anchor_iso: str,
) -> dict[str, Any]:
    commits, truncated = truncate_bounded_window(raw_commits, limit)
    previous_seen = commits[0]["authored_at"] if commits else ""
    first_seen = commits[-1]["authored_at"] if commits and not truncated else ""
    return {
        "count": limit if truncated else len(commits),
        "count_is_lower_bound": truncated,
        "first_seen_at": first_seen,
        "previous_seen_at": previous_seen,
        "hours_since_first_seen": hours_between(first_seen, anchor_iso) if first_seen else None,
        "hours_since_previous_seen": hours_between(previous_seen, anchor_iso) if previous_seen else None,
        "recent_commits": commits,
    }


def load_author_commit_surface_summaries(
    repo_path: Path,
    revision: str,
    *,
    author_pattern: str,
    max_count: int,
) -> list[dict[str, Any]]:
    if max_count <= 0 or not revision.strip() or not author_pattern.strip():
        return []

    fmt = "%x1e%H%x00%aI%x00%cI%x00%an%x00%ae%x00%s"
    cmd = [
        "log",
        "--first-parent",
        "--date-order",
        f"--max-count={max_count}",
        f"--author={author_pattern}",
        f"--format={fmt}",
        "--name-status",
        "--find-renames",
        revision,
    ]
    code, out, err = run_git(repo_path, *cmd)
    if code != 0:
        raise RuntimeError(f"git log surface summary failed for {repo_path}: {err.strip()}")

    summaries: list[dict[str, Any]] = []
    for raw_record in out.split("\x1e"):
        record = raw_record.strip()
        if not record:
            continue
        lines = [line.rstrip("\n") for line in record.splitlines() if line.strip()]
        if not lines:
            continue
        parts = (lines[0].split("\x00", 5) + [""] * 6)[:6]
        sha, authored_at, committed_at, author_name, author_email, subject = parts
        touched_paths: list[str] = []
        for line in lines[1:]:
            fields = [field for field in line.split("\t") if field]
            if not fields:
                continue
            status = fields[0]
            if status.startswith(("R", "C")) and len(fields) >= 3:
                touched_paths.append(fields[-1].strip())
            elif len(fields) >= 2:
                touched_paths.append(fields[-1].strip())
        summaries.append(
            {
                "sha": sha.strip(),
                "short_sha": sha.strip()[:7],
                "authored_at": authored_at.strip(),
                "committed_at": committed_at.strip(),
                "author_name": author_name.strip(),
                "author_email": author_email.strip(),
                "subject": subject.rstrip(),
                "paths": [path for path in touched_paths if path],
            }
        )
    return summaries


def load_author_commit_temporal_summaries(
    repo_path: Path,
    revision: str,
    *,
    author_pattern: str,
    max_count: int,
) -> list[dict[str, Any]]:
    if max_count <= 0 or not revision.strip() or not author_pattern.strip():
        return []

    fmt = "%x1e%H%x00%aI%x00%cI%x00%an%x00%ae%x00%B%x1f"
    cmd = [
        "log",
        "--first-parent",
        "--date-order",
        f"--max-count={max_count}",
        f"--author={author_pattern}",
        f"--format={fmt}",
        "--numstat",
        revision,
    ]
    code, out, err = run_git(repo_path, *cmd)
    if code != 0:
        raise RuntimeError(f"git log temporal summary failed for {repo_path}: {err.strip()}")

    summaries: list[dict[str, Any]] = []
    for raw_record in out.split("\x1e"):
        if not raw_record.strip():
            continue
        header_block, _, numstat_block = raw_record.partition("\x1f")
        header_text = header_block.lstrip("\n")
        if not header_text.strip():
            continue
        parts = (header_text.split("\x00", 5) + [""] * 6)[:6]
        sha, authored_at, committed_at, author_name, author_email, message = parts

        files_changed = 0
        total_added = 0
        total_deleted = 0
        binary_file_count = 0
        for line in numstat_block.splitlines():
            if not line.strip():
                continue
            fields = line.split("\t", 2)
            if len(fields) < 3:
                continue
            files_changed += 1
            added = parse_int_maybe(fields[0])
            deleted = parse_int_maybe(fields[1])
            if added is None or deleted is None:
                binary_file_count += 1
                continue
            total_added += added
            total_deleted += deleted

        summaries.append(
            {
                "sha": sha.strip(),
                "short_sha": sha.strip()[:7],
                "authored_at": authored_at.strip(),
                "committed_at": committed_at.strip(),
                "author_name": author_name.strip(),
                "author_email": author_email.strip(),
                "message": message.rstrip(),
                "stats": {
                    "files_changed": files_changed,
                    "total_added_lines": total_added,
                    "total_deleted_lines": total_deleted,
                    "binary_file_count": binary_file_count,
                },
            }
        )
    return summaries


def histogram_mode(histogram: dict[str, int]) -> tuple[int | None, int]:
    best_bucket: int | None = None
    best_count = 0
    for bucket_text in sorted(histogram, key=lambda value: int(value)):
        count = int(histogram.get(bucket_text) or 0)
        if count <= best_count:
            continue
        best_bucket = int(bucket_text)
        best_count = count
    return best_bucket, best_count


def days_between(start: str, end: str) -> float | None:
    start_dt = parse_iso_datetime(start)
    end_dt = parse_iso_datetime(end)
    if not start_dt or not end_dt:
        return None
    return round_float((end_dt - start_dt).total_seconds() / 86400.0)


def summarize_author_temporal_complexity_history(
    repo_path: Path,
    *,
    commit_payload: dict[str, Any],
    history_roots: list[str],
    observed_ref: str,
    default_branch_ref: str,
    repo_is_shallow: bool,
    max_author_history_commits: int,
) -> dict[str, Any]:
    observed_ref_normalized = normalize_git_ref(observed_ref)
    default_branch_ref_normalized = normalize_git_ref(default_branch_ref)
    if not default_branch_ref_normalized or observed_ref_normalized != default_branch_ref_normalized:
        return {}

    author_email = str(commit_payload.get("author_email", "")).strip()
    author_name = str(commit_payload.get("author_name", "")).strip()
    if author_email:
        author_pattern = exact_author_email_pattern(author_email)
        identity_basis = "email"
    elif author_name:
        author_pattern = exact_author_name_pattern(author_name)
        identity_basis = "name"
    else:
        author_pattern = ""
        identity_basis = "none"

    baseline_revision = history_roots[0] if history_roots else ""
    raw_author_commits = (
        load_author_commit_temporal_summaries(
            repo_path,
            baseline_revision,
            author_pattern=author_pattern,
            max_count=max_author_history_commits + 1,
        )
        if baseline_revision and author_pattern
        else []
    )
    author_commits, truncated = truncate_bounded_window(raw_author_commits, max_author_history_commits)
    history_is_lower_bound = bool(truncated or repo_is_shallow)

    hour_histogram = {str(hour): 0 for hour in range(24)}
    weekday_histogram = {str(day): 0 for day in range(7)}
    timezone_counts: dict[int, int] = {}
    interarrival_days: list[float] = []
    historical_commit_sizes: list[int] = []
    historical_message_to_diff_ratios: list[float] = []

    previous_author_timestamp = ""
    for index, item in enumerate(author_commits):
        authored_at = commit_timestamp_iso(item)
        hour = commit_hour_utc(authored_at)
        if hour is not None:
            hour_histogram[str(hour)] += 1
        weekday = commit_weekday_utc(authored_at)
        if weekday is not None:
            weekday_histogram[str(weekday)] += 1
        timezone_offset = commit_timezone_offset_minutes(authored_at)
        if timezone_offset is not None:
            timezone_counts[timezone_offset] = timezone_counts.get(timezone_offset, 0) + 1

        if index > 0 and previous_author_timestamp:
            gap_days = days_between(authored_at, previous_author_timestamp)
            if gap_days is not None:
                interarrival_days.append(gap_days)
        previous_author_timestamp = authored_at

        commit_size = total_changed_lines(item.get("stats") or {})
        if commit_size > 0:
            historical_commit_sizes.append(commit_size)
            historical_message_to_diff_ratios.append(
                round_float(count_message_tokens(item.get("message", "")) / commit_size, digits=6) or 0.0
            )

    current_authored_at = commit_timestamp_iso(commit_payload)
    current_hour = commit_hour_utc(current_authored_at)
    current_weekday = commit_weekday_utc(current_authored_at)
    current_timezone_offset = commit_timezone_offset_minutes(current_authored_at)
    prior_mode_hour, prior_mode_hour_count = histogram_mode(hour_histogram)
    prior_mode_weekday, prior_mode_weekday_count = histogram_mode(weekday_histogram)

    prior_mode_timezone_offset: int | None = None
    prior_mode_timezone_count = 0
    if timezone_counts:
        prior_mode_timezone_offset, prior_mode_timezone_count = min(
            timezone_counts.items(),
            key=lambda item: (-item[1], item[0]),
        )

    current_gap_since_prior_commit_days = (
        days_between(commit_timestamp_iso(author_commits[0]), current_authored_at)
        if author_commits
        else None
    )
    interarrival_median = median_or_none(interarrival_days)
    interarrival_stddev = pstdev_or_none(interarrival_days)
    cadence_shift_ratio = (
        round_float(current_gap_since_prior_commit_days / interarrival_median)
        if current_gap_since_prior_commit_days is not None and interarrival_median not in {None, 0}
        else None
    )

    current_stats = commit_payload.get("stats") or {}
    current_commit_size = total_changed_lines(current_stats)
    current_message_text = normalize_commit_message_text(commit_payload.get("message", ""))
    current_message_length = len(current_message_text)
    current_message_tokens = count_message_tokens(current_message_text)
    current_message_to_diff_ratio = (
        round_float(current_message_tokens / current_commit_size, digits=6)
        if current_commit_size > 0
        else None
    )
    historical_commit_size_median = median_or_none(historical_commit_sizes)
    historical_commit_size_stddev = pstdev_or_none(historical_commit_sizes)
    current_commit_size_ratio_to_historical_median = (
        round_float(current_commit_size / historical_commit_size_median)
        if current_commit_size > 0 and historical_commit_size_median not in {None, 0}
        else None
    )
    historical_message_to_diff_ratio_median = median_or_none(historical_message_to_diff_ratios, digits=6)

    message_to_diff_mismatch_flag = bool(
        len(historical_message_to_diff_ratios) >= 20
        and current_commit_size >= 100
        and current_message_tokens <= 4
        and current_commit_size_ratio_to_historical_median is not None
        and current_commit_size_ratio_to_historical_median >= 2.0
        and current_message_to_diff_ratio is not None
        and historical_message_to_diff_ratio_median not in {None, 0}
        and current_message_to_diff_ratio <= min(0.05, historical_message_to_diff_ratio_median * 0.25)
    )

    history_caveats = [
        "default_branch_first_parent_only",
        "authored_at_timestamps_used_for_author_baselines",
        "line_counts_exclude_binary_blob_sizes",
        "timezone_offsets_from_git_metadata",
    ]
    if repo_is_shallow:
        history_caveats.append("shallow_clone_visible_history_only")
    if truncated:
        history_caveats.append("bounded_author_history_window")

    current_timezone_prior_count = (
        timezone_counts.get(current_timezone_offset, 0)
        if current_timezone_offset is not None
        else 0
    )
    timezone_first_seen = (
        current_timezone_offset is not None
        and bool(author_commits)
        and current_timezone_prior_count == 0
    )

    return {
        "history_source": "default_branch_first_parent_visible_history_v1",
        "baseline_ref": default_branch_ref_normalized,
        "baseline_root_sha": baseline_revision,
        "identity_basis": identity_basis,
        "visible_default_branch_history_is_shallow": repo_is_shallow,
        "author_prior_commits_default_branch": max_author_history_commits if truncated else len(author_commits),
        "author_prior_commits_default_branch_is_lower_bound": history_is_lower_bound,
        "history_caveats": history_caveats,
        "temporal_distribution": {
            "author_commit_hour_histogram_utc": hour_histogram,
            "author_commit_weekday_histogram_utc": weekday_histogram,
            "current_commit_hour_utc": current_hour,
            "current_commit_weekday_utc": current_weekday,
            "current_commit_hour_prior_count": hour_histogram.get(str(current_hour), 0) if current_hour is not None else 0,
            "current_commit_weekday_prior_count": (
                weekday_histogram.get(str(current_weekday), 0)
                if current_weekday is not None
                else 0
            ),
            "prior_mode_hour_utc": prior_mode_hour,
            "prior_mode_hour_count": prior_mode_hour_count,
            "prior_mode_weekday_utc": prior_mode_weekday,
            "prior_mode_weekday_count": prior_mode_weekday_count,
            "current_commit_hour_delta_from_prior_mode_utc": circular_hour_distance(current_hour, prior_mode_hour),
        },
        "cadence": {
            "interarrival_sample_count": len(interarrival_days),
            "author_recent_interarrival_days": interarrival_days[:5],
            "author_historical_interarrival_days_median": interarrival_median,
            "author_historical_interarrival_days_stddev": interarrival_stddev,
            "current_gap_since_prior_commit_days": current_gap_since_prior_commit_days,
            "cadence_shift_ratio": cadence_shift_ratio,
        },
        "timezone": {
            "author_timezone_offsets_seen": [
                {
                    "offset_minutes": offset,
                    "count": count,
                }
                for offset, count in sorted(timezone_counts.items(), key=lambda item: (-item[1], item[0]))
            ],
            "current_timezone_offset_minutes": current_timezone_offset,
            "current_timezone_prior_count": current_timezone_prior_count,
            "prior_mode_timezone_offset_minutes": prior_mode_timezone_offset,
            "prior_mode_timezone_count": prior_mode_timezone_count,
            "timezone_first_seen": timezone_first_seen,
            "timezone_drift_from_prior_mode_minutes": (
                current_timezone_offset - prior_mode_timezone_offset
                if current_timezone_offset is not None and prior_mode_timezone_offset is not None
                else None
            ),
        },
        "complexity": {
            "commit_message_length": current_message_length,
            "commit_message_token_count": current_message_tokens,
            "diff_files_changed": current_stats.get("files_changed"),
            "diff_total_added_lines": current_stats.get("total_added_lines"),
            "diff_total_deleted_lines": current_stats.get("total_deleted_lines"),
            "diff_total_changed_lines": current_commit_size,
            "historical_commit_size_sample_count": len(historical_commit_sizes),
            "historical_commit_size_median": historical_commit_size_median,
            "historical_commit_size_stddev": historical_commit_size_stddev,
            "current_commit_size_ratio_to_historical_median": current_commit_size_ratio_to_historical_median,
            "message_to_diff_ratio_sample_count": len(historical_message_to_diff_ratios),
            "message_to_diff_ratio": current_message_to_diff_ratio,
            "historical_message_to_diff_ratio_median": historical_message_to_diff_ratio_median,
            "message_to_diff_mismatch_flag": message_to_diff_mismatch_flag,
        },
    }


_OWNERSHIP_QUERY_PATH_CLASSES = frozenset({"ci_workflow", "release_publish"})


def summarize_author_surface_history(
    repo_path: Path,
    *,
    repo_id: str,
    commit_payload: dict[str, Any],
    history_roots: list[str],
    ref: str,
    max_author_surface_commits: int,
    full_history_repo_path: Path | None = None,
) -> dict[str, Any]:
    profile = sensitive_surface_profile(repo_id)
    class_order = path_class_order(profile)
    sensitive_classes = set(profile.get("sensitive_classes", ()))
    touched_paths = [item.get("path", "") for item in commit_payload.get("files_changed", []) if item.get("path")]
    current_path_items = classify_paths(touched_paths, profile)
    current_path_classes = sorted({item["path_class"] for item in current_path_items})
    current_top_level_dirs = sorted({top_level_directory(item["path"]) for item in current_path_items})
    current_sensitive_items = [item for item in current_path_items if item["path_class"] in sensitive_classes]

    author_email = str(commit_payload.get("author_email", "")).strip()
    author_name = str(commit_payload.get("author_name", "")).strip()
    if author_email:
        author_pattern = exact_author_email_pattern(author_email)
        identity_basis = "email"
    elif author_name:
        author_pattern = exact_author_name_pattern(author_name)
        identity_basis = "name"
    else:
        author_pattern = ""
        identity_basis = "none"

    baseline_revision = history_roots[0] if history_roots else ref
    raw_author_commits = load_author_commit_surface_summaries(
        repo_path,
        baseline_revision,
        author_pattern=author_pattern,
        max_count=max_author_surface_commits + 1,
    ) if author_pattern else []
    author_commits, truncated = truncate_bounded_window(raw_author_commits, max_author_surface_commits)

    prior_counts_by_class = {path_class: 0 for path_class in class_order}
    recent_counts_by_class = {path_class: 0 for path_class in class_order}
    recent_window_commits = int(profile.get("recent_window_commits", 10))
    prior_exact_path_counts = {item["path"]: 0 for item in current_sensitive_items}
    prior_sensitive_commits_total = 0
    prior_sensitive_path_classes: set[str] = set()
    prior_top_level_dirs: set[str] = set()
    previous_sensitive_at = ""
    first_sensitive_at = ""

    for index, item in enumerate(author_commits):
        commit_path_items = classify_paths(item.get("paths", []), profile)
        commit_path_classes = sorted({entry["path_class"] for entry in commit_path_items})
        commit_top_level_dirs = {top_level_directory(entry["path"]) for entry in commit_path_items}
        prior_top_level_dirs.update(commit_top_level_dirs)
        sensitive_commit = False
        touched_path_set = {entry["path"] for entry in commit_path_items}
        for path_class in commit_path_classes:
            prior_counts_by_class[path_class] = prior_counts_by_class.get(path_class, 0) + 1
            if index < recent_window_commits:
                recent_counts_by_class[path_class] = recent_counts_by_class.get(path_class, 0) + 1
            if path_class in sensitive_classes:
                sensitive_commit = True
                prior_sensitive_path_classes.add(path_class)
        if sensitive_commit:
            prior_sensitive_commits_total += 1
            sensitive_at = item.get("authored_at") or item.get("committed_at") or ""
            if not previous_sensitive_at:
                previous_sensitive_at = sensitive_at
            first_sensitive_at = sensitive_at or first_sensitive_at
        for path in prior_exact_path_counts:
            if path in touched_path_set:
                prior_exact_path_counts[path] += 1

    current_new_path_classes = sorted(
        path_class for path_class in current_path_classes if prior_counts_by_class.get(path_class, 0) == 0
    )
    current_new_sensitive_path_classes = sorted(
        path_class for path_class in current_new_path_classes if path_class in sensitive_classes
    )
    current_new_top_level_dirs = sorted(directory for directory in current_top_level_dirs if directory not in prior_top_level_dirs)
    dominant_historical_classes = [
        path_class
        for path_class, count in sorted(
            prior_counts_by_class.items(),
            key=lambda item: (-item[1], item[0]),
        )
        if count > 0 and path_class != "other"
    ][:2]
    if dominant_historical_classes and current_new_sensitive_path_classes:
        transition_label = (
            f"{'_'.join(dominant_historical_classes)}_to_{'_'.join(current_new_sensitive_path_classes)}"
        )
    else:
        transition_label = ""
    prior_sensitive_history_exists = any(prior_counts_by_class.get(path_class, 0) > 0 for path_class in sensitive_classes)
    is_privilege_escalation_candidate = bool(
        current_new_sensitive_path_classes
        and author_commits
        and not prior_sensitive_history_exists
    )

    # Build a map from canonical path → file entry for change_type lookup.
    files_changed_by_path: dict[str, dict[str, Any]] = {
        str(f.get("path", "")): f
        for f in (commit_payload.get("files_changed") or [])
        if f.get("path")
    }

    # Parent SHA for ownership queries (first parent only).
    parent_shas = [p for p in (commit_payload.get("parent_shas") or []) if p]
    query_parent_sha = parent_shas[0] if parent_shas else ""

    sensitive_surface_hits: list[dict[str, Any]] = []
    for item in current_sensitive_items:
        path = item["path"]
        path_class = item["path_class"]
        prior_exact_touches = prior_exact_path_counts.get(path, 0)
        prior_class_touches = prior_counts_by_class.get(path_class, 0)
        hit: dict[str, Any] = {
            "path": path,
            "path_class": path_class,
            "author_prior_touches_exact_path": prior_exact_touches,
            "author_prior_touches_same_class": prior_class_touches,
            "exact_path_first_touch": prior_exact_touches == 0,
            "class_first_touch": prior_class_touches == 0,
        }

        # Enrich with change_type and ownership facts for target path classes.
        file_entry = files_changed_by_path.get(path)
        change_type: str | None = None
        renamed_from: str | None = None
        if file_entry is not None:
            change_type = file_entry.get("change_type")
            renamed_from = file_entry.get("renamed_from")

        if change_type is not None:
            hit["change_type"] = change_type
            if renamed_from is not None:
                hit["renamed_from"] = renamed_from
            # file_seen_before_commit: True for M/R/D (existed), False for A (new)
            if change_type in {"M", "R", "D"}:
                hit["file_seen_before_commit"] = True
            elif change_type == "A":
                hit["file_seen_before_commit"] = False

        # Ownership query for ci_workflow and release_publish only.
        if (
            path_class in _OWNERSHIP_QUERY_PATH_CLASSES
            and full_history_repo_path is not None
            and query_parent_sha
        ):
            # For renames, query the old path to avoid a false "never-touched" conclusion.
            # If the file is a rename and we have renamed_from, query that path.
            # However, treat results from renamed_from queries as potentially incomplete
            # (different path = different ownership history). Per conservative policy,
            # only use renamed_from query if change_type is R and renamed_from is available;
            # but do not apply the anomaly rendering gate to rename cases (handled in render).
            query_path = path
            is_rename_query = False
            if change_type == "R" and renamed_from:
                query_path = renamed_from
                is_rename_query = True

            author_email = str(commit_payload.get("author_email", "")).strip().casefold()
            ownership = query_sensitive_path_owners(
                full_history_repo_path,
                query_parent_sha,
                query_path,
                author_email,
            )
            if ownership is not None:
                hit["prior_human_authors_count"] = ownership["prior_human_authors_count"]
                hit["top_human_owners"] = ownership["top_human_owners"]
                hit["top_human_author_share"] = ownership["top_human_author_share"]
                hit["ownership_concentration"] = ownership["ownership_concentration"]
                hit["ownership_match_basis"] = ownership["ownership_match_basis"]
                if is_rename_query:
                    hit["ownership_queried_path"] = query_path

        sensitive_surface_hits.append(hit)

    return {
        "history_source": "default_branch_first_parent_v1",
        "profile_version": profile.get("profile_version", ""),
        "baseline_ref": ref,
        "baseline_root_sha": baseline_revision,
        "identity_basis": identity_basis,
        "author_prior_commits_default_branch": max_author_surface_commits if truncated else len(author_commits),
        "author_prior_commits_default_branch_is_lower_bound": truncated,
        "author_prior_sensitive_commits_total": prior_sensitive_commits_total,
        "author_prior_sensitive_commits_total_is_lower_bound": truncated,
        "author_prior_sensitive_path_classes": sorted(prior_sensitive_path_classes),
        "author_current_commit_path_classes": current_path_classes,
        "author_current_new_path_classes": current_new_path_classes,
        "author_current_new_sensitive_path_classes": current_new_sensitive_path_classes,
        "author_first_sensitive_touch_at": first_sensitive_at,
        "author_previous_sensitive_touch_at": previous_sensitive_at,
        "author_prior_commits_by_path_class": prior_counts_by_class,
        "author_recent_commits_by_path_class": {
            "window_commits": min(recent_window_commits, len(author_commits)),
            **recent_counts_by_class,
        },
        "sensitive_surface_hits": sensitive_surface_hits,
        "author_role_transition": {
            "dominant_historical_classes": dominant_historical_classes,
            "new_classes_in_current_commit": current_new_path_classes,
            "new_sensitive_classes_in_current_commit": current_new_sensitive_path_classes,
            "transition_label": transition_label,
            "is_privilege_escalation_candidate": is_privilege_escalation_candidate,
        },
        "author_prior_top_level_dirs_count": len(prior_top_level_dirs),
        "author_current_top_level_dirs": current_top_level_dirs,
        "author_current_new_top_level_dirs": current_new_top_level_dirs,
        "sensitive_surface_profile": {
            "sensitive_classes": list(profile.get("sensitive_classes", ())),
        },
    }


def build_realtime_history_features(
    repo_path: Path,
    commit_payload: dict[str, Any],
    *,
    repo_id: str,
    ref: str,
    observed_at: str,
    max_author_commits: int,
    max_path_commits: int,
    max_paths_for_history: int,
    max_ref_history_commits: int,
    max_author_surface_commits: int,
    full_history_repo_path: Path | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    history_roots = [item for item in commit_payload.get("parent_shas", []) if item]
    anchor_iso = observed_at
    default_branch_ref = resolve_default_branch_ref(repo_path)
    repo_is_shallow = git_is_shallow_repository(repo_path)

    ref_history_raw = load_recent_commit_summaries(
        repo_path,
        history_roots,
        max_count=max_ref_history_commits + 1,
    )
    recent_ref_history, ref_history_truncated = truncate_bounded_window(ref_history_raw, max_ref_history_commits)

    email_pattern = exact_author_email_pattern(commit_payload.get("author_email", "").strip())
    name_pattern = exact_author_name_pattern(commit_payload.get("author_name", "").strip())
    same_email_raw = (
        load_recent_commit_summaries(
            repo_path,
            history_roots,
            max_count=max_author_commits + 1,
            author_pattern=email_pattern,
        )
        if email_pattern
        else []
    )
    same_name_raw = (
        load_recent_commit_summaries(
            repo_path,
            history_roots,
            max_count=max_author_commits + 1,
            author_pattern=name_pattern,
        )
        if name_pattern
        else []
    )
    same_email = summarize_bounded_author_history(
        same_email_raw,
        limit=max_author_commits,
        anchor_iso=anchor_iso,
    )
    same_name = summarize_bounded_author_history(
        same_name_raw,
        limit=max_author_commits,
        anchor_iso=anchor_iso,
    )
    author_identity_history = summarize_author_identity_history(
        repo_path,
        commit_payload=commit_payload,
        history_roots=history_roots,
        observed_ref=ref,
        default_branch_ref=default_branch_ref,
        repo_is_shallow=repo_is_shallow,
        max_author_history_commits=max_author_surface_commits,
    )
    domain_provenance = build_domain_provenance_evidence(
        repo_path,
        commit_payload=commit_payload,
        author_identity_history=author_identity_history,
    )
    if domain_provenance is not None:
        author_identity_history["domain_provenance"] = domain_provenance
    author_temporal_complexity_history = summarize_author_temporal_complexity_history(
        repo_path,
        commit_payload=commit_payload,
        history_roots=history_roots,
        observed_ref=ref,
        default_branch_ref=default_branch_ref,
        repo_is_shallow=repo_is_shallow,
        max_author_history_commits=max_author_surface_commits,
    )
    author_surface_history = summarize_author_surface_history(
        repo_path,
        repo_id=repo_id,
        commit_payload=commit_payload,
        history_roots=history_roots,
        ref=ref,
        max_author_surface_commits=max_author_surface_commits,
        full_history_repo_path=full_history_repo_path,
    )

    touched_paths = [item.get("path", "") for item in commit_payload.get("files_changed", []) if item.get("path")]
    sampled_paths = touched_paths[:max_paths_for_history]
    path_recent_touches: list[dict[str, Any]] = []
    for path in sampled_paths:
        raw_history = load_recent_commit_summaries(
            repo_path,
            history_roots,
            max_count=max_path_commits + 1,
            paths=[path],
        )
        recent_commits, truncated = truncate_bounded_window(raw_history, max_path_commits)
        path_recent_touches.append(
            {
                "path": path,
                "recent_touch_count": max_path_commits if truncated else len(recent_commits),
                "recent_touch_count_is_lower_bound": truncated,
                "recent_commits": recent_commits,
            }
        )

    history = {
        "anchor_timestamp_utc": anchor_iso,
        "history_cutoff_utc": anchor_iso,
        "repo_commit_count_before": None,
        "author_prior_commits_same_email": same_email["count"],
        "author_prior_commits_same_email_is_lower_bound": same_email["count_is_lower_bound"],
        "author_prior_commits_same_name": same_name["count"],
        "author_prior_commits_same_name_is_lower_bound": same_name["count_is_lower_bound"],
        "author_first_seen_same_email_at": same_email["first_seen_at"],
        "author_previous_commit_same_email_at": same_email["previous_seen_at"],
        "author_first_seen_same_name_at": same_name["first_seen_at"],
        "author_previous_commit_same_name_at": same_name["previous_seen_at"],
        "hours_since_author_first_seen_same_email": same_email["hours_since_first_seen"],
        "hours_since_author_previous_commit_same_email": same_email["hours_since_previous_seen"],
        "hours_since_author_first_seen_same_name": same_name["hours_since_first_seen"],
        "hours_since_author_previous_commit_same_name": same_name["hours_since_previous_seen"],
        "history_scope": {
            "mode": "bounded_realtime_v1",
            "observed_ref": ref,
            "observed_at_utc": observed_at,
            "history_roots": history_roots,
            "default_branch_ref": default_branch_ref,
            "observed_ref_is_default_branch": bool(default_branch_ref and normalize_git_ref(ref) == default_branch_ref),
            "visible_history_is_shallow": repo_is_shallow,
            "author_history_limit": max_author_commits,
            "author_surface_history_limit": max_author_surface_commits,
            "author_identity_history_limit": max_author_surface_commits,
            "author_temporal_complexity_history_limit": max_author_surface_commits,
            "path_history_limit": max_path_commits,
            "ref_history_limit": max_ref_history_commits,
            "path_history_paths_considered": len(sampled_paths),
            "path_history_paths_truncated": len(sampled_paths) < len(touched_paths),
            "ref_history_truncated": ref_history_truncated,
        },
        "recent_ref_history": recent_ref_history,
        "recent_ref_history_truncated": ref_history_truncated,
        "author_recent_commits_same_email": same_email["recent_commits"],
        "author_recent_commits_same_name": same_name["recent_commits"],
        "author_identity_history": author_identity_history,
        "author_temporal_complexity_history": author_temporal_complexity_history,
        "author_surface_history": author_surface_history,
        "path_recent_touches": path_recent_touches,
    }
    return history, recent_ref_history


def observed_event_from_commit_summary(summary: dict[str, Any], *, repo_id: str, ref: str) -> dict[str, Any]:
    parent_shas = [item for item in summary.get("parent_shas", []) if item]
    return {
        "source_file": "realtime_ref_history",
        "created_at_utc": summary.get("committed_at") or summary.get("authored_at") or "",
        "actor_id": "",
        "actor_login": "",
        "repo_id": "",
        "repo_name": repo_id,
        "ref": ref,
        "push_before_sha": parent_shas[0] if parent_shas else "",
        "push_head_sha": summary.get("sha", ""),
        "push_size": 1,
        "push_distinct_size": 1,
        "forced_push": None,
        "commit_sha": summary.get("sha", ""),
        "commit_author_name": summary.get("author_name", ""),
        "commit_author_email": summary.get("author_email", ""),
        "commit_message": summary.get("subject", ""),
        "commit_distinct": True,
        "commit_api_url": "",
        "observation_source": "commit_history_estimate",
    }


def build_realtime_observation_context(
    repo_path: Path,
    repo_id: str,
    commit_payload: dict[str, Any],
    *,
    ref: str,
    observed_at: str,
    recent_ref_history: list[dict[str, Any]],
) -> dict[str, Any]:
    parent_shas = [item for item in commit_payload.get("parent_shas", []) if item]
    previous_commit = recent_ref_history[0] if recent_ref_history else None
    cadence_anchor = commit_payload.get("committed_at") or observed_at
    previous_commit_at = ""
    if previous_commit:
        previous_commit_at = previous_commit.get("committed_at") or previous_commit.get("authored_at") or ""

    return {
        "target_push_event": {
            "source_file": "realtime_observation",
            "created_at_utc": observed_at,
            "actor_id": "",
            "actor_login": "",
            "repo_id": "",
            "repo_name": repo_id,
            "ref": ref,
            "push_before_sha": parent_shas[0] if parent_shas else "",
            "push_head_sha": commit_payload.get("sha", ""),
            "push_size": 1,
            "push_distinct_size": 1,
            "forced_push": None,
            "commit_sha": commit_payload.get("sha", ""),
            "commit_author_name": commit_payload.get("author_name", ""),
            "commit_author_email": commit_payload.get("author_email", ""),
            "commit_message": commit_payload.get("message", ""),
            "commit_distinct": True,
            "commit_api_url": "",
        },
        "repo_event_window": {
            "previous_push": (
                observed_event_from_commit_summary(previous_commit, repo_id=repo_id, ref=ref)
                if previous_commit
                else None
            ),
            "next_push": None,
            "surrounding_pushes_same_repo": [],
        },
        "repo_push_timing": {
            "minutes_since_previous_repo_push": (
                minutes_between(previous_commit_at, cadence_anchor) if previous_commit_at else None
            ),
            "minutes_until_next_repo_push": None,
            "repo_pushes_by_same_actor_prev_1h": count_recent_commits_within_minutes(
                recent_ref_history,
                anchor_iso=cadence_anchor,
                minutes=60,
                author_email=commit_payload.get("author_email", ""),
            ),
            "repo_pushes_by_same_actor_next_1h": None,
            "repo_pushes_prev_1h": count_recent_commits_within_minutes(
                recent_ref_history,
                anchor_iso=cadence_anchor,
                minutes=60,
            ),
            "repo_pushes_next_1h": None,
            "timing_source": "commit_history_estimate",
        },
        "mirror_rewrite_signals": {
            "mirror_healthy": True,
            "commit_present_in_current_mirror": True,
            "push_head_present_in_current_mirror": True,
            "push_before_present_in_current_mirror": (
                git_object_exists(repo_path, parent_shas[0]) if parent_shas else False
            ),
            "target_commit_missing_after_observation": False,
            "push_head_missing_after_observation": False,
        },
        "fallback_metadata": {
            "push_created_at_utc": observed_at,
            "actor_login": "",
            "source_file": "realtime_observation",
        },
    }


def format_history_count(count: Any, lower_bound: bool, *, bounded_window: bool = False) -> str:
    if count is None or count == "":
        return str(count)
    prefix = ">=" if lower_bound else ""
    suffix = " seen in bounded window" if bounded_window else ""
    return f"{prefix}{count}{suffix}"


def count_repo_commits_before(repo_path: Path, anchor_iso: str) -> int | None:
    code, out, err = run_git(repo_path, "rev-list", "--count", "--all", f"--before={anchor_iso}")
    if code != 0:
        return None
    try:
        return int(out.strip())
    except ValueError as exc:
        raise RuntimeError(f"git rev-list count returned non-integer for {repo_path}: {err.strip()}") from exc


def author_history_before(repo_path: Path, anchor_iso: str, sha_to_exclude: str, author_pattern: str) -> tuple[int | None, str, str]:
    if not author_pattern.strip():
        return None, "", ""
    code, out, _ = run_git(
        repo_path,
        "log",
        "--all",
        "--format=%H%x00%aI",
        f"--before={anchor_iso}",
        f"--author={author_pattern}",
    )
    if code != 0:
        return None, "", ""

    first_seen = ""
    previous_seen = ""
    count = 0
    for line in out.splitlines():
        if not line:
            continue
        sha, authored_at = (line.split("\x00", 1) + [""])[:2]
        sha = sha.strip()
        authored_at = authored_at.strip()
        if sha == sha_to_exclude:
            continue
        count += 1
        if not previous_seen:
            previous_seen = authored_at
        first_seen = authored_at
    return count, first_seen, previous_seen


def hours_between(start: str, end: str) -> float | None:
    start_dt = parse_iso_datetime(start)
    end_dt = parse_iso_datetime(end)
    if not start_dt or not end_dt:
        return None
    delta = end_dt - start_dt
    return round(delta.total_seconds() / 3600.0, 3)


def build_history_features(
    repo_path: Path,
    anchor_iso: str,
    sha_to_exclude: str,
    author_name: str,
    author_email: str,
) -> dict[str, Any]:
    history_cutoff_iso = strict_before_iso(anchor_iso)
    email_pattern = exact_author_email_pattern(author_email.strip())
    name_pattern = exact_author_name_pattern(author_name.strip())

    prior_same_email, first_same_email, previous_same_email = author_history_before(
        repo_path, history_cutoff_iso, sha_to_exclude, email_pattern
    )
    prior_same_name, first_same_name, previous_same_name = author_history_before(
        repo_path, history_cutoff_iso, sha_to_exclude, name_pattern
    )

    return {
        "anchor_timestamp_utc": anchor_iso,
        "history_cutoff_utc": history_cutoff_iso,
        "repo_commit_count_before": count_repo_commits_before(repo_path, history_cutoff_iso),
        "author_prior_commits_same_email": prior_same_email,
        "author_prior_commits_same_name": prior_same_name,
        "author_first_seen_same_email_at": first_same_email,
        "author_previous_commit_same_email_at": previous_same_email,
        "author_first_seen_same_name_at": first_same_name,
        "author_previous_commit_same_name_at": previous_same_name,
        "hours_since_author_first_seen_same_email": hours_between(first_same_email, anchor_iso),
        "hours_since_author_previous_commit_same_email": hours_between(previous_same_email, anchor_iso),
        "hours_since_author_first_seen_same_name": hours_between(first_same_name, anchor_iso),
        "hours_since_author_previous_commit_same_name": hours_between(previous_same_name, anchor_iso),
    }


def commit_anchor_iso(commit_header: dict[str, Any] | None, truth: GroundTruthCommit) -> str:
    if commit_header and commit_header.get("committed_at"):
        return commit_header["committed_at"]
    if truth.gharchive_push_created_at:
        dt = parse_iso_datetime(truth.gharchive_push_created_at)
        if dt:
            return dt.isoformat().replace("+00:00", "Z")
    raise RuntimeError(f"could not determine anchor timestamp for {truth.repo} {truth.sha}")


def minutes_between(start: str, end: str) -> float | None:
    start_dt = parse_iso_datetime(start)
    end_dt = parse_iso_datetime(end)
    if not start_dt or not end_dt:
        return None
    return round((end_dt - start_dt).total_seconds() / 60.0, 3)


def serialize_gharchive_event(event: GHArchivePushEvent | None) -> dict[str, Any] | None:
    if event is None:
        return None
    return {
        "source_file": event.source_file,
        "created_at_utc": event.created_at,
        "actor_id": event.actor_id,
        "actor_login": event.actor_login,
        "repo_id": event.repo_id,
        "repo_name": event.repo_name,
        "ref": event.ref,
        "push_before_sha": event.push_before_sha,
        "push_head_sha": event.push_head_sha,
        "push_size": event.push_size,
        "push_distinct_size": event.push_distinct_size,
        "forced_push": event.forced_push,
        "commit_sha": event.commit_sha,
        "commit_author_name": event.commit_author_name,
        "commit_author_email": event.commit_author_email,
        "commit_message": event.commit_message,
        "commit_distinct": event.commit_distinct,
        "commit_api_url": event.commit_api_url,
    }


def build_gharchive_context(
    truth: GroundTruthCommit,
    repo_path: Path,
    repo_healthy: bool,
    commit_present: bool,
    event_lookup: GHArchiveEventLookup,
    events_by_repo: GHArchiveEventsByRepo,
) -> dict[str, Any]:
    event = event_lookup.get((truth.repo, truth.sha))
    repo_events = events_by_repo.get(truth.repo, [])

    if event is None:
        return {
            "target_push_event": None,
            "repo_event_window": {
                "previous_push": None,
                "next_push": None,
                "surrounding_pushes_same_repo": [],
            },
            "repo_push_timing": {
                "minutes_since_previous_repo_push": None,
                "minutes_until_next_repo_push": None,
                "repo_pushes_by_same_actor_prev_1h": None,
                "repo_pushes_by_same_actor_next_1h": None,
                "repo_pushes_prev_1h": None,
                "repo_pushes_next_1h": None,
            },
            "mirror_rewrite_signals": {
                "mirror_healthy": repo_healthy,
                "commit_present_in_current_mirror": commit_present,
                "push_head_present_in_current_mirror": git_object_exists(repo_path, truth.sha) if repo_path.exists() and repo_healthy else False,
                "push_before_present_in_current_mirror": False,
                "target_commit_missing_after_observation": (not commit_present) if repo_healthy else None,
                "push_head_missing_after_observation": (not commit_present) if repo_healthy else None,
            },
            "fallback_metadata": {
                "push_created_at_utc": truth.gharchive_push_created_at,
                "actor_login": truth.gharchive_actor_login,
                "source_file": truth.gharchive_file,
            },
        }

    idx = next((i for i, item in enumerate(repo_events) if item.commit_sha == truth.sha), None)
    previous_event = repo_events[idx - 1] if idx is not None and idx > 0 else None
    next_event = repo_events[idx + 1] if idx is not None and idx + 1 < len(repo_events) else None
    surrounding = repo_events[max(0, (idx or 0) - 2): (idx or 0) + 3] if idx is not None else []

    target_dt = parse_iso_datetime(event.created_at)
    prev_1h_same_repo = 0
    next_1h_same_repo = 0
    prev_1h_same_actor = 0
    next_1h_same_actor = 0
    if target_dt is not None:
        for other in repo_events:
            if other.commit_sha == truth.sha and other.created_at == event.created_at:
                continue
            other_dt = parse_iso_datetime(other.created_at)
            if other_dt is None:
                continue
            delta_minutes = (other_dt - target_dt).total_seconds() / 60.0
            if -60 <= delta_minutes < 0:
                prev_1h_same_repo += 1
                if other.actor_login == event.actor_login:
                    prev_1h_same_actor += 1
            elif 0 < delta_minutes <= 60:
                next_1h_same_repo += 1
                if other.actor_login == event.actor_login:
                    next_1h_same_actor += 1

    push_before_present = git_object_exists(repo_path, event.push_before_sha) if repo_path.exists() and repo_healthy else False
    push_head_present = git_object_exists(repo_path, event.push_head_sha) if repo_path.exists() and repo_healthy else False

    return {
        "target_push_event": serialize_gharchive_event(event),
        "repo_event_window": {
            "previous_push": serialize_gharchive_event(previous_event),
            "next_push": serialize_gharchive_event(next_event),
            "surrounding_pushes_same_repo": [serialize_gharchive_event(item) for item in surrounding],
        },
        "repo_push_timing": {
            "minutes_since_previous_repo_push": minutes_between(previous_event.created_at, event.created_at) if previous_event else None,
            "minutes_until_next_repo_push": minutes_between(event.created_at, next_event.created_at) if next_event else None,
            "repo_pushes_by_same_actor_prev_1h": prev_1h_same_actor,
            "repo_pushes_by_same_actor_next_1h": next_1h_same_actor,
            "repo_pushes_prev_1h": prev_1h_same_repo,
            "repo_pushes_next_1h": next_1h_same_repo,
        },
        "mirror_rewrite_signals": {
            "mirror_healthy": repo_healthy,
            "commit_present_in_current_mirror": commit_present,
            "push_head_present_in_current_mirror": push_head_present,
            "push_before_present_in_current_mirror": push_before_present,
            "previous_push_head_present_in_current_mirror": (
                git_object_exists(repo_path, previous_event.push_head_sha)
                if previous_event and repo_path.exists() and repo_healthy
                else False
            ),
            "next_push_head_present_in_current_mirror": (
                git_object_exists(repo_path, next_event.push_head_sha)
                if next_event and repo_path.exists() and repo_healthy
                else False
            ),
            "target_commit_missing_after_observation": (not commit_present) if repo_healthy else None,
            "push_head_missing_after_observation": (not push_head_present) if repo_healthy else None,
        },
        "fallback_metadata": {
            "push_created_at_utc": truth.gharchive_push_created_at,
            "actor_login": truth.gharchive_actor_login,
            "source_file": truth.gharchive_file,
        },
    }


def classify_evidence_state(
    *,
    repo_exists: bool,
    repo_healthy: bool,
    commit_present: bool,
    gharchive_context: dict[str, Any],
) -> str:
    if repo_exists and not repo_healthy:
        return "mirror_unhealthy_unknown"

    target_push = gharchive_context.get("target_push_event")
    rewrite = gharchive_context.get("mirror_rewrite_signals", {})

    if repo_exists and repo_healthy and commit_present:
        return "present_in_healthy_mirror"

    if target_push:
        has_surrounding_anchor = any(
            (
                rewrite.get("push_before_present_in_current_mirror"),
                rewrite.get("previous_push_head_present_in_current_mirror"),
                rewrite.get("next_push_head_present_in_current_mirror"),
            )
        )
        if repo_exists and repo_healthy and not commit_present and has_surrounding_anchor:
            return "observed_in_event_log_missing_from_healthy_mirror"
        return "observed_in_event_log_not_captured_in_mirror"

    if repo_exists and repo_healthy:
        return "present_in_healthy_mirror" if commit_present else "healthy_mirror_without_event_log"

    if not repo_exists:
        return "event_log_only_no_local_mirror"

    return "unknown_evidence_state"


def prior_pushes_for_realtime_prompt(event_window: dict[str, Any], target_created_at: str) -> list[dict[str, Any]]:
    target_dt = parse_iso_datetime(target_created_at)
    selected: list[dict[str, Any]] = []
    for item in event_window.get("surrounding_pushes_same_repo", []):
        item_dt = parse_iso_datetime(item.get("created_at_utc") or "")
        if target_dt is not None and item_dt is not None and item_dt > target_dt:
            continue
        selected.append(item)
    return selected


def format_weekday_label(value: int | None) -> str:
    if value is None or value < 0 or value >= len(WEEKDAY_NAMES):
        return "(unknown)"
    return f"{WEEKDAY_NAMES[value]}({value})"


def format_top_histogram_buckets(histogram: dict[str, int], *, label_map: dict[int, str] | None = None, limit: int = 4) -> str:
    entries = [
        (int(bucket), int(count))
        for bucket, count in histogram.items()
        if int(count or 0) > 0
    ]
    if not entries:
        return "(none)"
    rendered: list[str] = []
    for bucket, count in sorted(entries, key=lambda item: (-item[1], item[0]))[:limit]:
        label = label_map.get(bucket, str(bucket)) if label_map else str(bucket)
        rendered.append(f"{label}={count}")
    return ", ".join(rendered)


def format_timezone_offset_minutes(value: int | None) -> str:
    if value is None:
        return "(unknown)"
    sign = "+" if value >= 0 else "-"
    absolute = abs(value)
    hours, minutes = divmod(absolute, 60)
    return f"{sign}{hours:02d}:{minutes:02d} ({value}m)"


def format_timezone_offset_counts(items: list[dict[str, Any]], *, limit: int = 4) -> str:
    if not items:
        return "(none)"
    rendered: list[str] = []
    for item in items[:limit]:
        rendered.append(
            f"{format_timezone_offset_minutes(item.get('offset_minutes'))}={item.get('count')}"
        )
    return ", ".join(rendered)


def format_bool_unknown(value: Any) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "(unknown)"


def format_identity_variants(items: list[dict[str, Any]], value_key: str, *, limit: int = 4) -> str:
    if not items:
        return "(none)"
    rendered: list[str] = []
    for item in items[:limit]:
        rendered.append(f"{item.get(value_key)}={item.get('commit_count')}")
    return ", ".join(rendered)


def render_agent_prompt(case: CommitCase, gharchive_mode: str, temporal_mode: str) -> str:
    commit = case["commit"]
    history = case["history_before_commit"]
    history_scope = history.get("history_scope") or {}
    files_changed = commit.get("files_changed", [])
    gharchive = case["gharchive_context"]
    target_push = gharchive.get("target_push_event") or {}
    timing = gharchive.get("repo_push_timing") or {}
    rewrite = gharchive.get("mirror_rewrite_signals") or {}
    event_window = gharchive.get("repo_event_window") or {}
    mirror_commit_available = bool(case.get("feature_availability", {}).get("mirror_commit"))
    author_text = f"{commit.get('author_name', '')} <{commit.get('author_email', '')}>".strip()
    if not author_text or author_text == "<>":
        author_text = "(unknown)"
    if mirror_commit_available:
        committer_text = f"{commit.get('committer_name', '')} <{commit.get('committer_email', '')}>".strip()
        if not committer_text or committer_text == "<>":
            committer_text = "(unknown)"
        authored_at_text = commit.get("authored_at", "") or "(unknown)"
        committed_at_text = commit.get("committed_at", "") or "(unknown)"
        parent_count_text = str(len(commit.get("parent_shas", [])))
    else:
        if temporal_mode == "realtime":
            unavailable_text = "(unavailable in replay evidence)"
        else:
            unavailable_text = "(unknown from GH Archive recovery)"
        committer_text = unavailable_text
        authored_at_text = unavailable_text
        committed_at_text = unavailable_text
        parent_count_text = unavailable_text

    lines: list[str] = []
    if temporal_mode == "realtime":
        lines.append("You are triaging a single newly observed commit for potential supply-chain risk.")
        lines.append("Use only evidence that would have been available at first observation.")
    else:
        lines.append("You are triaging a single commit for potential supply-chain risk.")
    lines.append('Classify it as either "suspicious" or "benign" based only on the evidence below.')
    lines.append("Focus on commit-level behavioral signals: author history, identity consistency,")
    lines.append("file targets, dependency or build changes, and suspicious code or shell/network primitives.")
    lines.append("When the diff adds or wires in a new external dependency, treat that as a strong signal even")
    lines.append("if the push cadence looks normal or the author already has some prior commits.")
    lines.append("")
    lines.append("Decision rubric:")
    lines.append("- Strong suspicious signals: new runtime dependency introduction, exported API wired to a new dependency,")
    lines.append("  high-impact diff hidden behind a trivial message, rewrite/disappearance from a healthy mirror,")
    lines.append("  new or inconsistent author identity, or sensitive build/dependency file changes.")
    lines.append("- Weak exculpatory signals: normal push cadence, non-forced push, prior contributions, and presence of tests.")
    lines.append("  These do not clear a risky dependency introduction because the payload may live in the added dependency.")
    lines.append("- If the evidence state is mirror_unhealthy_unknown or the diff is unavailable, do not treat local corruption")
    lines.append("  alone as malicious. Use the observed push sequence and identity signals instead.")
    lines.append("- For GH Archive-only recovery, missing committer fields, missing timestamps, or unknown parent counts are")
    lines.append("  incomplete-evidence artifacts, not suspicious facts by themselves. Author vs push-actor mismatch is common")
    lines.append("  on collaborative repositories and only matters when combined with stronger anomalies.")
    lines.append("- Treat obviously placeholder or fabricated-looking author identity (for example generic names,")
    lines.append("  `example.com` addresses, or hash-like placeholder emails) plus trivial/generic commit messages as")
    lines.append("  a strong suspicious signal, especially when such commits appear in a short burst on the default branch.")
    lines.append("- Prefer benign only when the evidence supports an ordinary maintenance/change pattern and no strong")
    lines.append("  supply-chain signal is present.")
    lines.append("- PR/social metadata is supporting evidence only. It is not a source of truth for maliciousness.")
    lines.append("")
    lines.append("## Commit")
    lines.append(f"- Repo: {case['repo']}")
    if temporal_mode == "realtime":
        lines.append("- Commit SHA: (withheld for benchmark hygiene)")
    else:
        lines.append(f"- Commit SHA: {case['commit_sha']}")
    if gharchive_mode == "full" and temporal_mode == "retrospective":
        lines.append(f"- Recovery source: {case['recovery_source']}")
        lines.append(f"- Evidence state: {case['evidence_state']}")
    if case.get("mirror_error"):
        lines.append(f"- Current mirror error: {case['mirror_error']}")
    lines.append(f"- Author: {author_text}")
    lines.append(f"- Committer: {committer_text}")
    lines.append(f"- Authored at: {authored_at_text}")
    lines.append(f"- Committed at: {committed_at_text}")
    lines.append(f"- Parent count: {parent_count_text}")
    lines.append(f"- Message: {json.dumps(commit.get('message', ''))}")
    lines.append("")
    lines.append("## History Before This Commit")
    if history_scope.get("mode"):
        lines.append(f"- History mode: {history_scope.get('mode')}")
    bounded_window = str(history_scope.get("mode") or "").startswith("bounded_")
    if bounded_window:
        lines.append("- Author history counters below are seen in the current bounded window, not full-repo history.")
    lines.append(f"- Repo commit count before anchor: {history.get('repo_commit_count_before')}")
    lines.append(
        f"- Prior commits by same email: {format_history_count(history.get('author_prior_commits_same_email'), bool(history.get('author_prior_commits_same_email_is_lower_bound')), bounded_window=bounded_window)}"
    )
    lines.append(
        f"- Prior commits by same name: {format_history_count(history.get('author_prior_commits_same_name'), bool(history.get('author_prior_commits_same_name_is_lower_bound')), bounded_window=bounded_window)}"
    )
    lines.append(f"- First seen same email: {history.get('author_first_seen_same_email_at') or '(none)'}")
    lines.append(f"- Previous commit same email: {history.get('author_previous_commit_same_email_at') or '(none)'}")
    author_identity_history = history.get("author_identity_history") or {}
    if author_identity_history:
        author_identity = author_identity_history.get("current_author") or {}
        committer_identity = author_identity_history.get("current_committer") or {}
        author_committer_split = author_identity_history.get("author_committer_split") or {}
        history_caveats = author_identity_history.get("history_caveats") or []
        identity_flags = author_identity_history.get("identity_flags") or []
        lines.append("")
        lines.append("## Author Identity History")
        lines.append(
            f"- Identity history source: {author_identity_history.get('history_source') or '(unknown)'}"
        )
        lines.append(
            f"- Identity baseline ref: {author_identity_history.get('baseline_ref') or '(unknown)'}"
        )
        if author_identity_history.get("default_branch_ref"):
            lines.append(
                f"- Default branch ref for comparison: {author_identity_history.get('default_branch_ref')}"
            )
        if history_caveats:
            lines.append(f"- Identity caveats: {', '.join(history_caveats)}")
        lines.append(
            f"- Current author normalized identity: "
            f"name={author_identity.get('normalized_name') or '(none)'} "
            f"email={author_identity.get('normalized_email') or '(none)'} "
            f"domain={author_identity.get('email_domain') or '(none)'} "
            f"noreply={format_bool_unknown(author_identity.get('email_is_noreply'))} "
            f"bot_like={format_bool_unknown(author_identity.get('looks_bot_like'))}"
        )
        lines.append(
            f"- Prior exact author identity seen: "
            f"{format_bool_unknown(author_identity_history.get('author_seen_before_exact'))}; "
            f"prior_commits {format_history_count(author_identity_history.get('author_prior_exact_identity_commits'), bool(author_identity_history.get('author_prior_exact_identity_commits_is_lower_bound')), bounded_window=False)}"
        )
        lines.append(
            f"- Prior author email seen: {format_bool_unknown(author_identity_history.get('author_email_seen_before'))}; "
            f"prior author name seen: {format_bool_unknown(author_identity_history.get('author_name_seen_before'))}"
        )
        lines.append(
            f"- Prior names used with current author email: "
            f"{format_identity_variants(author_identity_history.get('author_name_variants') or [], 'name')}"
        )
        lines.append(
            f"- Prior emails used with current author name: "
            f"{format_identity_variants(author_identity_history.get('author_email_variants') or [], 'email')}"
        )
        lines.append(
            f"- Prior email domains used with current author name: "
            f"{', '.join(author_identity_history.get('author_prior_email_domains') or ['(none)'])}"
        )
        lines.append(
            f"- Current author email domain first seen for current name: "
            f"{format_bool_unknown(author_identity_history.get('author_domain_first_seen'))}"
        )
        lines.append(
            f"- Current author/committer split: "
            f"same_identity={format_bool_unknown(author_committer_split.get('same_identity'))} "
            f"same_email={format_bool_unknown(author_committer_split.get('same_email'))} "
            f"same_name={format_bool_unknown(author_committer_split.get('same_name'))} "
            f"committer_seen_before_as_author={format_bool_unknown(author_committer_split.get('committer_seen_before_as_author'))} "
            f"committer_prior_author_commits {format_history_count(author_committer_split.get('committer_prior_author_commits_in_baseline'), bool(author_committer_split.get('committer_prior_author_commits_in_baseline_is_lower_bound')), bounded_window=False)}"
        )
        if committer_identity:
            lines.append(
                f"- Current committer normalized identity: "
                f"name={committer_identity.get('normalized_name') or '(none)'} "
                f"email={committer_identity.get('normalized_email') or '(none)'} "
                f"domain={committer_identity.get('email_domain') or '(none)'} "
                f"noreply={format_bool_unknown(committer_identity.get('email_is_noreply'))} "
                f"bot_like={format_bool_unknown(committer_identity.get('looks_bot_like'))}"
            )
        if identity_flags:
            lines.append(f"- Identity flags: {', '.join(identity_flags)}")
        lines.extend(render_domain_provenance_lines(author_identity_history))
    author_surface_history = history.get("author_surface_history") or {}
    if author_surface_history:
        lines.append("")
        lines.append("## Author Surface History")
        lines.append(f"- Surface history source: {author_surface_history.get('history_source') or '(unknown)'}")
        lines.append(f"- Surface history baseline ref: {author_surface_history.get('baseline_ref') or '(unknown)'}")
        lines.append(
            f"- Prior author commits on default-branch baseline: "
            f"{format_history_count(author_surface_history.get('author_prior_commits_default_branch'), bool(author_surface_history.get('author_prior_commits_default_branch_is_lower_bound')), bounded_window=False)}"
        )
        lines.append(
            f"- Prior sensitive-surface commits on default-branch baseline: "
            f"{format_history_count(author_surface_history.get('author_prior_sensitive_commits_total'), bool(author_surface_history.get('author_prior_sensitive_commits_total_is_lower_bound')), bounded_window=False)}"
        )
        lines.append(
            f"- Current commit path classes: "
            f"{', '.join(author_surface_history.get('author_current_commit_path_classes') or ['(none)'])}"
        )
        current_new_classes = author_surface_history.get("author_current_new_path_classes") or []
        if current_new_classes:
            lines.append(f"- New path classes for author in current commit: {', '.join(current_new_classes)}")
        current_new_sensitive = author_surface_history.get("author_current_new_sensitive_path_classes") or []
        if current_new_sensitive:
            lines.append(f"- New sensitive path classes for author in current commit: {', '.join(current_new_sensitive)}")
        current_new_dirs = author_surface_history.get("author_current_new_top_level_dirs") or []
        if current_new_dirs:
            lines.append(f"- New top-level dirs for author in current commit: {', '.join(current_new_dirs)}")
        prior_sensitive_classes = author_surface_history.get("author_prior_sensitive_path_classes") or []
        lines.append(
            f"- Prior sensitive path classes on default-branch baseline: "
            f"{', '.join(prior_sensitive_classes) if prior_sensitive_classes else '(none)'}"
        )
        role_transition = author_surface_history.get("author_role_transition") or {}
        if role_transition:
            lines.append(
                f"- Author role transition: {role_transition.get('transition_label') or '(none)'} "
                f"(privilege escalation candidate={role_transition.get('is_privilege_escalation_candidate')})"
            )
        for item in (author_surface_history.get("sensitive_surface_hits") or [])[:8]:
            lines.append(
                f"- Sensitive surface hit: {item.get('path')} class={item.get('path_class')} "
                f"prior_exact_touches={item.get('author_prior_touches_exact_path')} "
                f"prior_class_touches={item.get('author_prior_touches_same_class')} "
                f"exact_first_touch={item.get('exact_path_first_touch')} "
                f"class_first_touch={item.get('class_first_touch')}"
            )
    pr_social_history = history.get("pr_social_history") or {}
    if pr_social_history:
        lines.append("")
        lines.append("## PR / Social History")
        lines.extend(render_pr_social_history_lines(pr_social_history))
    author_temporal_complexity_history = history.get("author_temporal_complexity_history") or {}
    if author_temporal_complexity_history:
        temporal = author_temporal_complexity_history.get("temporal_distribution") or {}
        cadence = author_temporal_complexity_history.get("cadence") or {}
        timezone_history = author_temporal_complexity_history.get("timezone") or {}
        complexity = author_temporal_complexity_history.get("complexity") or {}
        lines.append("")
        lines.append("## Author Temporal / Complexity History")
        lines.append(
            f"- Temporal/complexity history source: "
            f"{author_temporal_complexity_history.get('history_source') or '(unknown)'}"
        )
        lines.append(
            f"- Temporal/complexity baseline ref: "
            f"{author_temporal_complexity_history.get('baseline_ref') or '(unknown)'}"
        )
        lines.append(
            f"- Prior author commits on default-branch temporal baseline: "
            f"{format_history_count(author_temporal_complexity_history.get('author_prior_commits_default_branch'), bool(author_temporal_complexity_history.get('author_prior_commits_default_branch_is_lower_bound')), bounded_window=False)}"
        )
        caveats = author_temporal_complexity_history.get("history_caveats") or []
        if caveats:
            lines.append(f"- Temporal/complexity caveats: {', '.join(caveats)}")
        lines.append(
            f"- Current authored-at UTC bucket: hour={temporal.get('current_commit_hour_utc')} "
            f"weekday={format_weekday_label(temporal.get('current_commit_weekday_utc'))} "
            f"prior_hour_count={temporal.get('current_commit_hour_prior_count')} "
            f"prior_weekday_count={temporal.get('current_commit_weekday_prior_count')}"
        )
        lines.append(
            f"- Prior authored-at UTC modes: hour={temporal.get('prior_mode_hour_utc')} "
            f"count={temporal.get('prior_mode_hour_count')}; weekday="
            f"{format_weekday_label(temporal.get('prior_mode_weekday_utc'))} "
            f"count={temporal.get('prior_mode_weekday_count')}"
        )
        hour_delta = temporal.get("current_commit_hour_delta_from_prior_mode_utc")
        if hour_delta is not None:
            lines.append(f"- Current authored-at UTC hour delta from prior mode: {hour_delta}")
        lines.append(
            f"- Prior authored-at UTC hour histogram top buckets: "
            f"{format_top_histogram_buckets(temporal.get('author_commit_hour_histogram_utc') or {})}"
        )
        lines.append(
            f"- Prior authored-at UTC weekday histogram top buckets: "
            f"{format_top_histogram_buckets(temporal.get('author_commit_weekday_histogram_utc') or {}, label_map=WEEKDAY_LABEL_MAP)}"
        )
        lines.append(
            f"- Current gap since prior author commit: {cadence.get('current_gap_since_prior_commit_days')} days; "
            f"historical median={cadence.get('author_historical_interarrival_days_median')} "
            f"stddev={cadence.get('author_historical_interarrival_days_stddev')} "
            f"ratio={cadence.get('cadence_shift_ratio')} "
            f"sample_count={cadence.get('interarrival_sample_count')}"
        )
        recent_interarrivals = cadence.get("author_recent_interarrival_days") or []
        if recent_interarrivals:
            lines.append(f"- Recent author interarrival days: {json.dumps(recent_interarrivals)}")
        lines.append(
            f"- Current authored-at timezone offset: "
            f"{format_timezone_offset_minutes(timezone_history.get('current_timezone_offset_minutes'))}; "
            f"prior_count={timezone_history.get('current_timezone_prior_count')} "
            f"mode={format_timezone_offset_minutes(timezone_history.get('prior_mode_timezone_offset_minutes'))} "
            f"mode_count={timezone_history.get('prior_mode_timezone_count')} "
            f"first_seen={timezone_history.get('timezone_first_seen')} "
            f"drift_from_mode_minutes={timezone_history.get('timezone_drift_from_prior_mode_minutes')}"
        )
        lines.append(
            f"- Prior authored-at timezone offsets seen: "
            f"{format_timezone_offset_counts(timezone_history.get('author_timezone_offsets_seen') or [])}"
        )
        lines.append(
            f"- Current message/diff stats: message_chars={complexity.get('commit_message_length')} "
            f"message_tokens={complexity.get('commit_message_token_count')} "
            f"files={complexity.get('diff_files_changed')} "
            f"added={complexity.get('diff_total_added_lines')} "
            f"deleted={complexity.get('diff_total_deleted_lines')} "
            f"changed={complexity.get('diff_total_changed_lines')}"
        )
        lines.append(
            f"- Historical commit size baseline: sample_count={complexity.get('historical_commit_size_sample_count')} "
            f"median={complexity.get('historical_commit_size_median')} "
            f"stddev={complexity.get('historical_commit_size_stddev')} "
            f"current_size_ratio_to_median={complexity.get('current_commit_size_ratio_to_historical_median')}"
        )
        lines.append(
            f"- Message-to-diff ratio: current={complexity.get('message_to_diff_ratio')} "
            f"historical_median={complexity.get('historical_message_to_diff_ratio_median')} "
            f"sample_count={complexity.get('message_to_diff_ratio_sample_count')} "
            f"mismatch_flag={complexity.get('message_to_diff_mismatch_flag')}"
        )
    lines.append("")
    lines.append("## Changed Files")
    if files_changed:
        for item in files_changed:
            path = item.get("path", "")
            added = item.get("added_lines")
            deleted = item.get("deleted_lines")
            lines.append(f"- {path} (+{added if added is not None else '?'}/-{deleted if deleted is not None else '?'})")
    else:
        if temporal_mode == "realtime":
            lines.append("- Patch unavailable in replay evidence cache.")
        else:
            lines.append("- Diff unavailable in current mirrors.")
    if gharchive_mode == "full":
        lines.append("")
        if temporal_mode == "realtime":
            lines.append("## Observed Push Context")
        else:
            lines.append("## GH Archive Push Context")
        lines.append(f"- Observed push at: {target_push.get('created_at_utc') or gharchive.get('fallback_metadata', {}).get('push_created_at_utc') or '(unknown)'}")
        lines.append(f"- Push actor: {target_push.get('actor_login') or gharchive.get('fallback_metadata', {}).get('actor_login') or '(unknown)'}")
        lines.append(f"- Ref: {target_push.get('ref') or '(unknown)'}")
        lines.append(f"- Ref transition: {target_push.get('push_before_sha') or '(unknown)'} -> {target_push.get('push_head_sha') or '(unknown)'}")
        lines.append(f"- Push size: {target_push.get('push_size')}")
        lines.append(f"- Distinct commits in push: {target_push.get('push_distinct_size')}")
        lines.append(f"- Forced push flag in GH Archive: {target_push.get('forced_push')}")
        lines.append(f"- Commit distinct in push payload: {target_push.get('commit_distinct')}")
        target_created_at = target_push.get("created_at_utc") or gharchive.get("fallback_metadata", {}).get("push_created_at_utc") or ""
        lines.append("")
        if temporal_mode == "realtime":
            lines.append("## Prior Push Context")
            lines.append(f"- Minutes since previous same-repo push: {timing.get('minutes_since_previous_repo_push')}")
            lines.append(f"- Same-repo pushes in prior 1 hour: {timing.get('repo_pushes_prev_1h')}")
            lines.append(f"- Same-actor pushes in prior 1 hour: {timing.get('repo_pushes_by_same_actor_prev_1h')}")
            prompt_events = prior_pushes_for_realtime_prompt(event_window, target_created_at)
        else:
            lines.append("## Rewrite / Persistence Signals")
            lines.append(f"- Current mirror healthy/readable: {rewrite.get('mirror_healthy')}")
            lines.append(f"- Target commit still present in current mirror: {rewrite.get('commit_present_in_current_mirror')}")
            lines.append(f"- Push head still present in current mirror: {rewrite.get('push_head_present_in_current_mirror')}")
            lines.append(f"- Push before SHA still present in current mirror: {rewrite.get('push_before_present_in_current_mirror')}")
            lines.append(f"- Target commit disappeared after observation: {rewrite.get('target_commit_missing_after_observation')}")
            lines.append("")
            lines.append("## Nearby Push Sequence")
            lines.append(f"- Minutes since previous same-repo push: {timing.get('minutes_since_previous_repo_push')}")
            lines.append(f"- Minutes until next same-repo push: {timing.get('minutes_until_next_repo_push')}")
            lines.append(f"- Same-repo pushes in prior 1 hour: {timing.get('repo_pushes_prev_1h')}")
            lines.append(f"- Same-repo pushes in next 1 hour: {timing.get('repo_pushes_next_1h')}")
            lines.append(f"- Same-actor pushes in prior 1 hour: {timing.get('repo_pushes_by_same_actor_prev_1h')}")
            lines.append(f"- Same-actor pushes in next 1 hour: {timing.get('repo_pushes_by_same_actor_next_1h')}")
            prompt_events = event_window.get("surrounding_pushes_same_repo", [])
        for item in prompt_events:
            marker = "target" if item.get("commit_sha") == case["commit_sha"] else "neighbor"
            delta_minutes = minutes_between(target_created_at, item.get("created_at_utc") or "")
            if delta_minutes is not None and abs(delta_minutes) > 1440:
                continue
            delta_text = f" Δ{delta_minutes:+.1f}m" if delta_minutes is not None else ""
            lines.append(
                f"- [{marker}]{delta_text} {item.get('created_at_utc')} {item.get('actor_login')} "
                f"{item.get('push_before_sha')} -> {item.get('push_head_sha')} "
                f"msg={json.dumps(item.get('commit_message', ''))}"
            )
    lines.append("")
    patch_excerpt = commit.get("patch_excerpt", "")
    if patch_excerpt:
        lines.append("## Patch Excerpt")
        lines.append("```diff")
        lines.append(patch_excerpt)
        lines.append("```")
        lines.append("")
    lines.append("Respond in this exact format:")
    lines.append("**Classification**: [suspicious/benign]")
    lines.append("**Confidence**: [low/medium/high]")
    lines.append("**Reasoning**: [2-4 sentences explaining which commit-level signals drove the assessment]")
    return "\n".join(lines)


def normalize_ground_truth_class(label: str) -> str:
    normalized = (label or "").strip().lower()
    if normalized in {"malicious", "suspicious"}:
        return "suspicious"
    if normalized == "benign":
        return "benign"
    return normalized


def build_replay_case(
    truth: GroundTruthCommit,
    clone_dir: Path,
    max_patch_chars: int,
    max_files: int,
    gharchive_mode: str,
    temporal_mode: str,
    gharchive_event_lookup: GHArchiveEventLookup,
    gharchive_events_by_repo: GHArchiveEventsByRepo,
    email_domain_intel: dict[str, Any] | None = None,
) -> CommitCase:
    repo_path = mirror_path_for(truth.repo, clone_dir)
    repo_exists = repo_path.exists()
    repo_healthy = False
    mirror_error = ""
    if repo_exists:
        repo_healthy, mirror_error = git_repo_health(repo_path)
    commit_present = repo_exists and repo_healthy and git_commit_exists(repo_path, truth.sha)

    commit_header: dict[str, Any] | None = None
    commit_payload: dict[str, Any]

    if commit_present:
        commit_header = load_commit_header(repo_path, truth.sha)
        files_changed, stats = load_numstat(repo_path, truth.sha, max_files)
        patch_payload = load_patch(repo_path, truth.sha, max_patch_chars)
        commit_payload = {
            **commit_header,
            "files_changed": files_changed,
            "stats": stats,
            "patch_excerpt": patch_payload["patch"],
            "patch_char_count": patch_payload["patch_char_count"],
            "patch_truncated": patch_payload["patch_truncated"],
        }
    else:
        commit_payload = {
            "sha": truth.sha,
            "parent_shas": [],
            "author_name": truth.commit_author_name,
            "author_email": truth.commit_author_email,
            "authored_at": "",
            "committer_name": "",
            "committer_email": "",
            "committed_at": "",
            "message": truth.commit_message,
            "files_changed": [],
            "stats": {
                "files_changed": 0,
                "files_list_truncated": False,
                "total_added_lines": 0,
                "total_deleted_lines": 0,
                "binary_file_count": 0,
            },
            "patch_excerpt": "",
            "patch_char_count": 0,
            "patch_truncated": False,
        }

    anchor_iso = commit_anchor_iso(commit_header, truth)
    gharchive_context = build_gharchive_context(
        truth=truth,
        repo_path=repo_path,
        repo_healthy=repo_healthy,
        commit_present=commit_present,
        event_lookup=gharchive_event_lookup,
        events_by_repo=gharchive_events_by_repo,
    )
    evidence_state = classify_evidence_state(
        repo_exists=repo_exists,
        repo_healthy=repo_healthy,
        commit_present=commit_present,
        gharchive_context=gharchive_context,
    )
    if repo_exists and repo_healthy:
        history = build_history_features(
            repo_path=repo_path,
            anchor_iso=anchor_iso,
            sha_to_exclude=truth.sha,
            author_name=commit_payload["author_name"],
            author_email=commit_payload["author_email"],
        )
    else:
        history = {
            "anchor_timestamp_utc": anchor_iso,
            "history_cutoff_utc": strict_before_iso(anchor_iso),
            "repo_commit_count_before": None,
            "author_prior_commits_same_email": None,
            "author_prior_commits_same_name": None,
            "author_first_seen_same_email_at": "",
            "author_previous_commit_same_email_at": "",
            "author_first_seen_same_name_at": "",
            "author_previous_commit_same_name_at": "",
            "hours_since_author_first_seen_same_email": None,
            "hours_since_author_previous_commit_same_email": None,
            "hours_since_author_first_seen_same_name": None,
            "hours_since_author_previous_commit_same_name": None,
        }

    case: CommitCase = {
        "case_schema_version": REPLAY_CASE_SCHEMA_VERSION,
        "case_id": f"{slug_repo(truth.repo)}__{truth.short_sha}",
        "repo": truth.repo,
        "repo_slug": slug_repo(truth.repo),
        "commit_sha": truth.sha,
        "short_sha": truth.short_sha,
        "ground_truth": truth.label,
        "ground_truth_class": normalize_ground_truth_class(truth.label),
        "incident": truth.incident,
        "cwe_type": truth.cwe_type,
        "paper_window": truth.paper_window,
        "selection_reason": truth.selection_reason,
        "recovery_source": truth.recovery_source,
        "mirror_path": str(repo_path),
        "mirror_repo_exists": repo_exists,
        "mirror_repo_healthy": repo_healthy,
        "mirror_error": mirror_error,
        "commit_present_in_mirror": commit_present,
        "evidence_state": evidence_state,
        "feature_availability": {
            "mirror_commit": commit_present,
            "mirror_patch": commit_present,
            "gharchive_metadata": bool(truth.gharchive_push_created_at or truth.gharchive_actor_login),
            "gharchive_target_push_event": gharchive_context.get("target_push_event") is not None,
            "gharchive_repo_sequence": bool(gharchive_context.get("repo_event_window", {}).get("surrounding_pushes_same_repo")),
            "author_history_from_current_mirror": repo_healthy,
        },
        "commit": commit_payload,
        "history_before_commit": history,
        "gharchive_context": gharchive_context,
    }
    if email_domain_intel is not None:
        email_domain_context = build_email_domain_context(
            commit_payload, history, email_domain_intel, temporal_mode
        )
        case["email_domain_context"] = email_domain_context
        case["feature_availability"]["email_domain_intel"] = True
    case["agent_prompt"] = render_agent_prompt(case, gharchive_mode=gharchive_mode, temporal_mode=temporal_mode)
    if email_domain_intel is not None:
        case["agent_prompt"] += render_email_domain_evidence(email_domain_context)
    return case


def build_realtime_case(
    repo_path: Path,
    sha: str,
    ref: str,
    observed_at: str,
    *,
    repo: str = "",
    max_patch_chars: int = 12000,
    max_files: int = 200,
    max_author_commits: int = 20,
    max_path_commits: int = 5,
    max_paths_for_history: int = 10,
    max_ref_history_commits: int = 20,
    max_author_surface_commits: int = 250,
    pr_social_history: dict[str, Any] | None = None,
    gharchive_mode: str = "omit",
    full_history_repo_path: Path | None = None,
    email_domain_intel: dict[str, Any] | None = None,
) -> CommitCase:
    repo_path = Path(repo_path)
    if not repo_path.exists():
        raise RuntimeError(f"realtime repo path does not exist: {repo_path}")

    repo_healthy, mirror_error = git_repo_health(repo_path)
    if not repo_healthy:
        raise RuntimeError(f"realtime repo is not readable by git: {repo_path}: {mirror_error}")
    if not git_commit_exists(repo_path, sha):
        raise RuntimeError(f"realtime commit {sha} is not present in {repo_path}")

    observed_at_iso = normalize_iso_datetime(observed_at)
    repo_id = repo.strip() or infer_repo_id(repo_path)

    commit_header = load_commit_header(repo_path, sha)
    parent_sha = (commit_header.get("parent_shas") or [""])[0]
    files_changed, stats = load_numstat(repo_path, sha, max_files, parent_sha=parent_sha)
    patch_payload = load_patch(repo_path, sha, max_patch_chars)
    commit_payload = {
        **commit_header,
        "files_changed": files_changed,
        "stats": stats,
        "patch_excerpt": patch_payload["patch"],
        "patch_char_count": patch_payload["patch_char_count"],
        "patch_truncated": patch_payload["patch_truncated"],
    }

    history, recent_ref_history = build_realtime_history_features(
        repo_path,
        commit_payload,
        repo_id=repo_id,
        ref=ref,
        observed_at=observed_at_iso,
        max_author_commits=max_author_commits,
        max_path_commits=max_path_commits,
        max_paths_for_history=max_paths_for_history,
        max_ref_history_commits=max_ref_history_commits,
        max_author_surface_commits=max_author_surface_commits,
        full_history_repo_path=full_history_repo_path,
    )
    if pr_social_history is not None:
        history["pr_social_history"] = pr_social_history
    gharchive_context = build_realtime_observation_context(
        repo_path,
        repo_id,
        commit_payload,
        ref=ref,
        observed_at=observed_at_iso,
        recent_ref_history=recent_ref_history,
    )
    evidence_state = classify_evidence_state(
        repo_exists=True,
        repo_healthy=repo_healthy,
        commit_present=True,
        gharchive_context=gharchive_context,
    )

    case: CommitCase = {
        "case_schema_version": REALTIME_CASE_SCHEMA_VERSION,
        "case_id": f"{slug_repo(repo_id)}__{sha[:7]}__realtime",
        "repo": repo_id,
        "repo_slug": slug_repo(repo_id),
        "commit_sha": sha,
        "short_sha": sha[:7],
        "ground_truth": "",
        "ground_truth_class": "",
        "incident": "",
        "cwe_type": "",
        "paper_window": None,
        "selection_reason": "",
        "recovery_source": "realtime_observation",
        "mirror_path": str(repo_path),
        "mirror_repo_exists": True,
        "mirror_repo_healthy": repo_healthy,
        "mirror_error": mirror_error,
        "commit_present_in_mirror": True,
        "evidence_state": evidence_state,
        "feature_availability": {
            "mirror_commit": True,
            "mirror_patch": True,
            "gharchive_metadata": False,
            "gharchive_target_push_event": False,
            "gharchive_repo_sequence": False,
            "author_history_from_current_mirror": True,
            "author_identity_history_from_reachable_history": bool(history.get("author_identity_history")),
            "author_temporal_complexity_history_from_default_branch": bool(history.get("author_temporal_complexity_history")),
            "author_surface_history_from_default_branch": bool(history.get("author_surface_history")),
            "pr_social_history_context": bool(history.get("pr_social_history")),
            "pr_social_history_available": bool((history.get("pr_social_history") or {}).get("available")),
            "path_history_from_current_mirror": bool(history.get("path_recent_touches")),
            "realtime_observation_context": True,
            "realtime_ref_history": bool(recent_ref_history),
            "sensitive_path_ownership": bool(full_history_repo_path is not None and full_history_repo_path.exists()),
        },
        "commit": commit_payload,
        "history_before_commit": history,
        "gharchive_context": gharchive_context,
        "realtime_observation": {
            "repo_path": str(repo_path),
            "ref": ref,
            "observed_at_utc": observed_at_iso,
            "source": "realtime_observation",
        },
    }
    if email_domain_intel is not None:
        email_domain_context = build_email_domain_context(
            commit_payload, history, email_domain_intel, "realtime"
        )
        case["email_domain_context"] = email_domain_context
        case["feature_availability"]["email_domain_intel"] = True
    case["agent_prompt"] = render_agent_prompt(case, gharchive_mode=gharchive_mode, temporal_mode="realtime")
    if email_domain_intel is not None:
        case["agent_prompt"] += render_email_domain_evidence(email_domain_context)
    return case
