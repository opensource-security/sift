from __future__ import annotations

import subprocess
from collections import Counter
from pathlib import Path
from typing import Any


# Explicit bot identity blocklist — matched against normalized email local-part.
_BOT_EMAIL_LOCAL_PARTS: frozenset[str] = frozenset({
    "dependabot[bot]",
    "github-actions[bot]",
    "pre-commit-ci[bot]",
    "noreply",
})

# Known automation email domains where all addresses are non-human.
_BOT_EMAIL_DOMAINS: frozenset[str] = frozenset({
    "users.noreply.github.com",
})


def _is_bot_identity(email: str) -> bool:
    """Return True if the email belongs to an automation identity."""
    normalized = (email or "").strip().casefold()
    if not normalized:
        return False
    local, _, domain = normalized.partition("@")
    if local in _BOT_EMAIL_LOCAL_PARTS:
        return True
    if local.endswith("[bot]"):
        return True
    if local.endswith("-bot"):
        return True
    if domain in _BOT_EMAIL_DOMAINS:
        return True
    return False


def query_sensitive_path_owners(
    full_history_repo_path: Path,
    parent_sha: str,
    file_path: str,
    current_author_email: str,
    *,
    timeout_sec: int = 20,
) -> dict[str, Any] | None:
    """
    Query human-author ownership for file_path in history prior to parent_sha.

    Uses git log anchored at parent_sha against a full-history clone.  Returns
    None on unavailable repo, timeout, or git failure — callers treat None as
    "ownership unknown" and omit the evidence block.

    Excludes bot identities. Uses exact normalized email only (no name fallback).
    Does not semantically cap ownership history; the timeout is the only guard.
    Rendered top_human_owners list is capped at 5 entries, but prior_human_authors_count
    reflects all distinct human authors found.
    """
    if not full_history_repo_path or not full_history_repo_path.exists():
        return None
    if not parent_sha or not file_path:
        return None

    try:
        result = subprocess.run(
            [
                "git",
                "-C", str(full_history_repo_path),
                "log",
                parent_sha,
                "--format=%ae",
                "--",
                file_path,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_sec,
        )
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None

    if result.returncode != 0:
        return None

    raw_output = result.stdout.strip()

    # File never appeared in history prior to parent_sha.
    if not raw_output:
        return {
            "prior_human_authors_count": 0,
            "top_human_owners": [],
            "top_human_author_share": 0.0,
            "ownership_concentration": "low",
            "ownership_match_basis": "exact_email_only",
        }

    email_counter: Counter[str] = Counter()
    for line in raw_output.splitlines():
        email = line.strip().casefold()
        if not email:
            continue
        if _is_bot_identity(email):
            continue
        email_counter[email] += 1

    if not email_counter:
        return {
            "prior_human_authors_count": 0,
            "top_human_owners": [],
            "top_human_author_share": 0.0,
            "ownership_concentration": "low",
            "ownership_match_basis": "exact_email_only",
        }

    total_human_commits = sum(email_counter.values())
    top_entries = email_counter.most_common(5)
    top_author_count = top_entries[0][1]
    top_author_share = round(top_author_count / total_human_commits, 4)
    prior_human_authors_count = len(email_counter)

    if prior_human_authors_count <= 5 and top_author_share >= 0.6:
        ownership_concentration = "high"
    elif prior_human_authors_count <= 15:
        ownership_concentration = "medium"
    else:
        ownership_concentration = "low"

    top_human_owners = [
        {"email": email, "commit_count": count}
        for email, count in top_entries
    ]

    return {
        "prior_human_authors_count": prior_human_authors_count,
        "top_human_owners": top_human_owners,
        "top_human_author_share": top_author_share,
        "ownership_concentration": ownership_concentration,
        "ownership_match_basis": "exact_email_only",
    }
