"""Release-level case building and prompt rendering.

Extracts tag-to-tag diffs, builds a ReleaseCase dict, and renders
a triage prompt for supply-chain risk assessment at release granularity.
"""
from __future__ import annotations

import re
import sqlite3
import subprocess
from pathlib import Path
from typing import Any

from .case_builder import slug_repo
from .primary import (
    PRIMARY_ACTIONS,
    PRIMARY_FINDING_TYPES,
    PRIMARY_SEVERITIES,
)
from .types import ResolvedRelease, TagSignatureStatus

RELEASE_CASE_SCHEMA_VERSION = "release_case_v1"
RELEASE_PROMPT_VERSION = "release_findings_v1"

# Dependency file patterns (basename matching)
DEPENDENCY_FILE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^requirements.*\.txt$"),
    re.compile(r"^setup\.(py|cfg)$"),
    re.compile(r"^pyproject\.toml$"),
    re.compile(r"^Pipfile(\.lock)?$"),
    re.compile(r"^Cargo\.(toml|lock)$"),
    re.compile(r"^package(-lock)?\.json$"),
    re.compile(r"^yarn\.lock$"),
    re.compile(r"^pnpm-lock\.yaml$"),
    re.compile(r"^go\.(mod|sum)$"),
    re.compile(r"^Gemfile(\.lock)?$"),
    re.compile(r"^poetry\.lock$"),
    re.compile(r"^uv\.lock$"),
]


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------


def _git(repo_path: Path, *args: str, timeout: int = 60) -> str:
    """Run a git command and return stdout. Raises on failure."""
    proc = subprocess.run(
        ["git", "-C", str(repo_path), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args[:3])}... failed: {proc.stderr.strip()[:200]}"
        )
    return proc.stdout


def detect_tag_signature(repo_path: Path, tag_name: str) -> TagSignatureStatus:
    """Detect the signature status of a git tag in a local clone."""
    proc = subprocess.run(
        ["git", "-C", str(repo_path), "cat-file", "-t", f"refs/tags/{tag_name}"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if proc.returncode != 0:
        return TagSignatureStatus.UNKNOWN
    obj_type = proc.stdout.strip()
    if obj_type == "commit":
        return TagSignatureStatus.LIGHTWEIGHT
    if obj_type != "tag":
        return TagSignatureStatus.UNKNOWN
    proc = subprocess.run(
        ["git", "-C", str(repo_path), "cat-file", "-p", f"refs/tags/{tag_name}"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if proc.returncode != 0:
        return TagSignatureStatus.UNKNOWN
    body = proc.stdout
    if "-----BEGIN PGP SIGNATURE-----" in body:
        return TagSignatureStatus.SIGNED_GPG
    if "-----BEGIN CMS-----" in body or "-----BEGIN PKCS7-----" in body:
        return TagSignatureStatus.SIGNED_SIGSTORE
    return TagSignatureStatus.ANNOTATED_UNSIGNED


def normalize_tag_version(tag_name: str, release_tag_pattern: str = "") -> str:
    """Strip tag prefix and normalize separators to produce a comparable version.

    Examples:
        "v1.2.3"     -> "1.2.3"
        "R_2_7_5"    -> "2.7.5"
        "v/0.23.37"  -> "0.23.37"
        "5.2.1"      -> "5.2.1"
    """
    version = tag_name
    if release_tag_pattern:
        m = re.match(r"^([^0-9]*)", release_tag_pattern.lstrip("^"))
        if m and m.group(1):
            literal_prefix = m.group(1)
            literal_prefix = literal_prefix.replace(r"\.", ".").replace(r"\-", "-")
            literal_prefix = literal_prefix.replace(r"[_-]", "_").replace(r"[_\-]", "_")
            literal_prefix = re.sub(r"[\\?+*\[\](){}|]", "", literal_prefix)
            if literal_prefix and version.lower().startswith(literal_prefix.lower()):
                version = version[len(literal_prefix):]
            elif literal_prefix:
                m2 = re.match(r"^[^0-9]+", version)
                if m2:
                    version = version[m2.end():]
    else:
        m = re.match(r"^[^0-9]+", version)
        if m:
            version = version[m.end():]
    version = version.replace("_", ".")
    return version.strip(".")


# ---------------------------------------------------------------------------
# Diff and commit extraction
# ---------------------------------------------------------------------------


def load_release_diff(
    repo_path: Path,
    from_sha: str,
    to_sha: str,
    *,
    max_patch_chars: int = 50_000,
    max_files: int = 500,
) -> dict[str, Any]:
    """Extract aggregate diff between two commits (tag-to-tag)."""
    numstat_raw = _git(repo_path, "diff", f"{from_sha}..{to_sha}", "--numstat")
    files_changed: list[dict[str, Any]] = []
    total_added = 0
    total_deleted = 0
    for line in numstat_raw.strip().splitlines():
        parts = line.split("\t", 2)
        if len(parts) < 3:
            continue
        added_str, deleted_str, path = parts
        added = int(added_str) if added_str != "-" else 0
        deleted = int(deleted_str) if deleted_str != "-" else 0
        total_added += added
        total_deleted += deleted
        files_changed.append({
            "path": path,
            "added_lines": added,
            "deleted_lines": deleted,
        })

    files_truncated = len(files_changed) > max_files
    if files_truncated:
        files_changed = files_changed[:max_files]

    patch_raw = _git(
        repo_path, "diff", f"{from_sha}..{to_sha}",
        "--patch", "--unified=3",
        timeout=120,
    )
    patch_char_count = len(patch_raw)
    patch_truncated = patch_char_count > max_patch_chars
    patch_excerpt = patch_raw[:max_patch_chars] if patch_truncated else patch_raw

    return {
        "files_changed": files_changed,
        "stats": {
            "total_added": total_added,
            "total_deleted": total_deleted,
            "total_files": len(files_changed),
        },
        "patch_excerpt": patch_excerpt,
        "patch_char_count": patch_char_count,
        "patch_truncated": patch_truncated,
        "files_list_truncated": files_truncated,
    }


def load_release_commits(
    repo_path: Path,
    from_sha: str,
    to_sha: str,
    *,
    max_commits: int = 200,
) -> tuple[list[dict[str, str]], list[str], list[str]]:
    """Load commit inventory between two refs.

    Returns: (commits, unique_authors, first_time_authors)
    """
    sep = "|:|"
    fmt = f"%H{sep}%an{sep}%ae{sep}%aI{sep}%s"
    log_raw = _git(
        repo_path, "log", f"{from_sha}..{to_sha}",
        f"--format={fmt}", f"-{max_commits}",
    )

    commits: list[dict[str, str]] = []
    range_authors: set[str] = set()
    for line in log_raw.strip().splitlines():
        parts = line.split(sep, 4)
        if len(parts) < 5:
            continue
        sha, name, email, date, subject = parts
        commits.append({
            "sha": sha,
            "short_sha": sha[:7],
            "author_name": name,
            "author_email": email,
            "authored_at": date,
            "message_subject": subject,
        })
        range_authors.add(email.lower())

    prior_authors: set[str] = set()
    try:
        prior_raw = _git(
            repo_path, "log", from_sha,
            "--format=%ae", "-500",
            timeout=30,
        )
        for line in prior_raw.strip().splitlines():
            prior_authors.add(line.strip().lower())
    except RuntimeError:
        pass

    unique = sorted(range_authors)
    first_time = sorted(range_authors - prior_authors)
    return commits, unique, first_time


def detect_dependency_changes(
    files_changed: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Filter file list to dependency-related files."""
    dep_files: list[dict[str, Any]] = []
    for f in files_changed:
        basename = Path(f["path"]).name
        if any(pat.match(basename) for pat in DEPENDENCY_FILE_PATTERNS):
            dep_files.append(f)
    return dep_files


# ---------------------------------------------------------------------------
# Commit-level corroboration from SQLite
# ---------------------------------------------------------------------------


def load_commit_corroboration(
    sqlite_db: Path,
    repo: str,
    commit_shas: list[str],
) -> dict[str, Any] | None:
    """Query existing commit_runs for findings in the release range."""
    if not sqlite_db or not sqlite_db.exists() or not commit_shas:
        return None

    try:
        conn = sqlite3.connect(str(sqlite_db))
        conn.row_factory = sqlite3.Row
        placeholders = ",".join("?" for _ in commit_shas)
        rows = conn.execute(
            f"""
            SELECT cr.commit_sha, cr.primary_classification,
                   f.finding_type, f.severity
            FROM commit_runs cr
            LEFT JOIN findings f ON f.commit_run_id = cr.commit_run_id
            WHERE cr.repo = ? AND cr.commit_sha IN ({placeholders})
            """,
            [repo] + commit_shas,
        ).fetchall()
        conn.close()
    except Exception:
        return None

    analyzed_shas: set[str] = set()
    shas_with_findings: set[str] = set()
    finding_types: set[str] = set()
    severities: list[str] = []
    for row in rows:
        analyzed_shas.add(row["commit_sha"])
        if row["finding_type"]:
            shas_with_findings.add(row["commit_sha"])
            finding_types.add(row["finding_type"])
            if row["severity"]:
                severities.append(row["severity"])

    severity_rank = {"high": 3, "medium": 2, "low": 1}
    highest = max(severities, key=lambda s: severity_rank.get(s, 0)) if severities else None

    return {
        "commits_analyzed": len(analyzed_shas),
        "commits_with_findings": len(shas_with_findings),
        "finding_types": sorted(finding_types),
        "highest_severity": highest,
    }


# ---------------------------------------------------------------------------
# Prompt rendering
# ---------------------------------------------------------------------------


def render_release_evidence(case: dict[str, Any]) -> str:
    """Render the evidence block for the release triage prompt."""
    lines: list[str] = []
    lines.append("## Release metadata")
    lines.append(f"Repo: {case['repo']}")
    lines.append(f"From: {case['from_tag']} ({case['from_version']}) -> To: {case['to_tag']} ({case['to_version']})")
    lines.append(f"From SHA: {case['from_sha'][:12]}")
    lines.append(f"To SHA: {case['to_sha'][:12]}")
    if case.get("published_at"):
        lines.append(f"Published: {case['published_at']}")
    if case.get("tag_signature"):
        lines.append(f"Tag signature: {case['tag_signature']}")
    if case.get("tagger"):
        lines.append(f"Tagger: {case['tagger']}")
    lines.append("")

    rd = case["release_diff"]
    lines.append("## Release statistics")
    lines.append(f"Commits in range: {rd.get('commits_in_range', len(case.get('commits', [])))}")
    lines.append(f"Unique authors: {len(rd.get('unique_authors', []))}")
    if rd.get("first_time_authors"):
        lines.append(f"First-time authors in this range: {', '.join(rd['first_time_authors'])}")
    stats = rd["stats"]
    lines.append(f"Lines added: {stats['total_added']}, deleted: {stats['total_deleted']}")
    lines.append(f"Files changed: {len(rd['files_changed'])}")
    if rd.get("files_list_truncated"):
        lines.append("(file list truncated)")
    lines.append("")

    dep = case.get("dependency_changes", [])
    if dep:
        lines.append("## Dependency file changes")
        for d in dep:
            lines.append(f"  {d['path']}: +{d['added_lines']} / -{d['deleted_lines']}")
        lines.append("")

    commits = case.get("commits", [])
    if commits:
        lines.append("## Commit inventory")
        for c in commits[:50]:
            lines.append(f"  {c['short_sha']} {c['author_email']:30s} {c['message_subject'][:80]}")
        if len(commits) > 50:
            lines.append(f"  ... and {len(commits) - 50} more commits")
        lines.append("")

    corr = case.get("commit_corroboration")
    if corr:
        lines.append("## Commit-level corroboration (from prior per-commit analysis)")
        lines.append(f"  Commits analyzed: {corr['commits_analyzed']}")
        lines.append(f"  Commits with findings: {corr['commits_with_findings']}")
        if corr.get("finding_types"):
            lines.append(f"  Finding types: {', '.join(corr['finding_types'])}")
        if corr.get("highest_severity"):
            lines.append(f"  Highest severity: {corr['highest_severity']}")
        lines.append("")

    files = rd["files_changed"]
    if files:
        lines.append("## Changed files (numstat)")
        for f in files[:100]:
            lines.append(f"  +{f['added_lines']:<6d} -{f['deleted_lines']:<6d} {f['path']}")
        if len(files) > 100:
            lines.append(f"  ... and {len(files) - 100} more files")
        lines.append("")

    if rd.get("patch_excerpt"):
        lines.append("## Patch (unified diff)")
        if rd["patch_truncated"]:
            lines.append(f"(truncated to {len(rd['patch_excerpt'])} of {rd['patch_char_count']} chars)")
        lines.append("```")
        lines.append(rd["patch_excerpt"])
        lines.append("```")

    return "\n".join(lines)


def build_release_findings_prompt(case: dict[str, Any]) -> str:
    """Build the primary triage prompt for release-level analysis."""
    evidence = render_release_evidence(case)

    finding_types_str = ", ".join(sorted(PRIMARY_FINDING_TYPES))
    severities_str = ", ".join(sorted(PRIMARY_SEVERITIES))
    actions_str = ", ".join(sorted(PRIMARY_ACTIONS))

    from_tag = case["from_tag"]
    to_tag = case["to_tag"]

    return f"""\
You are the primary triage model for supply-chain release review.

You are analyzing the diff between two consecutive tagged releases of an
open-source project. Your task: determine whether upgrading from {from_tag}
to {to_tag} introduces supply-chain risk.

## Decision rules

Classify as **suspicious** if the release contains changes that a reasonable
security reviewer would want to examine before allowing the upgrade. Focus on:

- Dependency changes in a patch release (new dependencies, version pins
  pointing to unusual sources, post-install hooks)
- Hidden network fetches, credential access, or obfuscated payloads added
  in this release range
- Build/CI pipeline modifications that alter the release artifact
- Changes by first-time authors to security-sensitive paths
- Undocumented changes: code changes not referenced in any commit message
- Release process tampering: tag signature changes, tagger identity shifts

Classify as **benign** if the changes are routine maintenance, bug fixes,
documentation, or feature work consistent with the project's development
pattern.

Do NOT flag normal dependency version bumps, standard CI updates, or
routine refactoring. Prefer fewer, sharper findings over broad speculation.

## Allowed values

- finding_type: {finding_types_str}
- severity: {severities_str}
- suggested_action: {actions_str}
- evidence_refs: release_diff.patch_excerpt, release_diff.files_changed,
  commits, dependency_changes, commit_corroboration, release_metadata

## Evidence

{evidence}

## Output format

Respond with a single JSON object:

```json
{{{{
  "classification": "suspicious" or "benign",
  "confidence": "low", "medium", or "high",
  "reasoning": "2-4 sentence summary of your assessment",
  "findings": [
    {{{{
      "finding_type": "one of the allowed types",
      "claim": "specific, testable claim about what is suspicious",
      "severity": "low", "medium", or "high",
      "evidence_refs": ["release_diff.patch_excerpt", ...],
      "suggested_action": "review" or "hold" or "ignore"
    }}}}
  ]
}}}}
```

If benign, return an empty findings array. Maximum 5 findings.
"""


def build_release_verifier_prompt(
    case: dict[str, Any],
    finding: dict[str, Any],
    variant: dict[str, str],
) -> str:
    """Build a verifier prompt for a release-level finding."""
    evidence = render_release_evidence(case)

    return f"""\
You are a verification reviewer for supply-chain release analysis.

## Your role: {variant['label']}

{variant['instructions']}

## The finding to evaluate

**Type:** {finding.get('finding_type', 'unknown')}
**Claim:** {finding.get('claim', '(no claim)')}
**Severity:** {finding.get('severity', 'unknown')}
**Evidence refs:** {', '.join(finding.get('evidence_refs', []))}

## Release evidence

{evidence}

## Instructions

Evaluate whether the finding's claim is supported by the release evidence.

Respond with exactly:

**Outcome**: [verify/disprove/abstain]
**Confidence**: [low/medium/high]
**Rationale**: [2-4 sentences focused on the claim]
**Evidence Refs**: [comma-separated case field refs or none]
"""


# ---------------------------------------------------------------------------
# Case builder
# ---------------------------------------------------------------------------


def build_release_case(
    repo_path: Path,
    from_release: ResolvedRelease,
    to_release: ResolvedRelease,
    *,
    repo: str = "",
    max_patch_chars: int = 50_000,
    max_files: int = 500,
    max_commits: int = 200,
    sqlite_db: Path | None = None,
) -> dict[str, Any]:
    """Build a complete release case for triage.

    Requires a local clone with both tags present.
    """
    from_sha = from_release.commit_sha
    to_sha = to_release.commit_sha
    repo_id = repo or ""

    diff = load_release_diff(
        repo_path, from_sha, to_sha,
        max_patch_chars=max_patch_chars,
        max_files=max_files,
    )

    commits, unique_authors, first_time_authors = load_release_commits(
        repo_path, from_sha, to_sha,
        max_commits=max_commits,
    )

    diff["commits_in_range"] = len(commits)
    diff["unique_authors"] = unique_authors
    diff["first_time_authors"] = first_time_authors

    dep_changes = detect_dependency_changes(diff["files_changed"])

    corroboration = None
    if sqlite_db:
        commit_shas = [c["sha"] for c in commits]
        corroboration = load_commit_corroboration(sqlite_db, repo_id, commit_shas)

    sig = detect_tag_signature(repo_path, to_release.tag_name)

    safe_from = re.sub(r"[^a-zA-Z0-9._-]", "_", from_release.tag_name)
    safe_to = re.sub(r"[^a-zA-Z0-9._-]", "_", to_release.tag_name)

    case: dict[str, Any] = {
        "case_schema_version": RELEASE_CASE_SCHEMA_VERSION,
        "case_id": f"{slug_repo(repo_id)}__{safe_from}__{safe_to}",
        "repo": repo_id,
        "repo_slug": slug_repo(repo_id),
        "from_tag": from_release.tag_name,
        "to_tag": to_release.tag_name,
        "from_sha": from_sha,
        "to_sha": to_sha,
        "from_version": from_release.version_normalized,
        "to_version": to_release.version_normalized,
        "tag_signature": sig.value,
        "tagger": to_release.tagger,
        "published_at": (
            to_release.published_at.isoformat()
            if to_release.published_at else None
        ),
        "evidence_state": "mirror_present",
        "mirror_path": str(repo_path),
        "release_diff": diff,
        "commits": commits,
        "dependency_changes": dep_changes,
        "commit_corroboration": corroboration,
        "agent_prompt": "",
    }

    case["agent_prompt"] = build_release_findings_prompt(case)
    return case
