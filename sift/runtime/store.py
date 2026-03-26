from __future__ import annotations

import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .providers import now_utc_iso

PR_RUN_STORE_SCHEMA_VERSION = "shadow_pr_run_store_v1"
COMMIT_RUN_STORE_SCHEMA_VERSION = "shadow_commit_run_store_v1"
DEFAULT_VERIFIER_BUNDLE_VERSION = "verifier_matrix_v8"


SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS pr_runs (
    pr_run_id TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL,
    repo TEXT NOT NULL,
    pr_number INTEGER NOT NULL,
    base_sha TEXT NOT NULL,
    head_sha TEXT NOT NULL,
    merge_base TEXT NOT NULL,
    base_ref TEXT,
    head_ref TEXT,
    observed_at TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    runner TEXT NOT NULL,
    model_id TEXT NOT NULL,
    harness_git_sha TEXT NOT NULL,
    case_schema_version TEXT NOT NULL,
    primary_prompt_version TEXT,
    verifier_bundle_version TEXT,
    github_run_id TEXT,
    github_job_id TEXT,
    github_check_run_id TEXT,
    github_run_url TEXT,
    classification_counts_json TEXT NOT NULL,
    matrix_status_counts_json TEXT NOT NULL,
    commits_total INTEGER NOT NULL,
    findings_total INTEGER NOT NULL,
    verified_findings_total INTEGER NOT NULL,
    surviving_findings_total INTEGER NOT NULL,
    input_tokens INTEGER NOT NULL,
    output_tokens INTEGER NOT NULL,
    cost_usd_estimate REAL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pr_runs_repo_pr
    ON pr_runs(repo, pr_number);
CREATE INDEX IF NOT EXISTS idx_pr_runs_head_sha
    ON pr_runs(head_sha);
CREATE INDEX IF NOT EXISTS idx_pr_runs_profile
    ON pr_runs(profile_id, created_at);

CREATE TABLE IF NOT EXISTS commit_runs (
    commit_run_id TEXT PRIMARY KEY,
    pr_run_id TEXT REFERENCES pr_runs(pr_run_id),
    schema_version TEXT NOT NULL,
    repo TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    short_sha TEXT NOT NULL,
    ref TEXT,
    observed_at TEXT NOT NULL,
    case_schema_version TEXT NOT NULL,
    case_hash TEXT,
    primary_classification TEXT NOT NULL,
    primary_confidence TEXT,
    primary_reasoning TEXT,
    primary_prompt_version TEXT,
    primary_raw_response_path TEXT,
    primary_raw_content_blocks_json TEXT,
    primary_raw_response_payloads_json TEXT,
    input_tokens INTEGER NOT NULL,
    output_tokens INTEGER NOT NULL,
    latency_ms INTEGER,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_commit_runs_pr_run
    ON commit_runs(pr_run_id);
CREATE INDEX IF NOT EXISTS idx_commit_runs_repo_sha
    ON commit_runs(repo, commit_sha);
CREATE INDEX IF NOT EXISTS idx_commit_runs_classification
    ON commit_runs(primary_classification);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    commit_run_id TEXT NOT NULL REFERENCES commit_runs(commit_run_id),
    finding_index INTEGER NOT NULL,
    finding_type TEXT NOT NULL,
    claim TEXT NOT NULL,
    severity TEXT NOT NULL,
    suggested_action TEXT,
    evidence_refs_json TEXT NOT NULL,
    matrix_status TEXT NOT NULL,
    verifications INTEGER NOT NULL,
    disproofs INTEGER NOT NULL,
    abstains INTEGER NOT NULL,
    verification_ratio REAL NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_commit_run
    ON findings(commit_run_id);
CREATE INDEX IF NOT EXISTS idx_findings_type_status
    ON findings(finding_type, matrix_status);

CREATE TABLE IF NOT EXISTS verifier_votes (
    vote_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    verifier_id TEXT NOT NULL,
    verifier_profile_id TEXT,
    outcome TEXT NOT NULL,
    confidence TEXT,
    rationale TEXT,
    evidence_refs_json TEXT NOT NULL,
    input_tokens INTEGER,
    output_tokens INTEGER,
    latency_ms INTEGER,
    raw_response_path TEXT,
    raw_content_blocks_json TEXT,
    raw_response_payloads_json TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_verifier_votes_finding
    ON verifier_votes(finding_id);
CREATE INDEX IF NOT EXISTS idx_verifier_votes_outcome
    ON verifier_votes(outcome);

CREATE TABLE IF NOT EXISTS commit_judgment_votes (
    vote_id TEXT PRIMARY KEY,
    commit_run_id TEXT NOT NULL REFERENCES commit_runs(commit_run_id),
    target_classification TEXT NOT NULL,
    verifier_id TEXT NOT NULL,
    verifier_profile_id TEXT,
    outcome TEXT NOT NULL,
    confidence TEXT,
    rationale TEXT,
    evidence_refs_json TEXT NOT NULL,
    input_tokens INTEGER,
    output_tokens INTEGER,
    latency_ms INTEGER,
    raw_response_path TEXT,
    raw_content_blocks_json TEXT,
    raw_response_payloads_json TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_commit_judgment_votes_commit_run
    ON commit_judgment_votes(commit_run_id);
CREATE INDEX IF NOT EXISTS idx_commit_judgment_votes_outcome
    ON commit_judgment_votes(outcome);

CREATE TABLE IF NOT EXISTS benign_challenges (
    challenge_id TEXT PRIMARY KEY,
    commit_run_id TEXT NOT NULL REFERENCES commit_runs(commit_run_id),
    challenge_prompt_version TEXT,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    decision TEXT,
    confidence TEXT,
    reasoning TEXT,
    evidence_refs_json TEXT NOT NULL,
    candidate_findings_json TEXT NOT NULL,
    input_tokens INTEGER,
    output_tokens INTEGER,
    latency_ms INTEGER,
    raw_response_path TEXT,
    raw_content_blocks_json TEXT,
    raw_response_payloads_json TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_benign_challenges_commit_run
    ON benign_challenges(commit_run_id);
CREATE INDEX IF NOT EXISTS idx_benign_challenges_decision
    ON benign_challenges(decision);
"""

SCHEMA_COLUMN_MIGRATIONS: dict[str, list[tuple[str, str]]] = {
    "commit_runs": [
        ("primary_reasoning", "TEXT"),
        ("primary_raw_content_blocks_json", "TEXT"),
        ("primary_raw_response_payloads_json", "TEXT"),
        ("profile_id", "TEXT"),
        ("model_id", "TEXT"),
    ],
    "verifier_votes": [
        ("raw_content_blocks_json", "TEXT"),
        ("raw_response_payloads_json", "TEXT"),
    ],
}


def compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))



def make_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:20]}"




def connect_sqlite(db_path: Path) -> sqlite3.Connection:
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def _table_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table_name})")}


def _apply_schema_column_migrations(conn: sqlite3.Connection) -> None:
    for table_name, columns in SCHEMA_COLUMN_MIGRATIONS.items():
        existing = _table_columns(conn, table_name)
        for column_name, column_type in columns:
            if column_name in existing:
                continue
            conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")


_POST_MIGRATION_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_commit_runs_profile ON commit_runs(profile_id, created_at)",
]


def ensure_sqlite_schema(db_path: Path) -> None:
    conn = connect_sqlite(db_path)
    try:
        conn.executescript(SCHEMA_SQL)
        _apply_schema_column_migrations(conn)
        for idx_sql in _POST_MIGRATION_INDEXES:
            conn.execute(idx_sql)
        conn.commit()
    finally:
        conn.close()


def _github_payload(
    payload: dict[str, Any],
    *,
    github_run_id: str,
    github_job_id: str,
    github_check_run_id: str,
    github_run_url: str,
) -> dict[str, Any]:
    existing = payload.get("github") or {}
    pr = payload.get("pr") or {}
    return {
        "repo": existing.get("repo") or pr.get("repo") or "",
        "pr_number": existing.get("pr_number") or pr.get("pr_number"),
        "base_sha": existing.get("base_sha") or pr.get("base_sha") or "",
        "head_sha": existing.get("head_sha") or pr.get("head_sha") or "",
        "merge_base": existing.get("merge_base") or pr.get("merge_base") or "",
        "base_ref": existing.get("base_ref") or pr.get("base_ref") or "",
        "head_ref": existing.get("head_ref") or pr.get("head_ref") or "",
        "workflow_run_id": github_run_id.strip() or existing.get("workflow_run_id") or "",
        "job_id": github_job_id.strip() or existing.get("job_id") or "",
        "check_run_id": github_check_run_id.strip() or existing.get("check_run_id") or "",
        "workflow_run_url": github_run_url.strip() or existing.get("workflow_run_url") or "",
    }


def _benign_challenge_evidence_refs(challenge_result: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for item in challenge_result.get("candidate_findings") or []:
        for ref in item.get("evidence_refs") or []:
            text = str(ref).strip()
            if text and text not in refs:
                refs.append(text)
    return refs


def persist_shadow_pr_payload(
    db_path: Path,
    payload: dict[str, Any],
    *,
    profile_id: str,
    runner: str,
    model_id: str,
    harness_git_sha: str,
    verifier_bundle_version: str = DEFAULT_VERIFIER_BUNDLE_VERSION,
    github_run_id: str = "",
    github_job_id: str = "",
    github_check_run_id: str = "",
    github_run_url: str = "",
    cost_usd_estimate: float | None = None,
) -> dict[str, Any]:
    ensure_sqlite_schema(db_path)
    conn = connect_sqlite(db_path)
    try:
        pr = payload.get("pr") or {}
        summary = payload.get("summary") or {}
        total_usage = payload.get("total_usage") or {}
        created_at = payload.get("generated_at_utc") or now_utc_iso()
        commit_payloads = payload.get("commit_runs") or []
        first_case = ((commit_payloads[0].get("case") or {}) if commit_payloads else {})
        github = _github_payload(
            payload,
            github_run_id=github_run_id,
            github_job_id=github_job_id,
            github_check_run_id=github_check_run_id,
            github_run_url=github_run_url,
        )
        pr_run_id = make_id("prr")

        with conn:
            conn.execute(
                """
                INSERT INTO pr_runs (
                    pr_run_id, schema_version, repo, pr_number, base_sha, head_sha, merge_base,
                    base_ref, head_ref, observed_at, profile_id, runner, model_id, harness_git_sha,
                    case_schema_version, primary_prompt_version, verifier_bundle_version,
                    github_run_id, github_job_id, github_check_run_id, github_run_url,
                    classification_counts_json, matrix_status_counts_json, commits_total, findings_total,
                    verified_findings_total, surviving_findings_total, input_tokens, output_tokens,
                    cost_usd_estimate, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    pr_run_id,
                    PR_RUN_STORE_SCHEMA_VERSION,
                    pr.get("repo") or github.get("repo") or "",
                    pr.get("pr_number") or github.get("pr_number") or 0,
                    pr.get("base_sha") or github.get("base_sha") or "",
                    pr.get("head_sha") or github.get("head_sha") or "",
                    pr.get("merge_base") or github.get("merge_base") or "",
                    pr.get("base_ref") or github.get("base_ref") or "",
                    pr.get("head_ref") or github.get("head_ref") or "",
                    pr.get("observed_at") or "",
                    profile_id,
                    runner,
                    model_id,
                    harness_git_sha,
                    first_case.get("case_schema_version") or "",
                    ((commit_payloads[0].get("primary_result") or {}).get("primary_prompt_version") if commit_payloads else ""),
                    verifier_bundle_version,
                    github.get("workflow_run_id") or "",
                    github.get("job_id") or "",
                    github.get("check_run_id") or "",
                    github.get("workflow_run_url") or "",
                    compact_json(summary.get("classification_counts") or {}),
                    compact_json(summary.get("matrix_status_counts") or {}),
                    int(summary.get("commits_total") or 0),
                    int(summary.get("findings_total") or 0),
                    int(summary.get("verified_findings_total") or 0),
                    int(summary.get("surviving_findings_total") or 0),
                    int(total_usage.get("input_tokens") or 0),
                    int(total_usage.get("output_tokens") or 0),
                    cost_usd_estimate,
                    created_at,
                ),
            )

            persisted_commit_runs: list[dict[str, str]] = []
            total_findings = 0
            total_votes = 0
            total_commit_judgment_votes = 0
            total_benign_challenges = 0
            for commit_payload in commit_payloads:
                case = commit_payload.get("case") or {}
                primary_result = commit_payload.get("primary_result") or {}
                commit_usage = commit_payload.get("total_usage") or {}
                commit_run_id = make_id("cr")
                persisted_commit_runs.append(
                    {
                        "commit_run_id": commit_run_id,
                        "commit_sha": case.get("commit_sha", ""),
                    }
                )
                conn.execute(
                    """
                    INSERT INTO commit_runs (
                        commit_run_id, pr_run_id, schema_version, repo, commit_sha, short_sha, ref,
                        observed_at, case_schema_version, case_hash, primary_classification,
                        primary_confidence, primary_reasoning, primary_prompt_version,
                        primary_raw_response_path, primary_raw_content_blocks_json,
                        primary_raw_response_payloads_json,
                        input_tokens, output_tokens, latency_ms, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        commit_run_id,
                        pr_run_id,
                        COMMIT_RUN_STORE_SCHEMA_VERSION,
                        case.get("repo", ""),
                        case.get("commit_sha", ""),
                        case.get("short_sha", ""),
                        ((case.get("realtime_observation") or {}).get("ref") or ""),
                        ((case.get("realtime_observation") or {}).get("observed_at_utc") or ""),
                        case.get("case_schema_version") or "",
                        case.get("case_hash") or "",
                        primary_result.get("classification", "unknown"),
                        primary_result.get("confidence", ""),
                        primary_result.get("reasoning", ""),
                        primary_result.get("primary_prompt_version", ""),
                        "",
                        compact_json(primary_result.get("raw_content_blocks") or []),
                        compact_json(primary_result.get("raw_response_payloads") or []),
                        int(commit_usage.get("input_tokens") or 0),
                        int(commit_usage.get("output_tokens") or 0),
                        None,
                        created_at,
                    ),
                )

                benign_challenge_result = commit_payload.get("benign_challenge_result") or {}
                challenge_status = str(benign_challenge_result.get("status") or "").strip().lower()
                if challenge_status in {"executed", "error"}:
                    challenge_usage = benign_challenge_result.get("usage") or {}
                    challenge_id = make_id("bc")
                    conn.execute(
                        """
                        INSERT INTO benign_challenges (
                            challenge_id, commit_run_id, challenge_prompt_version, mode, status,
                            decision, confidence, reasoning, evidence_refs_json,
                            candidate_findings_json, input_tokens, output_tokens, latency_ms,
                            raw_response_path, raw_content_blocks_json,
                            raw_response_payloads_json, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            challenge_id,
                            commit_run_id,
                            benign_challenge_result.get("prompt_version", ""),
                            benign_challenge_result.get("mode", ""),
                            challenge_status,
                            benign_challenge_result.get("decision", ""),
                            benign_challenge_result.get("confidence", ""),
                            benign_challenge_result.get("reasoning", ""),
                            compact_json(_benign_challenge_evidence_refs(benign_challenge_result)),
                            compact_json(benign_challenge_result.get("candidate_findings") or []),
                            challenge_usage.get("input_tokens"),
                            challenge_usage.get("output_tokens"),
                            None,
                            "",
                            compact_json(benign_challenge_result.get("raw_content_blocks") or []),
                            compact_json(benign_challenge_result.get("raw_response_payloads") or []),
                            created_at,
                        ),
                    )
                    total_benign_challenges += 1

                commit_judgment_verification = commit_payload.get("commit_judgment_verification") or {}
                judgment_votes = commit_judgment_verification.get("votes") or []
                for vote in judgment_votes:
                    usage = vote.get("usage") or {}
                    conn.execute(
                        """
                        INSERT INTO commit_judgment_votes (
                            vote_id, commit_run_id, target_classification, verifier_id, verifier_profile_id,
                            outcome, confidence, rationale, evidence_refs_json, input_tokens,
                            output_tokens, latency_ms, raw_response_path,
                            raw_content_blocks_json, raw_response_payloads_json, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            make_id("cjv"),
                            commit_run_id,
                            commit_judgment_verification.get("target_classification", ""),
                            vote.get("verifier_id", ""),
                            profile_id,
                            vote.get("outcome", "abstain"),
                            vote.get("confidence", ""),
                            vote.get("rationale", ""),
                            compact_json(vote.get("evidence_refs") or []),
                            usage.get("input_tokens"),
                            usage.get("output_tokens"),
                            None,
                            "",
                            compact_json(vote.get("raw_content_blocks") or []),
                            compact_json(vote.get("raw_response_payloads") or []),
                            created_at,
                        ),
                    )
                    total_commit_judgment_votes += 1

                verifier_results = commit_payload.get("verifier_results") or []
                for finding_index, verifier_result in enumerate(verifier_results):
                    finding = verifier_result.get("finding") or {}
                    matrix = verifier_result.get("matrix") or {}
                    finding_id = finding.get("finding_id") or make_id("fd")
                    conn.execute(
                        """
                        INSERT INTO findings (
                            finding_id, commit_run_id, finding_index, finding_type, claim, severity,
                            suggested_action, evidence_refs_json, matrix_status, verifications,
                            disproofs, abstains, verification_ratio, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            finding_id,
                            commit_run_id,
                            finding_index,
                            finding.get("finding_type", "other"),
                            finding.get("claim", ""),
                            finding.get("severity", "unknown"),
                            finding.get("suggested_action", ""),
                            compact_json(finding.get("evidence_refs") or []),
                            matrix.get("status", "unknown"),
                            int(matrix.get("verifications") or 0),
                            int(matrix.get("disproofs") or 0),
                            int(matrix.get("abstains") or 0),
                            float(matrix.get("verification_ratio") or 0.0),
                            created_at,
                        ),
                    )
                    total_findings += 1

                    votes = verifier_result.get("votes") or []
                    for vote in votes:
                        usage = vote.get("usage") or {}
                        vote_id = vote.get("vote_id") or make_id("vv")
                        conn.execute(
                            """
                            INSERT INTO verifier_votes (
                                vote_id, finding_id, verifier_id, verifier_profile_id, outcome,
                                confidence, rationale, evidence_refs_json, input_tokens,
                                output_tokens, latency_ms, raw_response_path,
                                raw_content_blocks_json, raw_response_payloads_json, created_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                vote_id,
                                finding_id,
                                vote.get("verifier_id", ""),
                                vote.get("verifier_profile_id", ""),
                                vote.get("outcome", "abstain"),
                                vote.get("confidence", ""),
                                vote.get("rationale", ""),
                                compact_json(vote.get("evidence_refs") or []),
                                usage.get("input_tokens"),
                                usage.get("output_tokens"),
                                None,
                                "",
                                compact_json(vote.get("raw_content_blocks") or []),
                                compact_json(vote.get("raw_response_payloads") or []),
                                created_at,
                            ),
                        )
                        total_votes += 1

        return {
            "pr_run_id": pr_run_id,
            "commit_runs": persisted_commit_runs,
            "benign_challenges_written": total_benign_challenges,
            "commit_judgment_votes_written": total_commit_judgment_votes,
            "findings_written": total_findings,
            "verifier_votes_written": total_votes,
        }
    finally:
        conn.close()


def persist_shadow_commit_payload(
    db_path: Path,
    payload: dict[str, Any],
    *,
    profile_id: str,
    runner: str,
    model_id: str,
    harness_git_sha: str,
    verifier_bundle_version: str = DEFAULT_VERIFIER_BUNDLE_VERSION,
    cost_usd_estimate: float | None = None,
) -> dict[str, Any]:
    del verifier_bundle_version, cost_usd_estimate
    ensure_sqlite_schema(db_path)
    conn = connect_sqlite(db_path)
    try:
        case = payload.get("case") or {}
        primary_result = payload.get("primary_result") or {}
        total_usage = payload.get("total_usage") or {}
        created_at = payload.get("generated_at_utc") or now_utc_iso()
        commit_run_id = make_id("cr")

        with conn:
            conn.execute(
                """
                INSERT INTO commit_runs (
                    commit_run_id, pr_run_id, schema_version, repo, commit_sha, short_sha, ref,
                    observed_at, case_schema_version, case_hash, primary_classification,
                    primary_confidence, primary_reasoning, primary_prompt_version,
                    primary_raw_response_path, primary_raw_content_blocks_json,
                    primary_raw_response_payloads_json,
                    input_tokens, output_tokens, latency_ms, created_at,
                    profile_id, model_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    commit_run_id,
                    None,
                    COMMIT_RUN_STORE_SCHEMA_VERSION,
                    case.get("repo", ""),
                    case.get("commit_sha", ""),
                    case.get("short_sha", ""),
                    ((case.get("realtime_observation") or {}).get("ref") or ""),
                    ((case.get("realtime_observation") or {}).get("observed_at_utc") or created_at),
                    case.get("case_schema_version") or "",
                    case.get("case_hash") or "",
                    primary_result.get("classification", "unknown"),
                    primary_result.get("confidence", ""),
                    primary_result.get("reasoning", ""),
                    primary_result.get("primary_prompt_version", ""),
                    "",
                    compact_json(primary_result.get("raw_content_blocks") or []),
                    compact_json(primary_result.get("raw_response_payloads") or []),
                    int(total_usage.get("input_tokens") or 0),
                    int(total_usage.get("output_tokens") or 0),
                    None,
                    created_at,
                    profile_id,
                    model_id,
                ),
            )

            benign_challenge_result = payload.get("benign_challenge_result") or {}
            challenge_status = str(benign_challenge_result.get("status") or "").strip().lower()
            total_benign_challenges = 0
            if challenge_status in {"executed", "error"}:
                challenge_usage = benign_challenge_result.get("usage") or {}
                conn.execute(
                    """
                    INSERT INTO benign_challenges (
                        challenge_id, commit_run_id, challenge_prompt_version, mode, status,
                        decision, confidence, reasoning, evidence_refs_json,
                        candidate_findings_json, input_tokens, output_tokens, latency_ms,
                        raw_response_path, raw_content_blocks_json,
                        raw_response_payloads_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        make_id("bc"),
                        commit_run_id,
                        benign_challenge_result.get("prompt_version", ""),
                        benign_challenge_result.get("mode", ""),
                        challenge_status,
                        benign_challenge_result.get("decision", ""),
                        benign_challenge_result.get("confidence", ""),
                        benign_challenge_result.get("reasoning", ""),
                        compact_json(_benign_challenge_evidence_refs(benign_challenge_result)),
                        compact_json(benign_challenge_result.get("candidate_findings") or []),
                        challenge_usage.get("input_tokens"),
                        challenge_usage.get("output_tokens"),
                        None,
                        "",
                        compact_json(benign_challenge_result.get("raw_content_blocks") or []),
                        compact_json(benign_challenge_result.get("raw_response_payloads") or []),
                        created_at,
                    ),
                )
                total_benign_challenges = 1

            commit_judgment_verification = payload.get("commit_judgment_verification") or {}
            judgment_votes = commit_judgment_verification.get("votes") or []
            total_commit_judgment_votes = 0
            for vote in judgment_votes:
                usage = vote.get("usage") or {}
                conn.execute(
                    """
                    INSERT INTO commit_judgment_votes (
                        vote_id, commit_run_id, target_classification, verifier_id, verifier_profile_id,
                        outcome, confidence, rationale, evidence_refs_json, input_tokens,
                        output_tokens, latency_ms, raw_response_path,
                        raw_content_blocks_json, raw_response_payloads_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        make_id("cjv"),
                        commit_run_id,
                        commit_judgment_verification.get("target_classification", ""),
                        vote.get("verifier_id", ""),
                        profile_id,
                        vote.get("outcome", "abstain"),
                        vote.get("confidence", ""),
                        vote.get("rationale", ""),
                        compact_json(vote.get("evidence_refs") or []),
                        usage.get("input_tokens"),
                        usage.get("output_tokens"),
                        None,
                        "",
                        compact_json(vote.get("raw_content_blocks") or []),
                        compact_json(vote.get("raw_response_payloads") or []),
                        created_at,
                    ),
                )
                total_commit_judgment_votes += 1

            verifier_results = payload.get("verifier_results") or []
            total_findings = 0
            total_votes = 0
            for finding_index, verifier_result in enumerate(verifier_results):
                finding = verifier_result.get("finding") or {}
                matrix = verifier_result.get("matrix") or {}
                finding_id = make_id("fd")
                conn.execute(
                    """
                    INSERT INTO findings (
                        finding_id, commit_run_id, finding_index, finding_type, claim, severity,
                        suggested_action, evidence_refs_json, matrix_status, verifications,
                        disproofs, abstains, verification_ratio, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding_id,
                        commit_run_id,
                        finding_index,
                        finding.get("finding_type", "other"),
                        finding.get("claim", ""),
                        finding.get("severity", "unknown"),
                        finding.get("suggested_action", ""),
                        compact_json(finding.get("evidence_refs") or []),
                        matrix.get("status", "unknown"),
                        int(matrix.get("verifications") or 0),
                        int(matrix.get("disproofs") or 0),
                        int(matrix.get("abstains") or 0),
                        float(matrix.get("verification_ratio") or 0.0),
                        created_at,
                    ),
                )
                total_findings += 1

                votes = verifier_result.get("votes") or []
                for vote in votes:
                    usage = vote.get("usage") or {}
                    vote_id = make_id("vv")
                    conn.execute(
                        """
                        INSERT INTO verifier_votes (
                            vote_id, finding_id, verifier_id, verifier_profile_id, outcome,
                            confidence, rationale, evidence_refs_json, input_tokens,
                            output_tokens, latency_ms, raw_response_path,
                            raw_content_blocks_json, raw_response_payloads_json, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            vote_id,
                            finding_id,
                            vote.get("verifier_id", ""),
                            profile_id,
                            vote.get("outcome", "abstain"),
                            vote.get("confidence", ""),
                            vote.get("rationale", ""),
                            compact_json(vote.get("evidence_refs") or []),
                            usage.get("input_tokens"),
                            usage.get("output_tokens"),
                            None,
                            "",
                            compact_json(vote.get("raw_content_blocks") or []),
                            compact_json(vote.get("raw_response_payloads") or []),
                            created_at,
                        ),
                    )
                    total_votes += 1

        return {
            "commit_run_id": commit_run_id,
            "repo": case.get("repo", ""),
            "commit_sha": case.get("commit_sha", ""),
            "profile_id": profile_id,
            "runner": runner,
            "model_id": model_id,
            "harness_git_sha": harness_git_sha,
            "benign_challenges_written": total_benign_challenges,
            "commit_judgment_votes_written": total_commit_judgment_votes,
            "findings_written": total_findings,
            "verifier_votes_written": total_votes,
        }
    finally:
        conn.close()
