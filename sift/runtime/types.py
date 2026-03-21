from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeAlias, TypedDict


@dataclass(frozen=True)
class GroundTruthCommit:
    repo: str
    incident: str
    sha: str
    short_sha: str
    label: str
    cwe_type: str
    paper_window: dict[str, str] | None
    present_in_persisted_mirror: bool
    recovery_source: str
    gharchive_file: str
    gharchive_push_created_at: str
    gharchive_actor_login: str
    commit_author_name: str
    commit_author_email: str
    commit_message: str
    selection_reason: str = ""


@dataclass(frozen=True)
class GHArchivePushEvent:
    source_file: str
    created_at: str
    actor_id: str
    actor_login: str
    repo_id: str
    repo_name: str
    ref: str
    push_before_sha: str
    push_head_sha: str
    push_size: int | None
    push_distinct_size: int | None
    forced_push: bool
    commit_sha: str
    commit_author_name: str
    commit_author_email: str
    commit_message: str
    commit_distinct: bool
    commit_api_url: str


@dataclass(frozen=True)
class RealtimeObservation:
    repo_path: Path
    sha: str
    ref: str
    observed_at: str
    repo: str = ""


class Finding(TypedDict, total=False):
    finding_id: str
    finding_type: str
    claim: str
    severity: str
    evidence_refs: list[str]
    suggested_action: str


class VerifierVote(TypedDict, total=False):
    verifier_id: str
    outcome: str
    confidence: str
    rationale: str
    evidence_refs: list[str]
    raw_response: str
    usage: dict[str, int | None]


class VerificationMatrix(TypedDict, total=False):
    verifications: int
    disproofs: int
    abstains: int
    verification_ratio: float
    status: str


CommitCase: TypeAlias = dict[str, Any]
GHArchiveEventLookup: TypeAlias = dict[tuple[str, str], GHArchivePushEvent]
GHArchiveEventsByRepo: TypeAlias = dict[str, list[GHArchivePushEvent]]
