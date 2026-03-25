from __future__ import annotations

import hashlib
import json
from typing import Any

from .primary import (
    PRIMARY_ACTIONS,
    PRIMARY_FINDING_TYPES,
    PRIMARY_SEVERITIES,
    default_evidence_refs,
)
from .types import CommitCase
from .verifier import render_verifier_evidence


BENIGN_CHALLENGE_PROMPT_VERSION = "benign_challenge_v4"


def should_sample_benign_challenge(repo: str, commit_sha: str, sample_rate: float) -> bool:
    if sample_rate <= 0:
        return False
    if sample_rate >= 1:
        return True
    seed = f"{repo}:{commit_sha}".encode("utf-8")
    bucket = int.from_bytes(hashlib.sha256(seed).digest()[:8], "big") / float(2**64)
    return bucket < sample_rate


def build_benign_challenge_prompt(case: CommitCase) -> str:
    evidence_block = render_verifier_evidence(case)
    allowed_refs = [
        "commit.message",
        "commit.files_changed",
        "commit.stats",
        "commit.patch_excerpt",
        "history_before_commit",
        "history_before_commit.author_identity_history",
        "history_before_commit.author_surface_history",
        "history_before_commit.author_prior_commits_same_email",
        "history_before_commit.author_prior_commits_same_name",
        "history_before_commit.author_previous_commit_same_email_at",
        "gharchive_context",
        "gharchive_context.repo_push_timing",
        "gharchive_context.target_push_event",
        "realtime_observation",
    ]
    lines: list[str] = []
    lines.append("You are an independent challenger reviewing a commit that a separate primary pass labeled benign.")
    lines.append("Your job is to pressure-test that benign decision and surface missed suspicious signals if they exist.")
    lines.append("Do not simply restate why a commit looks normal. Search for concrete reasons it may still warrant review.")
    lines.append("")
    lines.append("Rules:")
    lines.append("- If the benign judgment should stand, set `decision` to `uphold` and return an empty `candidate_findings` array.")
    lines.append("- If the commit still warrants maintainer review, set `decision` to `escalate` and include 1-3 concrete candidate findings.")
    lines.append("- If the evidence is ambiguous or incomplete, set `decision` to `abstain` and keep candidate findings empty unless a specific claim survives.")
    lines.append("- Distinguish the patch author from the committer. In many OSS workflows, the committer is a maintainer/reviewer/merger rather than the patch author.")
    lines.append("- Treat maintainer-behavior deviation as supporting evidence, not sole proof. Escalate only when it is coupled with sensitive changes, unusual paths, thin prior history, or other concrete risk signals.")
    lines.append("- Evidence refs must point to the case fields that support the claim.")
    lines.append("- Do not invent repo history or external context beyond the evidence shown.")
    lines.append("- Read-only git tools may be available; use them when they would materially sharpen an escalation or falsify a weak suspicion.")
    lines.append(
        "- If the patch modifies code that handles resource limits, decompression guards, path sanitization, "
        "input size caps, authentication checks, or access control boundaries, consider escalating with a "
        "finding of type `security_boundary_change`, even when the author is trusted and the change looks routine."
    )
    lines.append(
        "- A CVE identifier, GHSA identifier, or security advisory reference in the commit message or changed "
        "files is a reason to escalate for security review, not a reason to uphold the benign judgment."
    )
    lines.append("")
    lines.append(f"Allowed finding_type values: {', '.join(sorted(PRIMARY_FINDING_TYPES))}")
    lines.append(f"Allowed severity values: {', '.join(sorted(PRIMARY_SEVERITIES))}")
    lines.append(f"Allowed suggested_action values: {', '.join(sorted(PRIMARY_ACTIONS))}")
    lines.append(f"Preferred evidence_refs values: {', '.join(allowed_refs)}")
    lines.append("")
    lines.append(evidence_block)
    lines.append("")
    lines.append("Return strict JSON only. No markdown fences.")
    lines.append("Schema:")
    lines.append(
        json.dumps(
            {
                "decision": "uphold|escalate|abstain",
                "confidence": "low|medium|high",
                "reasoning": "2-4 sentence summary",
                "candidate_findings": [
                    {
                        "finding_type": "dependency_injection",
                        "claim": "specific claim",
                        "severity": "high",
                        "evidence_refs": ["commit.patch_excerpt", "commit.files_changed"],
                        "suggested_action": "review",
                    }
                ],
            },
            ensure_ascii=False,
        )
    )
    return "\n".join(lines)


def _extract_json_payload(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        fence_start = stripped.find("\n")
        fence_end = stripped.rfind("```")
        if fence_start != -1 and fence_end != -1 and fence_end > fence_start:
            stripped = stripped[fence_start + 1:fence_end].strip()
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        first = stripped.find("{")
        last = stripped.rfind("}")
        if first != -1 and last != -1 and last > first:
            return json.loads(stripped[first:last + 1])
        raise


def normalize_candidate_findings(case: CommitCase, findings_raw: Any) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not isinstance(findings_raw, list):
        findings_raw = []

    for item in findings_raw[:3]:
        if not isinstance(item, dict):
            continue
        claim = str(item.get("claim", "")).strip()
        if not claim:
            continue
        finding_type = str(item.get("finding_type", "other")).strip().lower() or "other"
        if finding_type not in PRIMARY_FINDING_TYPES:
            finding_type = "other"
        severity = str(item.get("severity", "medium")).strip().lower() or "medium"
        if severity not in PRIMARY_SEVERITIES:
            severity = "medium"
        suggested_action = str(item.get("suggested_action", "review")).strip().lower() or "review"
        if suggested_action not in PRIMARY_ACTIONS:
            suggested_action = "review"
        evidence_refs = item.get("evidence_refs", [])
        if not isinstance(evidence_refs, list):
            evidence_refs = []
        evidence_refs = [str(ref).strip() for ref in evidence_refs if str(ref).strip()]
        if not evidence_refs:
            evidence_refs = default_evidence_refs(case)
        findings.append(
            {
                "finding_type": finding_type,
                "claim": claim,
                "severity": severity,
                "evidence_refs": evidence_refs,
                "suggested_action": suggested_action,
            }
        )
    return findings


def parse_benign_challenge_response(case: CommitCase, text: str) -> dict[str, Any]:
    signals: list[str] = []
    try:
        payload = _extract_json_payload(text)
    except (json.JSONDecodeError, ValueError):
        payload = {}
        signals.append("json_parse_failure")
    decision = str(payload.get("decision", "")).strip().lower()
    if decision not in {"uphold", "escalate", "abstain"}:
        decision = "abstain"
        signals.append("decision parse failure")
    confidence = str(payload.get("confidence", "")).strip().lower()
    if confidence not in {"low", "medium", "high"}:
        confidence = "unknown"
    reasoning = str(payload.get("reasoning", "")).strip()
    candidate_findings = normalize_candidate_findings(case, payload.get("candidate_findings", []))
    if candidate_findings and decision == "uphold":
        decision = "escalate"
    if decision == "escalate" and not candidate_findings:
        candidate_findings = [
            {
                "finding_type": "other",
                "claim": reasoning or "This commit still appears to warrant maintainer review.",
                "severity": "medium",
                "evidence_refs": default_evidence_refs(case),
                "suggested_action": "review",
            }
        ]
    return {
        "decision": decision,
        "confidence": confidence,
        "reasoning": reasoning,
        "candidate_findings": candidate_findings,
        "signals": signals,
        "raw_response": text.strip(),
    }
