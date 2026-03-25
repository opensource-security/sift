from __future__ import annotations

import json
from typing import Any

from .types import CommitCase, Finding
from .verifier import render_verifier_evidence


PRIMARY_FINDING_TYPES = {
    "dependency_injection",
    "build_ci_change",
    "hidden_network_fetch",
    "suspicious_execution_primitive",
    "identity_anomaly",
    "maintainer_behavior_deviation",
    "obfuscated_payload",
    "secret_exposure",
    "suspicious_persistence",
    "release_process_tampering",
    "security_boundary_change",
    "other",
}

PRIMARY_SEVERITIES = {"low", "medium", "high"}
PRIMARY_ACTIONS = {"ignore", "review", "hold"}
PRIMARY_PROMPT_VERSION = "primary_findings_v9"


def default_evidence_refs(case: CommitCase) -> list[str]:
    refs = [
        "commit.message",
        "commit.files_changed",
        "commit.stats",
        "history_before_commit",
    ]
    if case.get("history_before_commit", {}).get("author_identity_history"):
        refs.append("history_before_commit.author_identity_history")
    if case.get("history_before_commit", {}).get("pr_social_history"):
        refs.append("history_before_commit.pr_social_history")
    if case.get("commit", {}).get("patch_excerpt"):
        refs.append("commit.patch_excerpt")
    if case.get("gharchive_context", {}).get("target_push_event") or case.get("feature_availability", {}).get("realtime_observation_context"):
        refs.append("gharchive_context")
    return refs


def build_primary_findings_prompt(case: CommitCase, *, evidence_block: str = "", exclude_evidence: bool = False) -> str:
    if not evidence_block and not exclude_evidence:
        evidence_block = render_verifier_evidence(case)
    allowed_refs = [
        "commit.message",
        "commit.files_changed",
        "commit.stats",
        "commit.patch_excerpt",
        "history_before_commit",
        "history_before_commit.author_identity_history",
        "history_before_commit.author_surface_history",
        "history_before_commit.pr_social_history",
        "history_before_commit.author_prior_commits_same_email",
        "history_before_commit.author_prior_commits_same_name",
        "history_before_commit.author_previous_commit_same_email_at",
        "gharchive_context",
        "gharchive_context.repo_push_timing",
        "gharchive_context.target_push_event",
        "realtime_observation",
    ]
    lines: list[str] = []
    lines.append("You are the primary inline triage model for supply-chain commit review.")
    lines.append("Review the commit evidence and emit zero or more concrete findings.")
    lines.append("A finding must be a specific, testable claim grounded in the evidence, not a vague statement that the commit feels suspicious.")
    lines.append("Prefer fewer, sharper findings. If the evidence does not support a concrete issue, return no findings.")
    lines.append("")
    lines.append("Rules:")
    lines.append("- If maintainer review is warranted, set `classification` to `suspicious` and include 1-3 findings.")
    lines.append("- If the commit looks ordinary, set `classification` to `benign` and return an empty findings array.")
    lines.append("- Distinguish the patch author from the committer. In many OSS workflows, the committer is a maintainer/reviewer/merger rather than the person who wrote the patch.")
    lines.append("- Treat the history counters in the evidence as author history unless the evidence explicitly says otherwise.")
    lines.append("- Explicitly assess whether the author's timing, path selection, and recent activity align with the bounded repo-local history shown in the evidence.")
    lines.append("- Maintainer-behavior deviation is supporting evidence, not sole proof. Treat it as strong only when it is coupled with sensitive changes, unusual paths, thin prior history, or other concrete risk signals.")
    lines.append("- PR/social metadata is supporting evidence only. Do not treat it as a source of truth for maliciousness.")
    lines.append("- Evidence refs must point to the case fields that support the claim.")
    lines.append("- Do not invent repo history or external context beyond the evidence shown.")
    lines.append("- Do not use a well-known maintainer committer as evidence that the patch author has long-standing repo history when author and committer differ.")
    lines.append("- Do not infer role changes, account takeover, or broader GitHub-ecosystem behavior unless the evidence shown actually supports that claim.")
    lines.append("- Read-only git tools may be available; use them when they would materially sharpen a finding or falsify a weak one.")
    lines.append(
        "- If the patch modifies code that implements resource limits, decompression guards, "
        "path sanitization, input size caps, authentication checks, or access control boundaries, "
        "emit a finding of type `security_boundary_change` with severity proportional to the scope "
        "of the change. This applies even when the author is trusted and the change looks like a clean fix."
    )
    lines.append(
        "- A CVE identifier, GHSA identifier, or security advisory reference in the commit message "
        "or in a changed changelog or advisory file is NOT evidence that the commit is benign. It is "
        "evidence that the commit touches a security-relevant code path. Treat it as a reason to look "
        "harder at the patch, not a reason to close the finding."
    )
    lines.append("")
    lines.append(f"Allowed finding_type values: {', '.join(sorted(PRIMARY_FINDING_TYPES))}")
    lines.append(f"Allowed severity values: {', '.join(sorted(PRIMARY_SEVERITIES))}")
    lines.append(f"Allowed suggested_action values: {', '.join(sorted(PRIMARY_ACTIONS))}")
    lines.append(f"Preferred evidence_refs values: {', '.join(allowed_refs)}")
    lines.append("")
    if evidence_block:
        lines.append(evidence_block)
        lines.append("")
    lines.append("Return strict JSON only. No markdown fences.")
    lines.append("Schema:")
    lines.append(
        json.dumps(
            {
                "classification": "suspicious|benign",
                "confidence": "low|medium|high",
                "reasoning": "2-4 sentence summary",
                "findings": [
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


def normalize_primary_findings(
    case: CommitCase,
    classification: str,
    confidence: str,
    reasoning: str,
    findings_raw: Any,
) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(findings_raw, list):
        findings_raw = []

    for index, item in enumerate(findings_raw[:3], start=1):
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
                "finding_id": f"{case['case_id']}::finding_{index}",
                "finding_type": finding_type,
                "claim": claim,
                "severity": severity,
                "evidence_refs": evidence_refs,
                "suggested_action": suggested_action,
                "primary_classification": classification,
                "primary_confidence": confidence,
                "primary_reasoning": reasoning,
            }
        )

    if classification == "suspicious" and not findings:
        findings.append(
            {
                "finding_id": f"{case['case_id']}::finding_1",
                "finding_type": "other",
                "claim": reasoning or "This commit appears suspicious enough to warrant review.",
                "severity": "medium",
                "evidence_refs": default_evidence_refs(case),
                "suggested_action": "review",
                "primary_classification": classification,
                "primary_confidence": confidence,
                "primary_reasoning": reasoning,
            }
        )
    return findings


def parse_primary_findings_response(case: CommitCase, text: str) -> dict[str, Any]:
    payload = _extract_json_payload(text)
    classification = str(payload.get("classification", "")).strip().lower()
    if classification not in {"suspicious", "benign"}:
        classification = "unknown"
    confidence = str(payload.get("confidence", "")).strip().lower()
    if confidence not in {"low", "medium", "high"}:
        confidence = "unknown"
    reasoning = str(payload.get("reasoning", "")).strip()
    findings = normalize_primary_findings(
        case,
        classification=classification,
        confidence=confidence,
        reasoning=reasoning,
        findings_raw=payload.get("findings", []),
    )
    if findings and classification != "suspicious":
        classification = "suspicious"
    signals: list[str] = []
    if classification == "unknown":
        signals.append("classification parse failure")
    return {
        "classification": classification,
        "confidence": confidence,
        "reasoning": reasoning,
        "score": None,
        "signals": signals,
        "findings": findings,
        "raw_response": text.strip(),
    }


def synthesize_primary_findings(case: CommitCase, primary_result: dict[str, Any]) -> list[Finding]:
    if (primary_result.get("classification") or "").strip().lower() != "suspicious":
        return []

    confidence = (primary_result.get("confidence") or "").strip().lower()
    severity = "medium"
    if confidence == "high":
        severity = "high"
    elif confidence == "low":
        severity = "low"

    claim = "This commit contains enough supply-chain risk indicators to warrant maintainer review."
    reasoning = (primary_result.get("reasoning") or "").strip()
    if reasoning:
        claim = f"{claim} Primary rationale: {reasoning}"

    finding: Finding = {
        "finding_id": f"{case['case_id']}::primary_triage",
        "finding_type": "other",
        "claim": claim,
        "severity": severity,
        "evidence_refs": default_evidence_refs(case),
        "suggested_action": "review",
        "primary_classification": primary_result.get("classification", ""),
        "primary_confidence": primary_result.get("confidence", ""),
        "primary_reasoning": primary_result.get("reasoning", ""),
        "primary_signals": primary_result.get("signals", []),
    }
    return [finding]
