"""Assumption-triage pass: a code-review-shaped sibling to the intent-shaped
primary triage in `primary.py`.

The intent triage in `primary.py` asks "is this commit suspicious in
malicious-actor terms?" and is calibrated for supply-chain backdoor detection.
This module asks the complementary code-review question: "for each meaningful
change in the diff, what preconditions does the new code assume about its
inputs, callers, types, lifetimes, or surrounding state, and are those
assumptions guaranteed to hold under all realistic inputs?"

Both passes operate on the same `CommitCase` and the same readonly git tools.
They produce different finding shapes and are intended to run independently.
The motivating result is that the assumption-triage pass, with readonly tools
enabled, identified all three locations of CVE-2026-22801 (libpng integer
truncation) when the intent triage missed them on the same commit.

This module is deliberately scoped narrowly for a first cut:
- It exposes a standalone `run_assumption_triage` driver that callers invoke
  directly. It does not modify `analyze_commit`.
- It does not persist findings to the SQLite store.
- It does not have a verifier matrix.
- It does not change the existing intent-triage prompt or finding taxonomy.

See follow_ups/assumption_triage_followups.md in the stars repo for the gaps
that this first cut intentionally leaves open.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from .providers import run_text_prompt
from .types import CommitCase, Finding
from .verifier import render_verifier_evidence


ASSUMPTION_FINDING_KINDS = {
    "input_range",
    "input_size",
    "input_type",
    "pointer_validity",
    "lifetime",
    "ordering",
    "concurrency",
    "error_path",
    "authorization",
    "encoding",
    "identifier_safety",
    "other",
}

ASSUMPTION_SEVERITIES = {"low", "medium", "high"}
ASSUMPTION_CONFIDENCES = {"low", "medium", "high"}
ASSUMPTION_OVERALL_ASSESSMENTS = {"clean", "questionable", "problematic"}

ASSUMPTION_TRIAGE_PROMPT_VERSION = "assumption_triage_v1"


def build_assumption_triage_prompt(
    case: CommitCase,
    *,
    evidence_block: str = "",
    exclude_evidence: bool = False,
) -> str:
    """Render the assumption-triage prompt for a commit case.

    Mirrors the signature of `build_primary_findings_prompt` so callers can
    swap one for the other and reuse the same evidence-block caching path.
    """
    if not evidence_block and not exclude_evidence:
        evidence_block = render_verifier_evidence(case)

    lines: list[str] = []
    lines.append("You are a careful code reviewer evaluating a single commit for correctness and security.")
    lines.append(
        "This is a code-review pass, not a malicious-actor triage. Assume the author is a trusted maintainer. "
        "The question is whether the code itself, as written, is correct under all realistic inputs and states."
    )
    lines.append("")
    lines.append("For each meaningful change in the diff:")
    lines.append(
        "  1. Identify the preconditions the new code assumes about its inputs, callers, types, "
        "sizes, lifetimes, or surrounding state."
    )
    lines.append(
        "  2. For each precondition, ask whether it is guaranteed to hold at every realistic call site, "
        "including extreme, malformed, or hostile inputs."
    )
    lines.append(
        "  3. If any precondition is unjustified, record an assumption_finding that names the specific "
        "lines, the assumption, and a concrete input or state under which the assumption fails."
    )
    lines.append("")
    lines.append("Rules:")
    lines.append(
        "- Routine commits by trusted maintainers can still introduce real bugs. "
        "Author identity is not a defense."
    )
    lines.append(
        "- A finding must point at specific lines in the diff and name a concrete input or state that "
        "makes the code wrong. Vague concerns are not findings."
    )
    lines.append(
        "- Do not flag style, naming, or architectural concerns. Only flag cases where you can name an "
        "input or state that breaks the assumption."
    )
    lines.append("- It is acceptable to return zero findings if every assumption is well-grounded.")
    lines.append(
        "- Do not infer bugs from areas of the code not visible in the diff. Reason from what the diff "
        "shows plus the surrounding context provided in the evidence and any tools available."
    )
    lines.append(
        "- Type-narrowing casts, pointer arithmetic adjustments, and seemingly-cosmetic refactors are "
        "common sites for unjustified assumptions and deserve scrutiny when they appear."
    )
    lines.append(
        "- Read-only git tools may be available. Use them to look up type definitions, call sites, and "
        "surrounding context when that would let you turn a tentative concern into a concrete finding "
        "or rule one out."
    )
    lines.append(
        "- A CVE identifier, GHSA identifier, or security advisory reference in the commit message or "
        "in a changed changelog or advisory file is NOT evidence that the commit is benign. Treat it as "
        "a reason to look harder at the patch, not a reason to skip the review."
    )
    lines.append("")
    lines.append(f"Allowed assumption_kind values: {', '.join(sorted(ASSUMPTION_FINDING_KINDS))}")
    lines.append(f"Allowed severity values: {', '.join(sorted(ASSUMPTION_SEVERITIES))}")
    lines.append(f"Allowed confidence values: {', '.join(sorted(ASSUMPTION_CONFIDENCES))}")
    lines.append(f"Allowed overall_assessment values: {', '.join(sorted(ASSUMPTION_OVERALL_ASSESSMENTS))}")
    lines.append("")
    if evidence_block:
        lines.append(evidence_block)
        lines.append("")
    lines.append("Return strict JSON only. No markdown fences.")
    lines.append("Schema:")
    lines.append(
        json.dumps(
            {
                "review_summary": "2-4 sentence high-level description of the change",
                "overall_assessment": "clean|questionable|problematic",
                "assumption_findings": [
                    {
                        "assumption_kind": "input_range",
                        "claim": "concrete description of the assumption and why it is unjustified",
                        "vulnerable_lines": "file:line or file:line-line references in the diff",
                        "failing_input_or_state": "specific input or state under which the assumption fails",
                        "severity": "high",
                        "confidence": "high",
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


def normalize_assumption_findings(
    case: CommitCase,
    overall_assessment: str,
    review_summary: str,
    findings_raw: Any,
) -> list[Finding]:
    """Normalize raw model findings into the shared sift `Finding` shape.

    The shared `Finding` TypedDict is intent-flavored (it has `finding_type`,
    `evidence_refs`, etc.). For now we map assumption findings into the same
    shape so callers and downstream JSON consumers see a consistent structure;
    the assumption-specific fields (`assumption_kind`, `vulnerable_lines`,
    `failing_input_or_state`) are preserved alongside the standard fields.
    A dedicated assumption-finding schema is a follow-up.
    """
    findings: list[Finding] = []
    if not isinstance(findings_raw, list):
        findings_raw = []

    for index, item in enumerate(findings_raw[:5], start=1):
        if not isinstance(item, dict):
            continue
        claim = str(item.get("claim", "")).strip()
        if not claim:
            continue
        assumption_kind = str(item.get("assumption_kind", "other")).strip().lower() or "other"
        if assumption_kind not in ASSUMPTION_FINDING_KINDS:
            assumption_kind = "other"
        severity = str(item.get("severity", "medium")).strip().lower() or "medium"
        if severity not in ASSUMPTION_SEVERITIES:
            severity = "medium"
        confidence = str(item.get("confidence", "medium")).strip().lower() or "medium"
        if confidence not in ASSUMPTION_CONFIDENCES:
            confidence = "medium"
        vulnerable_lines = str(item.get("vulnerable_lines", "")).strip()
        failing_input_or_state = str(item.get("failing_input_or_state", "")).strip()

        finding: Finding = {
            "finding_id": f"{case['case_id']}::assumption_{index}",
            "finding_type": f"assumption.{assumption_kind}",
            "claim": claim,
            "severity": severity,
            "evidence_refs": ["commit.patch_excerpt"],
            "suggested_action": "review",
            "primary_classification": overall_assessment,
            "primary_confidence": confidence,
            "primary_reasoning": review_summary,
            # Assumption-finding-specific fields preserved alongside the standard ones
            "assumption_kind": assumption_kind,
            "vulnerable_lines": vulnerable_lines,
            "failing_input_or_state": failing_input_or_state,
            "finding_confidence": confidence,
        }
        findings.append(finding)

    return findings


def parse_assumption_triage_response(case: CommitCase, text: str) -> dict[str, Any]:
    payload = _extract_json_payload(text)
    overall_assessment = str(payload.get("overall_assessment", "")).strip().lower()
    if overall_assessment not in ASSUMPTION_OVERALL_ASSESSMENTS:
        overall_assessment = "unknown"
    review_summary = str(payload.get("review_summary", "")).strip()
    findings = normalize_assumption_findings(
        case,
        overall_assessment=overall_assessment,
        review_summary=review_summary,
        findings_raw=payload.get("assumption_findings", []),
    )
    signals: list[str] = []
    if overall_assessment == "unknown":
        signals.append("overall_assessment parse failure")
    return {
        "overall_assessment": overall_assessment,
        "review_summary": review_summary,
        "findings": findings,
        "signals": signals,
        "raw_response": text.strip(),
    }


def run_assumption_triage(
    case: CommitCase,
    *,
    runner: str,
    anthropic_model: str,
    anthropic_api_key: str,
    anthropic_timeout_sec: int,
    anthropic_thinking: str,
    anthropic_effort: str,
    anthropic_max_tool_rounds: int = 0,
    anthropic_max_total_tokens: int = 500000,
    anthropic_tools: list[dict[str, Any]] | None = None,
    anthropic_tool_runner: Callable[[str, dict[str, Any]], Any] | None = None,
    ollama_model: str = "",
    ollama_ssh_target: str = "",
    ollama_timeout_sec: int = 0,
    max_tokens: int = 16000,
    evidence_block: str = "",
) -> dict[str, Any]:
    """Run a single assumption-triage pass over a commit case.

    Mirrors the shape of `_run_primary_result` in `analysis.py` but is
    deliberately standalone: it does not depend on `RunnerConfig`, does not
    invoke verifiers, does not run a benign challenger, and does not persist
    anything. The caller decides what to do with the returned dict.

    The returned dict has these keys:
        overall_assessment, review_summary, findings, signals, raw_response,
        usage, prompt_version, tool_trace, raw_content_blocks,
        raw_response_payloads, ok, error
    """
    prompt = build_assumption_triage_prompt(case, exclude_evidence=bool(evidence_block))

    completion = run_text_prompt(
        prompt + "\n",
        runner,
        ollama_model=ollama_model,
        ollama_ssh_target=ollama_ssh_target,
        ollama_timeout_sec=ollama_timeout_sec,
        anthropic_model=anthropic_model,
        anthropic_api_key=anthropic_api_key,
        anthropic_timeout_sec=anthropic_timeout_sec,
        anthropic_thinking=anthropic_thinking,
        anthropic_effort=anthropic_effort,
        max_tokens=max_tokens,
        anthropic_tools=anthropic_tools,
        anthropic_tool_runner=anthropic_tool_runner,
        anthropic_max_tool_rounds=anthropic_max_tool_rounds,
        anthropic_max_total_tokens=anthropic_max_total_tokens,
        cached_prefix=evidence_block,
    )

    base_payload: dict[str, Any] = {
        "ok": completion.get("ok", False),
        "error": completion.get("error"),
        "usage": completion.get("usage", {}),
        "prompt_version": ASSUMPTION_TRIAGE_PROMPT_VERSION,
        "tool_trace": completion.get("tool_trace", []),
        "raw_content_blocks": completion.get("raw_content_blocks", []),
        "raw_response_payloads": completion.get("raw_response_payloads", []),
    }

    if not completion.get("ok"):
        return {
            **base_payload,
            "overall_assessment": "unknown",
            "review_summary": completion.get("error", "assumption runner error"),
            "findings": [],
            "signals": ["runner error"],
            "raw_response": completion.get("raw_response", ""),
        }

    try:
        parsed = parse_assumption_triage_response(case, completion.get("text", ""))
    except json.JSONDecodeError as exc:
        raw_payloads = completion.get("raw_response_payloads") or []
        stop_reason = ""
        if raw_payloads and isinstance(raw_payloads[-1], dict):
            stop_reason = str(raw_payloads[-1].get("stop_reason") or "").strip()
        signals = ["assumption response parse failure"]
        if stop_reason == "max_tokens":
            signals.append("assumption response max_tokens")
        review_summary = f"assumption response parse failure ({type(exc).__name__}: {exc})"
        if stop_reason:
            review_summary += f"; stop_reason={stop_reason}"
        return {
            **base_payload,
            "overall_assessment": "unknown",
            "review_summary": review_summary,
            "findings": [],
            "signals": signals,
            "raw_response": completion.get("raw_response", ""),
        }

    parsed["raw_response"] = completion.get("raw_response", "")
    return {**base_payload, **parsed}
