"""
In-process commit analysis API.

This module provides analyze_commit(), the library-level entrypoint for
single-commit analysis. It encapsulates case building, primary triage,
commit-judgment verification, finding-level verification, and benign
challenger execution into a single callable that returns a structured
payload dict.

shadow_commit_run.py and shadow_pr_run.py are thin CLI wrappers over this.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .benign_challenger import (
    BENIGN_CHALLENGE_PROMPT_VERSION,
    build_benign_challenge_prompt,
    parse_benign_challenge_response,
)
from .case_builder import build_realtime_case
from .primary import (
    PRIMARY_PROMPT_VERSION,
    build_primary_findings_prompt,
    parse_primary_findings_response,
    synthesize_primary_findings,
)
from .providers import (
    ANTHROPIC_DEFAULT_EFFORT,
    ANTHROPIC_DEFAULT_MODEL,
    ANTHROPIC_DEFAULT_THINKING,
    OPENAI_DEFAULT_EFFORT,
    OPENAI_DEFAULT_MODEL,
    now_utc_iso,
    run_text_prompt,
)
from .repo_tools import anthropic_readonly_repo_tools, make_repo_tool_runner
from .verifier import (
    VERIFIER_VARIANTS,
    build_commit_judgment_verifier_prompt,
    build_verifier_prompt,
    parse_verifier_response,
    render_verifier_evidence,
    summarize_verifier_votes,
)


ANALYSIS_SCHEMA_VERSION = "shadow_live_v2"
_HARNESS_SCHEMA_VERSION = "commit_harness_v1"
_PROMPT_FORMAT_VERSION = "commit_prompt_v2"


@dataclass
class RunnerConfig:
    """Configuration for the runner, model, and analysis behavior."""

    runner: str = "anthropic"
    ollama_model: str = "gpt-oss:120b"
    ollama_ssh_target: str = ""
    ollama_timeout_sec: int = 900
    anthropic_model: str = ANTHROPIC_DEFAULT_MODEL
    anthropic_api_key: str = ""
    anthropic_timeout_sec: int = 300
    anthropic_thinking: str = ANTHROPIC_DEFAULT_THINKING
    anthropic_effort: str = ANTHROPIC_DEFAULT_EFFORT
    anthropic_tool_mode: str = "readonly"
    anthropic_max_tool_rounds: int = 0
    anthropic_max_total_tokens: int = 500000
    openai_model: str = OPENAI_DEFAULT_MODEL
    openai_api_key: str = ""
    openai_timeout_sec: int = 240
    openai_effort: str = OPENAI_DEFAULT_EFFORT
    verifier_count: int = 3
    quick_panel_size: int = 2
    benign_challenge_mode: str = "off"


@dataclass
class ResultPolicy:
    """Maps analysis results to GitHub-facing actions."""

    maintainer_visible: bool = False
    blocking: bool = False
    requested_action: str = "log_only"

    def to_dict(self) -> dict[str, Any]:
        return {
            "maintainer_visible": self.maintainer_visible,
            "blocking": self.blocking,
            "requested_action": self.requested_action,
        }


# ---------------------------------------------------------------------------
# Replay-specific runners (heuristic, oracle) are not available in sift; sift
# supports only model-backed runners (anthropic, ollama).
# ---------------------------------------------------------------------------

def _get_replay_runners() -> tuple[Any, Any, Any]:
    raise RuntimeError(
        "heuristic and oracle runners are not available in sift. "
        "Use runner='anthropic' or runner='ollama'."
    )


# ---------------------------------------------------------------------------
# Internal helpers (moved from shadow_commit_run.py)
# ---------------------------------------------------------------------------

def _abort_if_auth_error(completion: dict[str, Any]) -> None:
    error = completion.get("error") or ""
    if "HTTP 401" in error or "authentication_error" in error:
        print(f"FATAL: Anthropic API authentication error — check ANTHROPIC_API_KEY: {error}", file=sys.stderr)
        sys.exit(2)


def _add_usage(total_usage: dict[str, int], usage: dict[str, int | None] | None) -> None:
    if not usage:
        return
    total_usage["input_tokens"] += usage.get("input_tokens") or 0
    total_usage["output_tokens"] += usage.get("output_tokens") or 0


def _classification_to_verifier_outcome(classification: str) -> str:
    normalized = (classification or "").strip().lower()
    if normalized == "suspicious":
        return "verify"
    if normalized == "benign":
        return "disprove"
    return "abstain"


def _quick_panel_needs_escalation(votes: list[dict[str, Any]]) -> bool:
    """Return True if any quick-panel vote is abstain or disprove."""
    for vote in votes:
        outcome = str(vote.get("outcome", "")).strip().lower()
        if outcome in {"abstain", "disprove"}:
            return True
    return False


def _default_benign_challenge_result(mode: str, status: str) -> dict[str, Any]:
    return {
        "mode": mode,
        "status": status,
        "decision": "",
        "confidence": "",
        "reasoning": "",
        "candidate_findings": [],
        "signals": [],
        "raw_response": "",
        "usage": {},
        "prompt_version": BENIGN_CHALLENGE_PROMPT_VERSION,
        "tool_trace": [],
        "raw_content_blocks": [],
        "raw_response_payloads": [],
    }


def _default_commit_judgment_verification_result(status: str, target_classification: str = "") -> dict[str, Any]:
    return {
        "scope": "primary_commit_classification",
        "status": status,
        "target_classification": target_classification,
        "votes": [],
        "matrix": summarize_verifier_votes([]),
    }


def _run_text_prompt_with_config(
    prompt: str,
    config: RunnerConfig,
    *,
    max_tokens: int = 16000,
    anthropic_tools: list[dict[str, Any]] | None = None,
    anthropic_tool_runner: Callable[[str, dict[str, Any]], Any] | None = None,
    cached_prefix: str = "",
) -> dict[str, Any]:
    return run_text_prompt(
        prompt,
        config.runner,
        ollama_model=config.ollama_model,
        ollama_ssh_target=config.ollama_ssh_target,
        ollama_timeout_sec=config.ollama_timeout_sec,
        anthropic_model=config.anthropic_model,
        anthropic_api_key=config.anthropic_api_key,
        anthropic_timeout_sec=config.anthropic_timeout_sec,
        anthropic_thinking=config.anthropic_thinking,
        anthropic_effort=config.anthropic_effort,
        max_tokens=max_tokens,
        anthropic_tools=anthropic_tools,
        anthropic_tool_runner=anthropic_tool_runner,
        anthropic_max_tool_rounds=config.anthropic_max_tool_rounds,
        anthropic_max_total_tokens=config.anthropic_max_total_tokens,
        cached_prefix=cached_prefix,
        openai_model=config.openai_model,
        openai_api_key=config.openai_api_key,
        openai_timeout_sec=config.openai_timeout_sec,
        openai_effort=config.openai_effort,
    )


def _run_verifier_vote(
    case: dict[str, Any],
    finding: dict[str, Any],
    variant: dict[str, str],
    config: RunnerConfig,
    *,
    anthropic_tools: list[dict[str, Any]] | None,
    anthropic_tool_runner: Any,
    evidence_block: str = "",
) -> dict[str, Any]:
    if config.runner == "heuristic":
        heuristic_predict, _, _ = _get_replay_runners()
        prediction = heuristic_predict(case, temporal_mode="realtime")
        return {
            "verifier_id": variant["verifier_id"],
            "outcome": _classification_to_verifier_outcome(prediction.get("classification", "")),
            "confidence": prediction.get("confidence", "unknown"),
            "rationale": (
                "Heuristic verifier fallback reused the heuristic classifier. Treat this as a single non-independent "
                "sanity check, not as an independent verifier vote."
            ),
            "evidence_refs": finding.get("evidence_refs", []),
            "raw_response": prediction.get("raw_response", ""),
            "usage": {},
            "tool_trace": [],
            "raw_content_blocks": [],
            "raw_response_payloads": [],
            "independence": "shared_heuristic_fallback",
        }
    if config.runner == "oracle":
        _, oracle_predict, _ = _get_replay_runners()
        prediction = oracle_predict(case)
        return {
            "verifier_id": variant["verifier_id"],
            "outcome": _classification_to_verifier_outcome(prediction.get("classification", "")),
            "confidence": prediction.get("confidence", "unknown"),
            "rationale": "Oracle verifier fallback mirrored the ground-truth label for pipeline validation only.",
            "evidence_refs": finding.get("evidence_refs", []),
            "raw_response": prediction.get("raw_response", ""),
            "usage": {},
            "tool_trace": [],
            "raw_content_blocks": [],
            "raw_response_payloads": [],
            "independence": "oracle_passthrough",
        }

    prompt = build_verifier_prompt(case, finding, variant, exclude_evidence=bool(evidence_block))
    completion = _run_text_prompt_with_config(
        prompt + "\n",
        config,
        anthropic_tools=anthropic_tools,
        anthropic_tool_runner=anthropic_tool_runner,
        cached_prefix=evidence_block,
    )
    _abort_if_auth_error(completion)
    if not completion.get("ok"):
        return {
            "verifier_id": variant["verifier_id"],
            "outcome": "abstain",
            "confidence": "unknown",
            "rationale": completion.get("error", "verifier runner error"),
            "evidence_refs": [],
            "raw_response": completion.get("raw_response", ""),
            "usage": completion.get("usage", {}),
            "tool_trace": completion.get("tool_trace", []),
            "raw_content_blocks": completion.get("raw_content_blocks", []),
            "raw_response_payloads": completion.get("raw_response_payloads", []),
        }

    outcome, confidence, rationale, evidence_refs = parse_verifier_response(completion.get("text", ""))
    return {
        "verifier_id": variant["verifier_id"],
        "outcome": outcome,
        "confidence": confidence,
        "rationale": rationale,
        "evidence_refs": evidence_refs,
        "raw_response": completion.get("raw_response", ""),
        "usage": completion.get("usage", {}),
        "tool_trace": completion.get("tool_trace", []),
        "raw_content_blocks": completion.get("raw_content_blocks", []),
        "raw_response_payloads": completion.get("raw_response_payloads", []),
        "independence": "independent_model_call",
    }


def _run_commit_judgment_vote(
    case: dict[str, Any],
    primary_result: dict[str, Any],
    findings: list[dict[str, Any]],
    variant: dict[str, str],
    config: RunnerConfig,
    *,
    anthropic_tools: list[dict[str, Any]] | None,
    anthropic_tool_runner: Any,
    evidence_block: str = "",
) -> dict[str, Any]:
    classification = str(primary_result.get("classification") or "").strip().lower()
    if config.runner == "heuristic":
        heuristic_predict, _, _ = _get_replay_runners()
        prediction = heuristic_predict(case, temporal_mode="realtime")
        predicted_classification = str(prediction.get("classification") or "").strip().lower()
        if predicted_classification == classification and classification in {"benign", "suspicious"}:
            outcome = "verify"
        elif classification in {"benign", "suspicious"} and predicted_classification in {"benign", "suspicious"}:
            outcome = "disprove"
        else:
            outcome = "abstain"
        return {
            "verifier_id": variant["verifier_id"],
            "target_classification": classification,
            "outcome": outcome,
            "confidence": prediction.get("confidence", "unknown"),
            "rationale": (
                "Heuristic commit-judgment verifier fallback reused the heuristic classifier. Treat this as a single "
                "non-independent sanity check, not as an independent verifier vote."
            ),
            "evidence_refs": ["history_before_commit", "commit.stats"],
            "raw_response": prediction.get("raw_response", ""),
            "usage": {},
            "tool_trace": [],
            "raw_content_blocks": [],
            "raw_response_payloads": [],
            "independence": "shared_heuristic_fallback",
        }
    if config.runner == "oracle":
        _, oracle_predict, _ = _get_replay_runners()
        prediction = oracle_predict(case)
        predicted_classification = str(prediction.get("classification") or "").strip().lower()
        if predicted_classification == classification and classification in {"benign", "suspicious"}:
            outcome = "verify"
        elif classification in {"benign", "suspicious"} and predicted_classification in {"benign", "suspicious"}:
            outcome = "disprove"
        else:
            outcome = "abstain"
        return {
            "verifier_id": variant["verifier_id"],
            "target_classification": classification,
            "outcome": outcome,
            "confidence": prediction.get("confidence", "unknown"),
            "rationale": "Oracle commit-judgment verifier fallback mirrored the ground-truth label for pipeline validation only.",
            "evidence_refs": ["history_before_commit", "commit.stats"],
            "raw_response": prediction.get("raw_response", ""),
            "usage": {},
            "tool_trace": [],
            "raw_content_blocks": [],
            "raw_response_payloads": [],
            "independence": "oracle_passthrough",
        }

    prompt = build_commit_judgment_verifier_prompt(case, primary_result, findings, variant, exclude_evidence=bool(evidence_block))
    completion = _run_text_prompt_with_config(
        prompt + "\n",
        config,
        anthropic_tools=anthropic_tools,
        anthropic_tool_runner=anthropic_tool_runner,
        cached_prefix=evidence_block,
    )
    _abort_if_auth_error(completion)
    if not completion.get("ok"):
        return {
            "verifier_id": variant["verifier_id"],
            "target_classification": classification,
            "outcome": "abstain",
            "confidence": "unknown",
            "rationale": completion.get("error", "commit judgment verifier runner error"),
            "evidence_refs": [],
            "raw_response": completion.get("raw_response", ""),
            "usage": completion.get("usage", {}),
            "tool_trace": completion.get("tool_trace", []),
            "raw_content_blocks": completion.get("raw_content_blocks", []),
            "raw_response_payloads": completion.get("raw_response_payloads", []),
        }

    outcome, confidence, rationale, evidence_refs = parse_verifier_response(completion.get("text", ""))
    return {
        "verifier_id": variant["verifier_id"],
        "target_classification": classification,
        "outcome": outcome,
        "confidence": confidence,
        "rationale": rationale,
        "evidence_refs": evidence_refs,
        "raw_response": completion.get("raw_response", ""),
        "usage": completion.get("usage", {}),
        "tool_trace": completion.get("tool_trace", []),
        "raw_content_blocks": completion.get("raw_content_blocks", []),
        "raw_response_payloads": completion.get("raw_response_payloads", []),
        "independence": "independent_model_call",
    }


def _run_primary_result(
    case: dict[str, Any],
    config: RunnerConfig,
    *,
    anthropic_tools: list[dict[str, Any]] | None,
    anthropic_tool_runner: Any,
    evidence_block: str = "",
) -> dict[str, Any]:
    if config.runner in {"heuristic", "oracle"}:
        _, _, run_runner = _get_replay_runners()
        prediction = run_runner(
            case,
            config.runner,
            temporal_mode="realtime",
            ollama_model=config.ollama_model,
            ollama_ssh_target=config.ollama_ssh_target,
            ollama_timeout_sec=config.ollama_timeout_sec,
            anthropic_model=config.anthropic_model,
            anthropic_api_key=config.anthropic_api_key,
            anthropic_timeout_sec=config.anthropic_timeout_sec,
            anthropic_thinking=config.anthropic_thinking,
            anthropic_effort=config.anthropic_effort,
        )
        prediction["findings"] = synthesize_primary_findings(case, prediction)
        prediction["primary_prompt_version"] = "classification_fallback_v1"
        prediction["tool_trace"] = []
        prediction["raw_content_blocks"] = []
        prediction["raw_response_payloads"] = []
        return prediction

    prompt = build_primary_findings_prompt(case, exclude_evidence=bool(evidence_block))
    completion = _run_text_prompt_with_config(
        prompt + "\n",
        config,
        anthropic_tools=anthropic_tools,
        anthropic_tool_runner=anthropic_tool_runner,
        cached_prefix=evidence_block,
    )
    _abort_if_auth_error(completion)
    if not completion.get("ok"):
        return {
            "classification": "unknown",
            "confidence": "unknown",
            "reasoning": completion.get("error", "primary runner error"),
            "score": None,
            "signals": ["runner error"],
            "findings": [],
            "raw_response": completion.get("raw_response", ""),
            "usage": completion.get("usage", {}),
            "primary_prompt_version": PRIMARY_PROMPT_VERSION,
            "tool_trace": completion.get("tool_trace", []),
            "raw_content_blocks": completion.get("raw_content_blocks", []),
            "raw_response_payloads": completion.get("raw_response_payloads", []),
        }

    try:
        parsed = parse_primary_findings_response(case, completion.get("text", ""))
    except json.JSONDecodeError as exc:
        raw_payloads = completion.get("raw_response_payloads") or []
        stop_reason = ""
        if raw_payloads and isinstance(raw_payloads[-1], dict):
            stop_reason = str(raw_payloads[-1].get("stop_reason") or "").strip()
        signals = ["primary response parse failure"]
        if stop_reason == "max_tokens":
            signals.append("primary response max_tokens")
        reasoning = f"primary response parse failure ({type(exc).__name__}: {exc})"
        if stop_reason:
            reasoning += f"; stop_reason={stop_reason}"
        return {
            "classification": "unknown",
            "confidence": "unknown",
            "reasoning": reasoning,
            "score": None,
            "signals": signals,
            "findings": [],
            "raw_response": completion.get("raw_response", ""),
            "usage": completion.get("usage", {}),
            "primary_prompt_version": PRIMARY_PROMPT_VERSION,
            "tool_trace": completion.get("tool_trace", []),
            "raw_content_blocks": completion.get("raw_content_blocks", []),
            "raw_response_payloads": raw_payloads,
        }
    parsed["raw_response"] = completion.get("raw_response", "")
    parsed["usage"] = completion.get("usage", {})
    parsed["primary_prompt_version"] = PRIMARY_PROMPT_VERSION
    parsed["tool_trace"] = completion.get("tool_trace", [])
    parsed["raw_content_blocks"] = completion.get("raw_content_blocks", [])
    parsed["raw_response_payloads"] = completion.get("raw_response_payloads", [])
    return parsed


def _run_benign_challenge(
    case: dict[str, Any],
    primary_result: dict[str, Any],
    config: RunnerConfig,
    *,
    anthropic_tools: list[dict[str, Any]] | None,
    anthropic_tool_runner: Any,
    evidence_block: str = "",
) -> dict[str, Any]:
    if config.benign_challenge_mode == "off":
        return _default_benign_challenge_result(config.benign_challenge_mode, "disabled")
    if (primary_result.get("classification") or "").strip().lower() != "benign":
        return _default_benign_challenge_result(config.benign_challenge_mode, "skipped_primary_not_benign")
    if config.runner in {"heuristic", "oracle"}:
        return _default_benign_challenge_result(config.benign_challenge_mode, "unsupported_runner")

    prompt = build_benign_challenge_prompt(case, exclude_evidence=bool(evidence_block))
    completion = _run_text_prompt_with_config(
        prompt + "\n",
        config,
        anthropic_tools=anthropic_tools,
        anthropic_tool_runner=anthropic_tool_runner,
        cached_prefix=evidence_block,
    )
    _abort_if_auth_error(completion)
    if not completion.get("ok"):
        result = _default_benign_challenge_result(config.benign_challenge_mode, "error")
        result["reasoning"] = completion.get("error", "benign challenger runner error")
        result["raw_response"] = completion.get("raw_response", "")
        result["usage"] = completion.get("usage", {})
        result["tool_trace"] = completion.get("tool_trace", [])
        result["raw_content_blocks"] = completion.get("raw_content_blocks", [])
        result["raw_response_payloads"] = completion.get("raw_response_payloads", [])
        return result

    parsed = parse_benign_challenge_response(case, completion.get("text", ""))
    parsed["mode"] = config.benign_challenge_mode
    parsed["status"] = "executed"
    parsed["usage"] = completion.get("usage", {})
    parsed["prompt_version"] = BENIGN_CHALLENGE_PROMPT_VERSION
    parsed["raw_response"] = completion.get("raw_response", "")
    parsed["tool_trace"] = completion.get("tool_trace", [])
    parsed["raw_content_blocks"] = completion.get("raw_content_blocks", [])
    parsed["raw_response_payloads"] = completion.get("raw_response_payloads", [])
    return parsed


def _build_primary_result_record(case: dict[str, Any], prediction: dict[str, Any]) -> dict[str, Any]:
    """Build the primary_result dict from case and prediction.

    This replaces the replay-era build_result_record with a version that
    does not require ground-truth labels.
    """
    record = {
        "case_id": case.get("case_id", ""),
        "repo": case.get("repo", ""),
        "commit_sha": case.get("commit_sha", ""),
        "classification": prediction.get("classification", "unknown"),
        "confidence": prediction.get("confidence", "unknown"),
        "reasoning": prediction.get("reasoning", ""),
        "runner_score": prediction.get("score"),
        "signals": prediction.get("signals", []),
        "findings": prediction.get("findings", []),
        "raw_response": prediction.get("raw_response", ""),
        "evidence_state": case.get("evidence_state", ""),
        "commit_present_in_mirror": case.get("commit_present_in_mirror", False),
        "recovery_source": case.get("recovery_source", ""),
    }
    if "usage" in prediction:
        record["usage"] = prediction["usage"]
    if "tool_trace" in prediction:
        record["tool_trace"] = prediction["tool_trace"]
    if "raw_content_blocks" in prediction:
        record["raw_content_blocks"] = prediction["raw_content_blocks"]
    if "raw_response_payloads" in prediction:
        record["raw_response_payloads"] = prediction["raw_response_payloads"]
    # Replay-era fields — set to defaults for realtime path
    record.setdefault("ground_truth", case.get("ground_truth", ""))
    record.setdefault("ground_truth_class", case.get("ground_truth_class", ""))
    return record


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_commit(
    repo_path: Path,
    sha: str,
    ref: str,
    *,
    runner_config: RunnerConfig,
    observed_at: str = "",
    repo: str = "",
    max_patch_chars: int = 12000,
    max_files: int = 200,
    max_author_commits: int = 20,
    max_path_commits: int = 5,
    max_paths_for_history: int = 10,
    max_ref_history_commits: int = 20,
    gharchive_mode: str = "full",
    pr_social_history: dict[str, Any] | None = None,
    full_history_repo_path: Path | None = None,
    result_policy: ResultPolicy | None = None,
    default_branch_ref: str = "",
) -> dict[str, Any]:
    """Analyze a single commit and return the full structured payload.

    Builds a realtime case, runs the primary triage pass, commit-judgment
    verification, finding-level verification, and the optional benign
    challenger. The returned dict is the analysis payload; CLI wrappers add
    profile metadata before writing the JSON artifact.
    """
    if not observed_at:
        observed_at = now_utc_iso()

    config = runner_config

    # Resolve API key from env if not provided
    anthropic_api_key = config.anthropic_api_key
    if config.runner == "anthropic" and not anthropic_api_key:
        anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not anthropic_api_key:
            raise RuntimeError("ANTHROPIC_API_KEY environment variable is required for the anthropic runner")
    openai_api_key = config.openai_api_key
    if config.runner == "openai" and not openai_api_key:
        # Evan's .env uses the OPEN_AI_API_KEY spelling; accept both.
        openai_api_key = os.environ.get("OPENAI_API_KEY", "") or os.environ.get("OPEN_AI_API_KEY", "")
        if not openai_api_key:
            raise RuntimeError(
                "OPENAI_API_KEY (or OPEN_AI_API_KEY) environment variable is required for the openai runner"
            )
    # Build a config copy with the resolved key
    config = RunnerConfig(
        runner=config.runner,
        ollama_model=config.ollama_model,
        ollama_ssh_target=config.ollama_ssh_target,
        ollama_timeout_sec=config.ollama_timeout_sec,
        anthropic_model=config.anthropic_model,
        anthropic_api_key=anthropic_api_key,
        anthropic_timeout_sec=config.anthropic_timeout_sec,
        anthropic_thinking=config.anthropic_thinking,
        anthropic_effort=config.anthropic_effort,
        anthropic_tool_mode=config.anthropic_tool_mode,
        anthropic_max_tool_rounds=config.anthropic_max_tool_rounds,
        anthropic_max_total_tokens=config.anthropic_max_total_tokens,
        openai_model=config.openai_model,
        openai_api_key=openai_api_key,
        openai_timeout_sec=config.openai_timeout_sec,
        openai_effort=config.openai_effort,
        verifier_count=config.verifier_count,
        quick_panel_size=config.quick_panel_size,
        benign_challenge_mode=config.benign_challenge_mode,
    )

    case = build_realtime_case(
        repo_path=repo_path,
        sha=sha,
        ref=ref,
        observed_at=observed_at,
        repo=repo,
        max_patch_chars=max_patch_chars,
        max_files=max_files,
        max_author_commits=max_author_commits,
        max_path_commits=max_path_commits,
        max_paths_for_history=max_paths_for_history,
        max_ref_history_commits=max_ref_history_commits,
        pr_social_history=pr_social_history,
        gharchive_mode=gharchive_mode,
        full_history_repo_path=full_history_repo_path,
        default_branch_ref=default_branch_ref,
    )

    anthropic_tools = None
    anthropic_tool_runner = None
    if config.runner == "anthropic" and config.anthropic_tool_mode == "readonly":
        anthropic_tools = anthropic_readonly_repo_tools()
        anthropic_tool_runner = make_repo_tool_runner(case)

    # Pre-render evidence once for prompt caching across all API calls
    evidence_block = render_verifier_evidence(case) if config.runner == "anthropic" else ""

    prediction = _run_primary_result(
        case,
        config,
        anthropic_tools=anthropic_tools,
        anthropic_tool_runner=anthropic_tool_runner,
        evidence_block=evidence_block,
    )
    result = _build_primary_result_record(case, prediction)
    result["primary_prompt_version"] = prediction.get("primary_prompt_version", "")
    if "tool_trace" in prediction:
        result["tool_trace"] = prediction.get("tool_trace", [])

    findings = prediction.get("findings", [])
    verifier_results: list[dict[str, Any]] = []
    total_usage: dict[str, int] = {"input_tokens": 0, "output_tokens": 0}
    _add_usage(total_usage, result.get("usage"))
    all_variants = VERIFIER_VARIANTS[: max(0, config.verifier_count)]
    if config.runner in {"heuristic", "oracle"} and all_variants:
        all_variants = all_variants[:1]

    quick_panel_size = min(config.quick_panel_size, len(all_variants))
    quick_variants = all_variants[:quick_panel_size]
    escalation_variants = all_variants[quick_panel_size:]

    target_classification = str(result.get("classification") or "").strip().lower()
    commit_judgment_verification = _default_commit_judgment_verification_result(
        "disabled" if not all_variants else "skipped_primary_unknown",
        target_classification,
    )
    benign_challenge_result = _default_benign_challenge_result("off", "not_yet_run")
    escalation_reason: str | None = None

    if all_variants and target_classification in {"benign", "suspicious"}:
        judgment_votes: list[dict[str, Any]] = []

        if target_classification == "suspicious":
            # Suspicious: run ALL variants immediately
            run_variants = all_variants
            escalation_reason = "suspicious_primary"
        else:
            # Benign: run quick panel first
            run_variants = quick_variants

        for variant in run_variants:
            vote = _run_commit_judgment_vote(
                case, result, findings, variant, config,
                anthropic_tools=anthropic_tools,
                anthropic_tool_runner=anthropic_tool_runner,
                evidence_block=evidence_block,
            )
            judgment_votes.append(vote)
            _add_usage(total_usage, vote.get("usage"))

        # Benign challenge runs after quick panel, before escalation decision
        benign_challenge_result = _run_benign_challenge(
            case, result, config,
            anthropic_tools=anthropic_tools,
            anthropic_tool_runner=anthropic_tool_runner,
            evidence_block=evidence_block,
        )
        _add_usage(total_usage, benign_challenge_result.get("usage"))

        # Escalation: run remaining variants if quick panel had dissent or challenge escalated
        if target_classification == "benign" and escalation_variants:
            panel_escalate = _quick_panel_needs_escalation(judgment_votes)
            challenge_escalate = benign_challenge_result.get("decision") == "escalate"
            if panel_escalate or challenge_escalate:
                reasons = []
                if panel_escalate:
                    reasons.append("quick_panel_dissent")
                if challenge_escalate:
                    reasons.append("benign_challenge_escalate")
                escalation_reason = "+".join(reasons)
                for variant in escalation_variants:
                    vote = _run_commit_judgment_vote(
                        case, result, findings, variant, config,
                        anthropic_tools=anthropic_tools,
                        anthropic_tool_runner=anthropic_tool_runner,
                        evidence_block=evidence_block,
                    )
                    judgment_votes.append(vote)
                    _add_usage(total_usage, vote.get("usage"))

        commit_judgment_verification = {
            "scope": "primary_commit_classification",
            "status": "executed",
            "target_classification": target_classification,
            "votes": judgment_votes,
            "matrix": summarize_verifier_votes(judgment_votes),
            "tiered": True,
            "quick_panel_size": len(run_variants),
            "escalation_reason": escalation_reason,
        }
    else:
        # No variants or unknown classification — still run benign challenge
        benign_challenge_result = _run_benign_challenge(
            case, result, config,
            anthropic_tools=anthropic_tools,
            anthropic_tool_runner=anthropic_tool_runner,
            evidence_block=evidence_block,
        )
        _add_usage(total_usage, benign_challenge_result.get("usage"))

    for finding in findings:
        votes: list[dict[str, Any]] = []
        for variant in all_variants:
            vote = _run_verifier_vote(
                case,
                finding,
                variant,
                config,
                anthropic_tools=anthropic_tools,
                anthropic_tool_runner=anthropic_tool_runner,
                evidence_block=evidence_block,
            )
            votes.append(vote)
            _add_usage(total_usage, vote.get("usage"))
        verifier_results.append(
            {
                "finding": finding,
                "votes": votes,
                "matrix": summarize_verifier_votes(votes),
            }
        )

    policy = result_policy or ResultPolicy()

    payload: dict[str, Any] = {
        "schema_version": ANALYSIS_SCHEMA_VERSION,
        "harness_schema_version": _HARNESS_SCHEMA_VERSION,
        "prompt_format_version": _PROMPT_FORMAT_VERSION,
        "generated_at_utc": now_utc_iso(),
        "mode": "shadow_live",
        "config": {
            "runner": config.runner,
            "repo_path": str(repo_path),
            "repo": repo,
            "sha": sha,
            "ref": ref,
            "observed_at": observed_at,
            "gharchive_mode": gharchive_mode,
            "max_patch_chars": max_patch_chars,
            "max_files": max_files,
            "max_author_commits": max_author_commits,
            "max_path_commits": max_path_commits,
            "max_paths_for_history": max_paths_for_history,
            "max_ref_history_commits": max_ref_history_commits,
            "pr_social_mode": "attached" if pr_social_history else "off",
            "pr_social_history_attached": bool(pr_social_history),
            "ollama_model": config.ollama_model,
            "ollama_ssh_target": config.ollama_ssh_target,
            "ollama_timeout_sec": config.ollama_timeout_sec,
            "anthropic_model": config.anthropic_model,
            "anthropic_timeout_sec": config.anthropic_timeout_sec,
            "anthropic_thinking": config.anthropic_thinking,
            "anthropic_effort": config.anthropic_effort,
            "anthropic_tool_mode": config.anthropic_tool_mode,
            "anthropic_max_tool_rounds": config.anthropic_max_tool_rounds,
            "anthropic_max_total_tokens": config.anthropic_max_total_tokens,
            "openai_model": config.openai_model,
            "openai_timeout_sec": config.openai_timeout_sec,
            "openai_effort": config.openai_effort,
            "verifier_count": config.verifier_count,
            "quick_panel_size": config.quick_panel_size,
            "effective_verifier_count": len(all_variants),
            "effective_commit_judgment_verifier_count": len(commit_judgment_verification.get("votes", [])),
            "benign_challenge_mode": config.benign_challenge_mode,
        },
        "case": case,
        "primary_result": result,
        "commit_judgment_verification": commit_judgment_verification,
        "findings": findings,
        "verifier_results": verifier_results,
        "benign_challenge_result": benign_challenge_result,
        "total_usage": total_usage,
        "shadow_policy": policy.to_dict(),
    }

    return payload
