#!/usr/bin/env python3
"""
CLI entrypoint: analyze a single commit.

Thin wrapper over sift.runtime.analysis.analyze_commit().
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from sift.profiles import get_profile, list_profiles
from sift.runtime.analysis import RunnerConfig, ResultPolicy, analyze_commit
from sift.runtime.providers import (
    ANTHROPIC_DEFAULT_EFFORT,
    ANTHROPIC_DEFAULT_MODEL,
    ANTHROPIC_DEFAULT_THINKING,
    now_utc_iso,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sift-commit",
        description="Analyze a single commit for security-relevant findings",
    )
    parser.add_argument(
        "--profile",
        default="",
        help=f"Named profile (overrides runner/model/effort flags). Available: {', '.join(list_profiles())}",
    )
    parser.add_argument("--repo-path", required=True, help="Path to a local checkout or bare mirror")
    parser.add_argument("--sha", required=True, help="Commit SHA to analyze")
    parser.add_argument("--ref", required=True, help="Observed ref, e.g. refs/heads/main")
    parser.add_argument("--observed-at", default="", help="First-observation timestamp (ISO-8601 UTC)")
    parser.add_argument("--repo", default="", help="Optional repo identifier like owner/name")
    parser.add_argument("--runner", choices=("ollama", "anthropic"), default="anthropic")
    parser.add_argument("--gharchive-mode", choices=("full", "omit"), default="full")
    parser.add_argument("--max-patch-chars", type=int, default=12000)
    parser.add_argument("--max-files", type=int, default=200)
    parser.add_argument("--max-author-commits", type=int, default=20)
    parser.add_argument("--max-path-commits", type=int, default=5)
    parser.add_argument("--max-paths-for-history", type=int, default=10)
    parser.add_argument("--max-ref-history-commits", type=int, default=20)
    parser.add_argument("--pr-social-json", default="", help="Optional path to prebuilt PR/social JSON")
    parser.add_argument("--ollama-model", default="gpt-oss:120b")
    parser.add_argument("--ollama-ssh-target", default="")
    parser.add_argument("--ollama-timeout-sec", type=int, default=900)
    parser.add_argument("--anthropic-model", default=ANTHROPIC_DEFAULT_MODEL)
    parser.add_argument("--anthropic-timeout-sec", type=int, default=300)
    parser.add_argument("--anthropic-thinking", choices=("adaptive", "off"), default=ANTHROPIC_DEFAULT_THINKING)
    parser.add_argument("--anthropic-effort", choices=("low", "medium", "high", "max"), default=ANTHROPIC_DEFAULT_EFFORT)
    parser.add_argument("--anthropic-tool-mode", choices=("none", "readonly"), default="readonly")
    parser.add_argument("--anthropic-max-tool-rounds", type=int, default=0)
    parser.add_argument("--anthropic-max-total-tokens", type=int, default=500000)
    parser.add_argument("--verifier-count", type=int, default=3)
    parser.add_argument(
        "--benign-challenge-mode",
        choices=("off", "if_primary_benign"),
        default="off",
    )
    parser.add_argument("--full-history-repo-path", default="")
    parser.add_argument("--output", default="", help="Path to write the JSON payload")
    return parser


def main() -> None:
    args = build_parser().parse_args()

    pr_social_history: dict[str, Any] | None = None
    if args.pr_social_json:
        pr_social_history = json.loads(Path(args.pr_social_json).read_text(encoding="utf-8"))

    full_history_repo_path = Path(args.full_history_repo_path) if args.full_history_repo_path else None

    if args.profile:
        profile = get_profile(args.profile)
        runner_config = profile.runner_config
        result_policy = profile.result_policy
        max_patch_chars = profile.max_patch_chars
        max_files = profile.max_files
        max_author_commits = profile.max_author_commits
        max_path_commits = profile.max_path_commits
        max_paths_for_history = profile.max_paths_for_history
        max_ref_history_commits = profile.max_ref_history_commits
    else:
        runner_config = RunnerConfig(
            runner=args.runner,
            ollama_model=args.ollama_model,
            ollama_ssh_target=args.ollama_ssh_target,
            ollama_timeout_sec=args.ollama_timeout_sec,
            anthropic_model=args.anthropic_model,
            anthropic_timeout_sec=args.anthropic_timeout_sec,
            anthropic_thinking=args.anthropic_thinking,
            anthropic_effort=args.anthropic_effort,
            anthropic_tool_mode=args.anthropic_tool_mode,
            anthropic_max_tool_rounds=args.anthropic_max_tool_rounds,
            anthropic_max_total_tokens=args.anthropic_max_total_tokens,
            verifier_count=args.verifier_count,
            benign_challenge_mode=args.benign_challenge_mode,
        )
        result_policy = None
        max_patch_chars = args.max_patch_chars
        max_files = args.max_files
        max_author_commits = args.max_author_commits
        max_path_commits = args.max_path_commits
        max_paths_for_history = args.max_paths_for_history
        max_ref_history_commits = args.max_ref_history_commits

    payload = analyze_commit(
        Path(args.repo_path),
        args.sha,
        args.ref,
        runner_config=runner_config,
        result_policy=result_policy if args.profile else None,
        observed_at=args.observed_at or now_utc_iso(),
        repo=args.repo,
        max_patch_chars=max_patch_chars,
        max_files=max_files,
        max_author_commits=max_author_commits,
        max_path_commits=max_path_commits,
        max_paths_for_history=args.max_paths_for_history,
        max_ref_history_commits=args.max_ref_history_commits,
        gharchive_mode=args.gharchive_mode,
        pr_social_history=pr_social_history,
        full_history_repo_path=full_history_repo_path,
    )

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    result = payload["primary_result"]
    print(f"classification={result['classification']}")
    print(f"confidence={result['confidence']}")
    print(f"findings={len(payload['findings'])}")
    if payload["total_usage"]["input_tokens"]:
        print(f"total_input_tokens={payload['total_usage']['input_tokens']}")
        print(f"total_output_tokens={payload['total_usage']['output_tokens']}")


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.exit(0)
