#!/usr/bin/env python3
"""
CLI entrypoint: analyze all commits in a PR.

Thin wrapper that calls analyze_commit() per commit and aggregates results.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from sift.runtime.analysis import RunnerConfig, ResultPolicy, analyze_commit
from sift.runtime.benign_challenger import should_sample_benign_challenge
from sift.runtime.pr_social import build_current_pr_social_history
from sift.runtime.providers import (
    ANTHROPIC_DEFAULT_EFFORT,
    ANTHROPIC_DEFAULT_MODEL,
    ANTHROPIC_DEFAULT_THINKING,
    now_utc_iso,
)


def run_git(repo_path: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo_path), *args],
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"git {' '.join(args)} failed")
    return proc.stdout.strip()


def normalize_ref(ref: str) -> str:
    text = (ref or "").strip()
    if not text:
        return ""
    if text.startswith("refs/"):
        return text
    return f"refs/heads/{text}"


def parse_event_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    pr = payload.get("pull_request") or {}
    repo_name = (payload.get("repository") or {}).get("full_name") or ""
    base = pr.get("base") or {}
    head = pr.get("head") or {}
    return {
        "repo": repo_name,
        "pr_number": pr.get("number") or payload.get("number"),
        "base_sha": (base.get("sha") or "").strip(),
        "head_sha": (head.get("sha") or "").strip(),
        "base_ref": normalize_ref(base.get("ref") or ""),
        "head_ref": normalize_ref(head.get("ref") or ""),
        "observed_at": (pr.get("updated_at") or payload.get("updated_at") or now_utc_iso()).strip(),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sift-pr",
        description="Analyze commits introduced by a pull request",
    )
    parser.add_argument("--repo-path", required=True)
    parser.add_argument("--event-json", default="", help="GitHub pull_request event payload")
    parser.add_argument("--repo", default="")
    parser.add_argument("--pr-number", type=int, default=0)
    parser.add_argument("--base-sha", default="")
    parser.add_argument("--head-sha", default="")
    parser.add_argument("--base-ref", default="")
    parser.add_argument("--head-ref", default="")
    parser.add_argument("--observed-at", default="")
    parser.add_argument("--limit-commits", type=int, default=0)
    parser.add_argument("--runner", choices=("ollama", "anthropic"), default="anthropic")
    parser.add_argument("--gharchive-mode", choices=("full", "omit"), default="full")
    parser.add_argument("--max-patch-chars", type=int, default=12000)
    parser.add_argument("--max-files", type=int, default=200)
    parser.add_argument("--max-author-commits", type=int, default=20)
    parser.add_argument("--max-path-commits", type=int, default=5)
    parser.add_argument("--max-paths-for-history", type=int, default=10)
    parser.add_argument("--max-ref-history-commits", type=int, default=20)
    parser.add_argument(
        "--pr-social-mode",
        choices=("off", "current_pr"),
        default="off",
    )
    parser.add_argument("--pr-social-timeout-sec", type=int, default=30)
    parser.add_argument("--pr-social-max-review-pages", type=int, default=5)
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
    parser.add_argument("--benign-challenge-mode", choices=("off", "sample", "all"), default="off")
    parser.add_argument("--benign-challenge-sample-rate", type=float, default=0.1)
    parser.add_argument("--output", default="", help="Path to write the aggregated PR JSON payload")
    return parser


def resolve_pr_metadata(args: argparse.Namespace) -> dict[str, Any]:
    metadata = {
        "repo": args.repo.strip(),
        "pr_number": args.pr_number or None,
        "base_sha": args.base_sha.strip(),
        "head_sha": args.head_sha.strip(),
        "base_ref": normalize_ref(args.base_ref),
        "head_ref": normalize_ref(args.head_ref),
        "observed_at": (args.observed_at or now_utc_iso()).strip(),
    }
    if args.event_json:
        event_meta = parse_event_json(Path(args.event_json))
        for key, value in event_meta.items():
            if not metadata.get(key):
                metadata[key] = value
    if not metadata["base_sha"] or not metadata["head_sha"]:
        raise SystemExit("PR analysis requires base/head SHAs, either explicitly or via --event-json")
    if not metadata["head_ref"]:
        metadata["head_ref"] = "refs/heads/unknown-pr-head"
    if not metadata["observed_at"]:
        metadata["observed_at"] = now_utc_iso()
    return metadata


def aggregate_pr_payload(
    *,
    metadata: dict[str, Any],
    merge_base: str,
    commit_payloads: list[dict[str, Any]],
    pr_social_history: dict[str, Any] | None,
) -> dict[str, Any]:
    classification_counts: dict[str, int] = {}
    matrix_status_counts: dict[str, int] = {}
    total_usage = {"input_tokens": 0, "output_tokens": 0}
    findings_total = 0
    verified_findings: list[dict[str, Any]] = []
    surviving_findings: list[dict[str, Any]] = []

    for payload in commit_payloads:
        classification = payload.get("primary_result", {}).get("classification", "unknown")
        classification_counts[classification] = classification_counts.get(classification, 0) + 1
        usage = payload.get("total_usage") or {}
        total_usage["input_tokens"] += usage.get("input_tokens") or 0
        total_usage["output_tokens"] += usage.get("output_tokens") or 0
        findings_total += len(payload.get("findings", []))
        for verifier_result in payload.get("verifier_results", []):
            matrix = verifier_result.get("matrix", {})
            status = matrix.get("status", "unknown")
            matrix_status_counts[status] = matrix_status_counts.get(status, 0) + 1
            finding_record = {
                "commit_sha": payload.get("case", {}).get("commit_sha", ""),
                "short_sha": payload.get("case", {}).get("short_sha", ""),
                "finding": verifier_result.get("finding", {}),
                "matrix": matrix,
            }
            if status == "valid":
                verified_findings.append(finding_record)
            if status in {"valid", "weak", "contested"}:
                surviving_findings.append(finding_record)

    return {
        "schema_version": "sift_pr_v1",
        "generated_at_utc": now_utc_iso(),
        "mode": "pr_analysis",
        "pr": {**metadata, "merge_base": merge_base},
        "summary": {
            "commits_total": len(commit_payloads),
            "classification_counts": classification_counts,
            "findings_total": findings_total,
            "matrix_status_counts": matrix_status_counts,
            "verified_findings_total": len(verified_findings),
            "surviving_findings_total": len(surviving_findings),
        },
        "verified_findings": verified_findings,
        "surviving_findings": surviving_findings,
        "total_usage": total_usage,
        "commit_runs": commit_payloads,
        "pr_social_history": pr_social_history or {},
        "result_policy": {
            "maintainer_visible": False,
            "blocking": False,
            "requested_action": "log_only",
        },
    }


def main() -> None:
    args = build_parser().parse_args()
    metadata = resolve_pr_metadata(args)
    repo_path = Path(args.repo_path)

    merge_base = run_git(repo_path, "merge-base", metadata["base_sha"], metadata["head_sha"])
    revs = run_git(repo_path, "rev-list", "--reverse", f"{merge_base}..{metadata['head_sha']}")
    commits = [line.strip() for line in revs.splitlines() if line.strip()]
    if args.limit_commits > 0:
        commits = commits[: args.limit_commits]
    if not commits:
        raise SystemExit("no commits found in PR range")

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
    )

    pr_social_history: dict[str, Any] | None = None
    if args.pr_social_mode == "current_pr":
        pr_social_history = build_current_pr_social_history(
            repo=metadata.get("repo") or "",
            pr_number=metadata.get("pr_number"),
            base_ref=metadata.get("base_ref") or "",
            head_ref=metadata.get("head_ref") or "",
            token=os.environ.get("GITHUB_TOKEN", ""),
            timeout_sec=args.pr_social_timeout_sec,
            max_review_pages=args.pr_social_max_review_pages,
        )

    commit_payloads: list[dict[str, Any]] = []
    for index, sha in enumerate(commits, start=1):
        benign_challenge_mode = "off"
        if args.benign_challenge_mode == "all":
            benign_challenge_mode = "if_primary_benign"
        elif args.benign_challenge_mode == "sample" and should_sample_benign_challenge(
            metadata.get("repo") or "", sha, args.benign_challenge_sample_rate,
        ):
            benign_challenge_mode = "if_primary_benign"

        commit_config = RunnerConfig(
            runner=runner_config.runner,
            ollama_model=runner_config.ollama_model,
            ollama_ssh_target=runner_config.ollama_ssh_target,
            ollama_timeout_sec=runner_config.ollama_timeout_sec,
            anthropic_model=runner_config.anthropic_model,
            anthropic_timeout_sec=runner_config.anthropic_timeout_sec,
            anthropic_thinking=runner_config.anthropic_thinking,
            anthropic_effort=runner_config.anthropic_effort,
            anthropic_tool_mode=runner_config.anthropic_tool_mode,
            anthropic_max_tool_rounds=runner_config.anthropic_max_tool_rounds,
            anthropic_max_total_tokens=runner_config.anthropic_max_total_tokens,
            verifier_count=runner_config.verifier_count,
            benign_challenge_mode=benign_challenge_mode,
        )

        payload = analyze_commit(
            repo_path,
            sha,
            metadata["head_ref"],
            runner_config=commit_config,
            observed_at=metadata["observed_at"],
            repo=metadata.get("repo") or "",
            max_patch_chars=args.max_patch_chars,
            max_files=args.max_files,
            max_author_commits=args.max_author_commits,
            max_path_commits=args.max_path_commits,
            max_paths_for_history=args.max_paths_for_history,
            max_ref_history_commits=args.max_ref_history_commits,
            gharchive_mode=args.gharchive_mode,
            pr_social_history=pr_social_history,
        )
        commit_payloads.append(payload)
        classification = payload.get("primary_result", {}).get("classification", "unknown")
        findings_count = len(payload.get("findings", []))
        print(
            f"[{index}/{len(commits)}] {sha[:7]} classification={classification} findings={findings_count}",
            file=sys.stderr,
            flush=True,
        )

    aggregated = aggregate_pr_payload(
        metadata=metadata,
        merge_base=merge_base,
        commit_payloads=commit_payloads,
        pr_social_history=pr_social_history,
    )

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(aggregated, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    summary = aggregated["summary"]
    print(f"commits={summary['commits_total']}")
    print(f"classifications={json.dumps(summary['classification_counts'], sort_keys=True)}")
    print(f"verified_findings={summary['verified_findings_total']}")
    print(f"surviving_findings={summary['surviving_findings_total']}")
    if aggregated["total_usage"]["input_tokens"]:
        print(f"total_input_tokens={aggregated['total_usage']['input_tokens']}")
        print(f"total_output_tokens={aggregated['total_usage']['output_tokens']}")


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.exit(0)
