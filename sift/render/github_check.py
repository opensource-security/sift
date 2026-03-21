#!/usr/bin/env python3
"""
Render a GitHub check-run payload from a PR analysis artifact.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .github_summary import render_markdown


CHECK_RUN_NAME = "Sift PR Review"


def pluralize(count: int, singular: str, plural: str | None = None) -> str:
    if count == 1:
        return singular
    return plural or f"{singular}s"


def build_conclusion(payload: dict[str, Any]) -> str:
    surviving = int(((payload.get("summary") or {}).get("surviving_findings_total")) or 0)
    if surviving > 0:
        return "neutral"
    return "success"


def build_title(payload: dict[str, Any]) -> str:
    summary = payload.get("summary") or {}
    commits = int(summary.get("commits_total") or 0)
    surviving = int(summary.get("surviving_findings_total") or 0)
    if surviving > 0:
        return (
            f"{surviving} surviving {pluralize(surviving, 'finding')} across "
            f"{commits} {pluralize(commits, 'commit')}"
        )
    return f"No surviving findings across {commits} {pluralize(commits, 'commit')}"


def build_summary(payload: dict[str, Any], *, max_findings: int) -> str:
    pr = payload.get("pr") or {}
    summary = payload.get("summary") or {}
    usage = payload.get("total_usage") or {}
    surviving = payload.get("surviving_findings") or []
    pr_social = payload.get("pr_social_history") or {}
    pr_social_fetch = pr_social.get("fetch_summary") or {}

    lines = [
        f"PR #{pr.get('pr_number')} on `{pr.get('repo') or '(unknown)'}`",
        f"Commits analyzed: {summary.get('commits_total', 0)}",
        f"Findings emitted: {summary.get('findings_total', 0)}",
        f"Verified findings: {summary.get('verified_findings_total', 0)}",
        f"Surviving findings: {summary.get('surviving_findings_total', 0)}",
    ]
    if usage.get("input_tokens") or usage.get("output_tokens"):
        lines.append(
            f"Token usage: input={usage.get('input_tokens', 0)}, output={usage.get('output_tokens', 0)}"
        )
    if pr_social:
        lines.append(
            "PR/social enrichment: "
            f"available={pr_social.get('available')}, "
            f"partial={pr_social.get('partial_data')}, "
            f"requests={pr_social_fetch.get('requests_made', 0)}"
        )
    if surviving:
        top = []
        for item in surviving[:max_findings]:
            finding = item.get("finding") or {}
            matrix = item.get("matrix") or {}
            commit_short = item.get("short_sha") or (item.get("commit_sha") or "")[:7]
            top.append(
                f"`{commit_short}` `{finding.get('finding_type', 'other')}` "
                f"`{matrix.get('status', 'unknown')}`: {finding.get('claim', '').strip()}"
            )
        lines.append("")
        lines.append("Top surviving findings:")
        lines.extend(f"- {line}" for line in top)
    else:
        lines.append("")
        lines.append("No surviving findings in shadow mode.")
    return "\n".join(lines).strip()


def build_check_run_payload(
    payload: dict[str, Any],
    *,
    details_url: str,
    max_findings: int,
) -> dict[str, Any]:
    pr = payload.get("pr") or {}
    head_sha = (pr.get("head_sha") or "").strip()
    if not head_sha:
        raise ValueError("shadow PR payload is missing pr.head_sha")
    markdown = render_markdown(payload, max_findings=max_findings)
    return {
        "name": CHECK_RUN_NAME,
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": build_conclusion(payload),
        "details_url": details_url,
        "output": {
            "title": build_title(payload),
            "summary": build_summary(payload, max_findings=max_findings),
            "text": markdown,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Render a GitHub check-run payload from shadow PR JSON")
    parser.add_argument("--input", required=True, help="Path to shadow_pr_run JSON")
    parser.add_argument("--details-url", required=True, help="Workflow or run URL for drill-down")
    parser.add_argument("--output", default="", help="Optional JSON output path")
    parser.add_argument("--max-findings", type=int, default=5)
    args = parser.parse_args()

    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    rendered = build_check_run_payload(
        payload,
        details_url=args.details_url,
        max_findings=args.max_findings,
    )
    content = json.dumps(rendered, indent=2, ensure_ascii=False) + "\n"

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
    else:
        print(content, end="")


if __name__ == "__main__":
    main()
