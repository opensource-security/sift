#!/usr/bin/env python3
"""
Render a concise markdown summary for a PR analysis payload.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def render_counts(title: str, counts: dict[str, Any]) -> list[str]:
    if not counts:
        return [f"- {title}: (none)"]
    rendered = ", ".join(f"{key}={counts[key]}" for key in sorted(counts))
    return [f"- {title}: {rendered}"]


def summarize_findings(items: list[dict[str, Any]], *, limit: int, heading: str) -> list[str]:
    lines = [f"## {heading}"]
    if not items:
        lines.append("None.")
        return lines
    for item in items[:limit]:
        finding = item.get("finding", {})
        matrix = item.get("matrix", {})
        commit_short = item.get("short_sha") or (item.get("commit_sha") or "")[:7]
        finding_type = finding.get("finding_type", "other")
        severity = finding.get("severity", "unknown")
        claim = (finding.get("claim", "") or "").strip().replace("\n", " ")
        status = matrix.get("status", "unknown")
        ratio = matrix.get("verification_ratio", "n/a")
        lines.append(
            f"- `{commit_short}` `{finding_type}` `{severity}` `{status}` ratio={ratio}: {claim}"
        )
    remaining = len(items) - limit
    if remaining > 0:
        lines.append(f"- ... and {remaining} more")
    return lines


def render_markdown(payload: dict[str, Any], *, max_findings: int) -> str:
    pr = payload.get("pr", {})
    summary = payload.get("summary", {})
    usage = payload.get("total_usage", {}) or {}
    pr_social = payload.get("pr_social_history") or {}
    pr_social_fetch = pr_social.get("fetch_summary") or {}

    lines: list[str] = []
    lines.append("# Shadow PR Summary")
    lines.append("")
    lines.append(f"- Repo: `{pr.get('repo') or '(unknown)'}`")
    lines.append(f"- PR: `{pr.get('pr_number')}`")
    lines.append(f"- Base SHA: `{(pr.get('base_sha') or '')[:12]}`")
    lines.append(f"- Head SHA: `{(pr.get('head_sha') or '')[:12]}`")
    lines.append(f"- Merge base: `{(pr.get('merge_base') or '')[:12]}`")
    lines.append(f"- Observed at: `{pr.get('observed_at') or '(unknown)'}`")
    lines.append("")
    lines.append("## Totals")
    lines.append(f"- Commits analyzed: `{summary.get('commits_total', 0)}`")
    lines.append(f"- Findings emitted: `{summary.get('findings_total', 0)}`")
    lines.append(f"- Verified findings: `{summary.get('verified_findings_total', 0)}`")
    lines.append(f"- Surviving findings: `{summary.get('surviving_findings_total', 0)}`")
    if usage.get("input_tokens") or usage.get("output_tokens"):
        lines.append(f"- Token usage: input=`{usage.get('input_tokens', 0)}`, output=`{usage.get('output_tokens', 0)}`")
    if pr_social:
        lines.append(
            f"- PR/social enrichment: available=`{pr_social.get('available')}`, "
            f"partial=`{pr_social.get('partial_data')}`, "
            f"requests=`{pr_social_fetch.get('requests_made', 0)}`"
        )
    lines.append("")
    lines.append("## Distributions")
    lines.extend(render_counts("Classifications", summary.get("classification_counts", {}) or {}))
    lines.extend(render_counts("Matrix statuses", summary.get("matrix_status_counts", {}) or {}))
    lines.append("")
    lines.extend(summarize_findings(payload.get("verified_findings", []) or [], limit=max_findings, heading="Verified Findings"))
    lines.append("")
    lines.extend(summarize_findings(payload.get("surviving_findings", []) or [], limit=max_findings, heading="Surviving Findings"))
    lines.append("")
    lines.append("_Shadow mode only: this run is non-blocking and not a merge gate._")
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Render markdown summary from a shadow PR run JSON payload")
    parser.add_argument("--input", required=True, help="Path to shadow_pr_run JSON")
    parser.add_argument("--output", default="", help="Optional markdown output path")
    parser.add_argument("--max-findings", type=int, default=10)
    args = parser.parse_args()

    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    markdown = render_markdown(payload, max_findings=args.max_findings)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(markdown, encoding="utf-8")
    else:
        print(markdown, end="")


if __name__ == "__main__":
    main()
