#!/usr/bin/env python3
"""`sift-domain` -- check whether a contributor's email domain changed hands.

Third-party imports are deliberately deferred into `main()`. Entries in
`[project.scripts]` are installed unconditionally, so a base-install user can run
`sift-domain` without the `sift[provenance]` extra; without the guard they would
get a raw ModuleNotFoundError instead of an instruction.

Usage:

    sift-domain --login <github-login>
    sift-domain --email someone@example.net [--email other@example.org]
    sift-domain --event-path "$GITHUB_EVENT_PATH" --repo-path .
    sift-domain --login <login> --json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_INSTALL_HINT = (
    "sift-domain needs the provenance extra.\n"
    "  uv pip install -e '.[provenance]'\n"
    "  (or: pip install 'sift[provenance]')"
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sift-domain",
        description=(
            "Detect whether a contributor's email domain changed hands since that "
            "identity began using it -- the maintainer-domain takeover vector behind "
            "npm node-ipc (2026) and PyPI ctx (2022)."
        ),
    )
    parser.add_argument("--login", default="", help="GitHub login (fetches GPG key UIDs)")
    parser.add_argument(
        "--email",
        action="append",
        default=[],
        dest="emails",
        help="email address to assess; repeatable",
    )
    parser.add_argument(
        "--event-path",
        default="",
        help="GitHub Actions event.json; reads the PR author login",
    )
    parser.add_argument(
        "--repo-path",
        default="",
        help="git repository for repo-local gap-activity analysis",
    )
    parser.add_argument(
        "--now",
        default="",
        help="ISO-8601 clock override, for replaying historical incidents",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of markdown")
    parser.add_argument(
        "--public",
        action="store_true",
        help="emit the redacted public summary rather than maintainer detail",
    )
    parser.add_argument(
        "--no-corroboration",
        action="store_true",
        help="skip Certificate Transparency and Wayback lookups",
    )
    return parser


def _login_from_event(path: Path) -> tuple[str, list[str]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "", []
    pull_request = payload.get("pull_request") or {}
    user = pull_request.get("user") or payload.get("sender") or {}
    login = str(user.get("login") or "").strip()
    return login, []


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        from sift.provenance import assess_identity
        from sift.provenance.render import render_maintainer_detail, render_public_summary
    except ImportError as exc:
        print(f"{_INSTALL_HINT}\n\n  underlying error: {exc}", file=sys.stderr)
        return 2

    from datetime import datetime, timezone

    login = args.login.strip()
    emails = list(args.emails)
    if args.event_path:
        event_login, event_emails = _login_from_event(Path(args.event_path))
        login = login or event_login
        emails.extend(event_emails)

    if not login and not emails:
        print(
            "nothing to assess: pass --login, --email, or --event-path", file=sys.stderr
        )
        return 2

    if args.now:
        try:
            now = datetime.fromisoformat(args.now)
        except ValueError:
            print(f"--now is not ISO-8601: {args.now!r}", file=sys.stderr)
            return 2
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
    else:
        now = datetime.now(timezone.utc)

    assessment = assess_identity(
        login,
        now=now,
        emails=emails,
        repo_path=Path(args.repo_path) if args.repo_path else None,
        with_corroboration=not args.no_corroboration,
    )

    if args.json:
        print(json.dumps(_to_dict(assessment), indent=2, sort_keys=True))
    elif args.public:
        print(render_public_summary(assessment))
    else:
        print(render_maintainer_detail(assessment))

    # Exit status reports what was found without implying a gate: 0 for nothing
    # actionable, 1 for an anomaly worth a human look. Never non-zero merely
    # because a lookup failed.
    worst = assessment.worst
    return 1 if worst is not None and worst.is_anomaly else 0


def _to_dict(assessment) -> dict:
    def verdict_dict(verdict) -> dict:
        gap = verdict.gap_activity
        return {
            "domain": verdict.domain,
            "band": verdict.band,
            "confidence": verdict.confidence,
            "role": verdict.role,
            "held_since": verdict.held_since.isoformat() if verdict.held_since else None,
            "used_since": (
                {
                    "first_seen": verdict.used_since.first_seen.isoformat(),
                    "kind": verdict.used_since.kind,
                    "strength": verdict.used_since.strength,
                    "evidence": verdict.used_since.evidence,
                }
                if verdict.used_since
                else None
            ),
            "gap_activity": (
                {
                    "verdict": gap.verdict,
                    "commits_in_gap": gap.commits_in_gap,
                    "same_signing_key": gap.same_signing_key,
                    "scope": gap.scope,
                    "gap_start": gap.gap_start.isoformat(),
                    "gap_end": gap.gap_end.isoformat(),
                }
                if gap
                else None
            ),
            "corroboration": [
                {
                    "kind": item.kind,
                    "start": item.start.isoformat() if item.start else None,
                    "end": item.end.isoformat() if item.end else None,
                    "detail": item.detail,
                }
                for item in verdict.corroboration
            ],
            "reasons": list(verdict.reasons),
            "prospective": list(verdict.prospective),
        }

    return {
        "login": assessment.login,
        "verdicts": [verdict_dict(v) for v in assessment.verdicts],
        "declined": [{"input": raw, "reason": reason} for raw, reason in assessment.declined],
        "rejected": [{"input": raw, "reason": reason} for raw, reason in assessment.rejected],
    }


if __name__ == "__main__":
    raise SystemExit(main())
