"""Rendering for domain-provenance results.

Two audiences, two levels of disclosure:

  `render_public_summary` -- anything that lands on a public surface (a PR comment,
  a check-run summary on a public repo). Bands and reasoning only; the domain and
  the email are redacted. Publishing "contributor X's domain enters pending-delete
  in six days" to a public thread is a targeting notice for anyone watching the
  repository, and it drags a personal email domain into a permanent public record.

  `render_maintainer_detail` -- the job summary or a private channel, where the
  reviewer needs the actual domain to act, and where the prospective expiry
  findings belong.

Nothing here decides anything; it only formats what `verdict.py` produced.
"""

from __future__ import annotations

from sift.provenance.verdict import (
    CLEAN,
    CRITICAL,
    LIKELY,
    NOTE,
    ROLE_COUNTER,
    ROLE_DECLINED,
    ROLE_UNAVAILABLE,
    UNKNOWN,
    DomainVerdict,
    IdentityAssessment,
)

_BAND_LABEL = {
    CRITICAL: "Identity discontinuity (critical)",
    LIKELY: "Identity discontinuity (likely)",
    NOTE: "Identity discontinuity (note)",
    UNKNOWN: "Not measurable",
    CLEAN: "No discontinuity",
}

_ROLE_NOTE = {
    ROLE_UNAVAILABLE: "The check ran and could not answer. This is not a clean result.",
    ROLE_DECLINED: "There was nothing to measure for this contributor.",
    ROLE_COUNTER: "This argues against an account-takeover reading.",
}


def redact_domain(domain: str) -> str:
    """`example-corp.net` -> `e***-****.net`; enough to correlate, not to target."""
    if not domain or "." not in domain:
        return "(redacted)"
    label, _, suffix = domain.partition(".")
    if len(label) <= 2:
        return f"{label[:1]}*.{suffix}"
    return f"{label[0]}{'*' * (len(label) - 2)}{label[-1]}.{suffix}"


def _redact_reason(reason: str, domain: str) -> str:
    return reason.replace(domain, redact_domain(domain)) if domain else reason


def render_public_summary(assessment: IdentityAssessment) -> str:
    """Markdown safe for a public PR thread."""
    lines = ["### Contributor identity provenance", ""]

    if not assessment.verdicts:
        if assessment.declined:
            lines.append(
                "Nothing measurable: the contributor's addresses have no registrable "
                "domain (noreply or a shared mailbox provider). This is not a finding "
                "either way."
            )
        else:
            lines.append("No domains were assessed.")
        return "\n".join(lines)

    worst = assessment.worst
    assert worst is not None
    lines.append(f"**{_BAND_LABEL.get(worst.band, worst.band)}** — {worst.confidence} confidence")
    note = _ROLE_NOTE.get(worst.role)
    if note:
        lines.append("")
        lines.append(note)

    lines.append("")
    for reason in worst.reasons:
        lines.append(f"- {_redact_reason(reason, worst.domain)}")

    if worst.gap_activity is not None:
        gap = worst.gap_activity
        lines.append(
            f"- Activity across the gap: **{gap.verdict}** "
            f"({gap.commits_in_gap} commit(s), scope `{gap.scope}`)"
        )

    if worst.prospective:
        lines.append("")
        lines.append(
            f"_{len(worst.prospective)} forward-looking registration note(s) withheld "
            f"from public output and sent to the maintainers instead._"
        )

    lines.append("")
    lines.append(
        "_Domain redacted. This is reviewer context, not a merge gate: a discontinuity "
        "means an identity's email domain changed hands, which is worth weighing against "
        "what this change touches._"
    )
    return "\n".join(lines)


def render_maintainer_detail(assessment: IdentityAssessment) -> str:
    """Full detail, including domains and the prospective expiry findings."""
    lines = [f"# Domain provenance: {assessment.login or '(unknown identity)'}", ""]

    if not assessment.verdicts:
        lines.append("No candidate domains.")
    for verdict in assessment.verdicts:
        lines.append(f"## {verdict.domain}")
        lines.append("")
        lines.append(f"- Band: **{verdict.band}** ({verdict.confidence} confidence)")
        lines.append(f"- Evidence role: `{verdict.role}`")
        if verdict.held_since:
            lines.append(f"- Registration began: {verdict.held_since.date().isoformat()}")
        if verdict.used_since:
            lines.append(
                f"- Identity first used it: "
                f"{verdict.used_since.first_seen.date().isoformat()} "
                f"({verdict.used_since.kind}, {verdict.used_since.strength}) — "
                f"{verdict.used_since.evidence}"
            )
        if verdict.gap_activity:
            gap = verdict.gap_activity
            lines.append(
                f"- Activity across gap: {gap.verdict}; {gap.commits_in_gap} commit(s), "
                f"same signing key: {gap.same_signing_key}, scope: {gap.scope}"
            )
        if verdict.corroboration:
            for item in verdict.corroboration:
                lines.append(f"- Corroboration ({item.kind}): {item.detail}")
        else:
            lines.append(
                "- Corroboration: none available (typical for abandoned "
                "single-maintainer domains)"
            )
        for reason in verdict.reasons:
            lines.append(f"- {reason}")
        if verdict.prospective:
            lines.append("")
            lines.append("**Forward-looking registration risk** (do not publish):")
            for note in verdict.prospective:
                lines.append(f"- {note}")
        lines.append("")

    if assessment.declined:
        lines.append("## Declined (nothing to measure)")
        lines.append("")
        for raw, reason in assessment.declined:
            lines.append(f"- `{raw}`: {reason}")
        lines.append("")

    if assessment.rejected:
        lines.append("## Rejected inputs (never queried)")
        lines.append("")
        for raw, reason in assessment.rejected:
            lines.append(f"- `{raw}`: {reason}")
        lines.append("")

    return "\n".join(lines)


def render_check_run(assessment: IdentityAssessment) -> dict:
    """GitHub check-run payload, matching the shape used by `render/github_check.py`.

    Conclusion is `neutral` for every band. This check reports context about an
    identity; it does not pass or fail a change, and a contributor whose domain
    lapsed years ago should not see a red X on their pull request.
    """
    worst = assessment.worst
    band = worst.band if worst else UNKNOWN
    title = _BAND_LABEL.get(band, band)
    return {
        "name": "sift: contributor identity provenance",
        "status": "completed",
        "conclusion": "neutral",
        "output": {
            "title": title,
            "summary": render_public_summary(assessment),
        },
    }


def summarize_one_line(verdict: DomainVerdict) -> str:
    return (
        f"{redact_domain(verdict.domain)}: {verdict.band} "
        f"({verdict.confidence}, role={verdict.role})"
    )
