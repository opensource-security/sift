from __future__ import annotations

import json
import re
from typing import Any

from .case_builder import render_domain_provenance_lines
from .pr_social import render_pr_social_history_lines
from .types import CommitCase, Finding, VerificationMatrix, VerifierVote


WEEKDAY_NAMES = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
WEEKDAY_LABEL_MAP = {index: name for index, name in enumerate(WEEKDAY_NAMES)}


VERIFIER_VARIANTS: list[dict[str, str]] = [
    {
        "verifier_id": "verify_balanced_v8",
        "label": "balanced",
        "instructions": (
            "Assess the finding directly. Verify only when the claim is supported by the commit-local evidence. "
            "Disprove when the evidence materially undercuts the claim. Abstain when the evidence is insufficient."
        ),
    },
    {
        "verifier_id": "verify_skeptical_v8",
        "label": "skeptical",
        "instructions": (
            "Start from a skeptical stance. Look for ordinary maintenance explanations, incomplete evidence, "
            "or reasons the claim overstates the risk. Abstain rather than over-verifying weak claims."
        ),
    },
    {
        "verifier_id": "verify_counterexample_v8",
        "label": "counterexample",
        "instructions": (
            "Try to falsify the claim first. Search for contradictions, benign explanations, or missing links "
            "between the evidence and the alleged risk. Only verify if the claim still survives that pressure."
        ),
    },
    {
        "verifier_id": "verify_bounded_context_v8",
        "label": "bounded-context",
        "instructions": (
            "Focus on scope limits and baseline caveats. Reject claims or judgments that lean too heavily on thin "
            "history, timing anomalies, timezone changes, or message/diff mismatch without corroborating patch evidence."
        ),
    },
    {
        "verifier_id": "verify_security_boundary_v2",
        "label": "security-boundary",
        "instructions": (
            "Focus specifically on whether this commit touches a security boundary: resource limits, decompression "
            "guards, path sanitization, input size caps, authentication logic, or access control. If such code is "
            "modified—added, removed, or weakened—consider disprove on a benign judgment or verify on a suspicious "
            "one, regardless of author trust level. A CVE, GHSA, or security advisory reference in the commit "
            "message or changed files is a signal to look harder at the patch content, not evidence the commit is safe."
        ),
    },
]


def _format_history_count(count: Any, lower_bound: bool, *, bounded_window: bool) -> str:
    if count in {None, ""}:
        return "(unknown)"
    prefix = ">=" if lower_bound else ""
    suffix = " seen in bounded window" if bounded_window else ""
    return f"{prefix}{count}{suffix}"


def _same_identity(commit: CommitCase) -> bool | None:
    author_email = str((commit.get("author_email") or "")).strip().lower()
    committer_email = str((commit.get("committer_email") or "")).strip().lower()
    if author_email and committer_email:
        return author_email == committer_email
    author_name = str((commit.get("author_name") or "")).strip().lower()
    committer_name = str((commit.get("committer_name") or "")).strip().lower()
    if author_name and committer_name:
        return author_name == committer_name
    return None


def _format_weekday_label(value: int | None) -> str:
    if value is None or value < 0 or value >= len(WEEKDAY_NAMES):
        return "(unknown)"
    return f"{WEEKDAY_NAMES[value]}({value})"


def _format_top_histogram_buckets(histogram: dict[str, int], *, label_map: dict[int, str] | None = None, limit: int = 4) -> str:
    entries = [
        (int(bucket), int(count))
        for bucket, count in histogram.items()
        if int(count or 0) > 0
    ]
    if not entries:
        return "(none)"
    rendered: list[str] = []
    for bucket, count in sorted(entries, key=lambda item: (-item[1], item[0]))[:limit]:
        label = label_map.get(bucket, str(bucket)) if label_map else str(bucket)
        rendered.append(f"{label}={count}")
    return ", ".join(rendered)


def _format_timezone_offset_minutes(value: int | None) -> str:
    if value is None:
        return "(unknown)"
    sign = "+" if value >= 0 else "-"
    absolute = abs(value)
    hours, minutes = divmod(absolute, 60)
    return f"{sign}{hours:02d}:{minutes:02d} ({value}m)"


def _format_timezone_offset_counts(items: list[dict[str, Any]], *, limit: int = 4) -> str:
    if not items:
        return "(none)"
    rendered: list[str] = []
    for item in items[:limit]:
        rendered.append(
            f"{_format_timezone_offset_minutes(item.get('offset_minutes'))}={item.get('count')}"
        )
    return ", ".join(rendered)


def _format_bool_unknown(value: Any) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "(unknown)"


def _format_identity_variants(items: list[dict[str, Any]], value_key: str, *, limit: int = 4) -> str:
    if not items:
        return "(none)"
    rendered: list[str] = []
    for item in items[:limit]:
        rendered.append(f"{item.get(value_key)}={item.get('commit_count')}")
    return ", ".join(rendered)


def render_verifier_evidence(case: CommitCase) -> str:
    commit = case.get("commit", {})
    history = case.get("history_before_commit", {})
    timing = case.get("gharchive_context", {}).get("repo_push_timing", {}) or {}
    target_push = case.get("gharchive_context", {}).get("target_push_event", {}) or {}
    same_identity = _same_identity(commit)
    history_scope = history.get("history_scope", {}) or {}
    bounded_window = str(history_scope.get("mode") or "").startswith("bounded_")

    lines: list[str] = []
    lines.append("## Commit Evidence")
    lines.append(f"- Repo: {case.get('repo', '')}")
    lines.append(f"- Commit SHA: {case.get('commit_sha', '')}")
    lines.append(f"- Ref: {target_push.get('ref') or case.get('realtime_observation', {}).get('ref') or '(unknown)'}")
    lines.append(f"- Evidence state: {case.get('evidence_state', '')}")
    lines.append(f"- Author (patch author): {commit.get('author_name', '')} <{commit.get('author_email', '')}>")
    lines.append(f"- Committer (may be maintainer/reviewer/merger): {commit.get('committer_name', '')} <{commit.get('committer_email', '')}>")
    lines.append(
        "- Author and committer same identity: "
        + ("yes" if same_identity is True else "no" if same_identity is False else "(unknown)")
    )
    lines.append(f"- Message: {json.dumps(commit.get('message', ''))}")
    if history_scope.get("mode"):
        lines.append(f"- History mode: {history_scope.get('mode')}")
    if bounded_window:
        lines.append("- Author history counters below refer to the author identity only and are seen in the current bounded window, not full-repo history.")
    else:
        lines.append("- Author history counters below refer to the author identity only, not the committer.")
    lines.append(
        f"- Prior commits by same author email: "
        f"{_format_history_count(history.get('author_prior_commits_same_email'), bool(history.get('author_prior_commits_same_email_is_lower_bound')), bounded_window=bounded_window)}"
    )
    lines.append(
        f"- Prior commits by same author name: "
        f"{_format_history_count(history.get('author_prior_commits_same_name'), bool(history.get('author_prior_commits_same_name_is_lower_bound')), bounded_window=bounded_window)}"
    )
    lines.append(f"- Previous commit same author email at: {history.get('author_previous_commit_same_email_at') or '(none)'}")
    author_identity_history = history.get("author_identity_history") or {}
    if author_identity_history:
        author_identity = author_identity_history.get("current_author") or {}
        committer_identity = author_identity_history.get("current_committer") or {}
        author_committer_split = author_identity_history.get("author_committer_split") or {}
        history_caveats = author_identity_history.get("history_caveats") or []
        identity_flags = author_identity_history.get("identity_flags") or []
        lines.append(
            f"- Identity history source: {author_identity_history.get('history_source') or '(unknown)'}"
        )
        lines.append(
            f"- Identity baseline ref: {author_identity_history.get('baseline_ref') or '(unknown)'}"
        )
        if author_identity_history.get("default_branch_ref"):
            lines.append(
                f"- Identity comparison default branch ref: {author_identity_history.get('default_branch_ref')}"
            )
        if history_caveats:
            lines.append(f"- Identity caveats: {', '.join(history_caveats)}")
        lines.append(
            f"- Current author normalized identity: "
            f"name={author_identity.get('normalized_name') or '(none)'} "
            f"email={author_identity.get('normalized_email') or '(none)'} "
            f"domain={author_identity.get('email_domain') or '(none)'} "
            f"noreply={_format_bool_unknown(author_identity.get('email_is_noreply'))} "
            f"bot_like={_format_bool_unknown(author_identity.get('looks_bot_like'))}"
        )
        lines.append(
            f"- Prior exact author identity seen: "
            f"{_format_bool_unknown(author_identity_history.get('author_seen_before_exact'))}; "
            f"prior_commits {_format_history_count(author_identity_history.get('author_prior_exact_identity_commits'), bool(author_identity_history.get('author_prior_exact_identity_commits_is_lower_bound')), bounded_window=False)}"
        )
        lines.append(
            f"- Prior author email seen: {_format_bool_unknown(author_identity_history.get('author_email_seen_before'))}; "
            f"prior author name seen: {_format_bool_unknown(author_identity_history.get('author_name_seen_before'))}"
        )
        lines.append(
            f"- Prior names used with current author email: "
            f"{_format_identity_variants(author_identity_history.get('author_name_variants') or [], 'name')}"
        )
        lines.append(
            f"- Prior emails used with current author name: "
            f"{_format_identity_variants(author_identity_history.get('author_email_variants') or [], 'email')}"
        )
        lines.append(
            f"- Prior email domains used with current author name: "
            f"{', '.join(author_identity_history.get('author_prior_email_domains') or ['(none)'])}"
        )
        lines.append(
            f"- Current author email domain first seen for current name: "
            f"{_format_bool_unknown(author_identity_history.get('author_domain_first_seen'))}"
        )
        lines.append(
            f"- Author/committer split facts: "
            f"same_identity={_format_bool_unknown(author_committer_split.get('same_identity'))} "
            f"same_email={_format_bool_unknown(author_committer_split.get('same_email'))} "
            f"same_name={_format_bool_unknown(author_committer_split.get('same_name'))} "
            f"committer_seen_before_as_author={_format_bool_unknown(author_committer_split.get('committer_seen_before_as_author'))} "
            f"committer_prior_author_commits {_format_history_count(author_committer_split.get('committer_prior_author_commits_in_baseline'), bool(author_committer_split.get('committer_prior_author_commits_in_baseline_is_lower_bound')), bounded_window=False)}"
        )
        if committer_identity:
            lines.append(
                f"- Current committer normalized identity: "
                f"name={committer_identity.get('normalized_name') or '(none)'} "
                f"email={committer_identity.get('normalized_email') or '(none)'} "
                f"domain={committer_identity.get('email_domain') or '(none)'} "
                f"noreply={_format_bool_unknown(committer_identity.get('email_is_noreply'))} "
                f"bot_like={_format_bool_unknown(committer_identity.get('looks_bot_like'))}"
            )
        if identity_flags:
            lines.append(f"- Identity flags: {', '.join(identity_flags)}")
        # This renderer -- not `case_builder.render_agent_prompt` -- is what
        # `primary.py` and every verifier variant actually read. Omitting the block
        # here would leave the `domain_provenance` evidence ref pointing at a field
        # the model never sees.
        lines.extend(render_domain_provenance_lines(author_identity_history))
    author_surface_history = history.get("author_surface_history") or {}
    if author_surface_history:
        lines.append(f"- Surface history source: {author_surface_history.get('history_source') or '(unknown)'}")
        lines.append(
            f"- Prior author commits on default-branch baseline: "
            f"{_format_history_count(author_surface_history.get('author_prior_commits_default_branch'), bool(author_surface_history.get('author_prior_commits_default_branch_is_lower_bound')), bounded_window=False)}"
        )
        lines.append(
            f"- Prior sensitive-surface commits on default-branch baseline: "
            f"{_format_history_count(author_surface_history.get('author_prior_sensitive_commits_total'), bool(author_surface_history.get('author_prior_sensitive_commits_total_is_lower_bound')), bounded_window=False)}"
        )
        lines.append(
            f"- Current commit path classes: "
            f"{', '.join(author_surface_history.get('author_current_commit_path_classes') or ['(none)'])}"
        )
        current_new_classes = author_surface_history.get("author_current_new_path_classes") or []
        if current_new_classes:
            lines.append(f"- New path classes for author in current commit: {', '.join(current_new_classes)}")
        current_new_sensitive = author_surface_history.get("author_current_new_sensitive_path_classes") or []
        if current_new_sensitive:
            lines.append(f"- New sensitive path classes for author in current commit: {', '.join(current_new_sensitive)}")
        current_new_dirs = author_surface_history.get("author_current_new_top_level_dirs") or []
        if current_new_dirs:
            lines.append(f"- New top-level dirs for author in current commit: {', '.join(current_new_dirs)}")
        prior_sensitive_classes = author_surface_history.get("author_prior_sensitive_path_classes") or []
        lines.append(
            f"- Prior sensitive path classes on default-branch baseline: "
            f"{', '.join(prior_sensitive_classes) if prior_sensitive_classes else '(none)'}"
        )
        role_transition = author_surface_history.get("author_role_transition") or {}
        if role_transition:
            lines.append(
                f"- Author role transition: {role_transition.get('transition_label') or '(none)'} "
                f"(privilege escalation candidate={role_transition.get('is_privilege_escalation_candidate')})"
            )
        for item in (author_surface_history.get("sensitive_surface_hits") or [])[:8]:
            change_type = item.get("change_type")
            change_type_str = f" change_type={change_type}" if change_type else ""
            lines.append(
                f"- Sensitive surface hit: {item.get('path')} class={item.get('path_class')}"
                f"{change_type_str}"
                f" prior_exact_touches={item.get('author_prior_touches_exact_path')}"
                f" prior_class_touches={item.get('author_prior_touches_same_class')}"
                f" exact_first_touch={item.get('exact_path_first_touch')}"
                f" class_first_touch={item.get('class_first_touch')}"
            )
            # Render ownership evidence only when all five anomaly conditions hold:
            # 1. path_class in {ci_workflow, release_publish}
            # 2. change_type is M (or R when rename query was safe — see note)
            # 3. exact_path_first_touch is True
            # 4. prior_human_authors_count <= 5
            # 5. ownership_concentration == "high"
            # For rename cases (change_type == R), we conservatively exclude them in v1
            # because ownership was queried against the old path and the paths differ.
            path_class = item.get("path_class", "")
            prior_human_count = item.get("prior_human_authors_count")
            ownership_concentration = item.get("ownership_concentration", "")
            exact_first = item.get("exact_path_first_touch")
            top_human_owners = item.get("top_human_owners") or []
            top_human_author_share = item.get("top_human_author_share")
            if (
                path_class in {"ci_workflow", "release_publish"}
                and change_type == "M"
                and exact_first is True
                and prior_human_count is not None
                and prior_human_count <= 5
                and ownership_concentration == "high"
            ):
                # Do not render when the current author is already in top_human_owners
                # (that is the ordinary case — exculpatory to surface it).
                current_author_email = str(
                    (case.get("commit") or {}).get("author_email") or ""
                ).strip().casefold()
                author_in_owners = any(
                    str(o.get("email", "")).strip().casefold() == current_author_email
                    for o in top_human_owners
                    if current_author_email
                )
                if not author_in_owners:
                    owner_strs = ", ".join(
                        f"{o.get('email')}:{o.get('commit_count')}"
                        for o in top_human_owners
                    )
                    share_pct = f"{top_human_author_share * 100:.1f}%" if top_human_author_share is not None else "(unknown)"
                    lines.append(
                        f"  SENSITIVE PATH OWNERSHIP — {item.get('path')} ({path_class}):"
                    )
                    file_seen = item.get("file_seen_before_commit")
                    if file_seen is True:
                        lines.append("    File existed before this commit.")
                    lines.append(
                        f"    Author has {item.get('author_prior_touches_exact_path')} prior touch(es) to this exact path."
                    )
                    lines.append(
                        f"    Prior human authors: {prior_human_count}"
                        + (f" ({owner_strs})." if owner_strs else ".")
                    )
                    lines.append(
                        f"    Top author share: {share_pct}. Ownership concentration: {ownership_concentration.upper()}."
                    )
                    lines.append(
                        f"    Match basis: {item.get('ownership_match_basis', 'exact_email_only')}."
                    )
    pr_social_history = history.get("pr_social_history") or {}
    if pr_social_history:
        lines.extend(render_pr_social_history_lines(pr_social_history))
    author_temporal_complexity_history = history.get("author_temporal_complexity_history") or {}
    if author_temporal_complexity_history:
        temporal = author_temporal_complexity_history.get("temporal_distribution") or {}
        cadence = author_temporal_complexity_history.get("cadence") or {}
        timezone_history = author_temporal_complexity_history.get("timezone") or {}
        complexity = author_temporal_complexity_history.get("complexity") or {}
        lines.append(
            f"- Temporal/complexity history source: "
            f"{author_temporal_complexity_history.get('history_source') or '(unknown)'}"
        )
        lines.append(
            f"- Temporal/complexity baseline ref: "
            f"{author_temporal_complexity_history.get('baseline_ref') or '(unknown)'}"
        )
        lines.append(
            f"- Temporal/complexity baseline scope: "
            f"{author_temporal_complexity_history.get('baseline_scope') or '(unknown)'} "
            f"(observed ref {author_temporal_complexity_history.get('observed_ref') or '(unknown)'}, "
            f"is default branch="
            f"{_format_bool_unknown(author_temporal_complexity_history.get('observed_ref_is_default_branch'))}, "
            f"commits ahead of baseline="
            f"{author_temporal_complexity_history.get('observed_ref_commits_ahead_of_baseline')})"
        )
        if author_temporal_complexity_history.get("baseline_is_contributor_controlled"):
            lines.append(
                "- WARNING: the temporal baseline is branch-local, so this contributor may "
                "have authored the history it is compared against; treat agreement with the "
                "baseline as uninformative."
            )
        lines.append(
            f"- Prior author commits on default-branch temporal baseline: "
            f"{_format_history_count(author_temporal_complexity_history.get('author_prior_commits_default_branch'), bool(author_temporal_complexity_history.get('author_prior_commits_default_branch_is_lower_bound')), bounded_window=False)}"
        )
        caveats = author_temporal_complexity_history.get("history_caveats") or []
        if caveats:
            lines.append(f"- Temporal/complexity caveats: {', '.join(caveats)}")
        lines.append(
            f"- Current authored-at UTC bucket: hour={temporal.get('current_commit_hour_utc')} "
            f"weekday={_format_weekday_label(temporal.get('current_commit_weekday_utc'))} "
            f"prior_hour_count={temporal.get('current_commit_hour_prior_count')} "
            f"prior_weekday_count={temporal.get('current_commit_weekday_prior_count')}"
        )
        lines.append(
            f"- Prior authored-at UTC modes: hour={temporal.get('prior_mode_hour_utc')} "
            f"count={temporal.get('prior_mode_hour_count')}; weekday="
            f"{_format_weekday_label(temporal.get('prior_mode_weekday_utc'))} "
            f"count={temporal.get('prior_mode_weekday_count')}"
        )
        hour_delta = temporal.get("current_commit_hour_delta_from_prior_mode_utc")
        if hour_delta is not None:
            lines.append(f"- Current authored-at UTC hour delta from prior mode: {hour_delta}")
        lines.append(
            f"- Prior authored-at UTC hour histogram top buckets: "
            f"{_format_top_histogram_buckets(temporal.get('author_commit_hour_histogram_utc') or {})}"
        )
        lines.append(
            f"- Prior authored-at UTC weekday histogram top buckets: "
            f"{_format_top_histogram_buckets(temporal.get('author_commit_weekday_histogram_utc') or {}, label_map=WEEKDAY_LABEL_MAP)}"
        )
        lines.append(
            f"- Current gap since prior author commit: {cadence.get('current_gap_since_prior_commit_days')} days; "
            f"historical median={cadence.get('author_historical_interarrival_days_median')} "
            f"stddev={cadence.get('author_historical_interarrival_days_stddev')} "
            f"ratio={cadence.get('cadence_shift_ratio')} "
            f"sample_count={cadence.get('interarrival_sample_count')}"
        )
        recent_interarrivals = cadence.get("author_recent_interarrival_days") or []
        if recent_interarrivals:
            lines.append(f"- Recent author interarrival days: {json.dumps(recent_interarrivals)}")
        lines.append(
            f"- Current authored-at timezone offset: "
            f"{_format_timezone_offset_minutes(timezone_history.get('current_timezone_offset_minutes'))}; "
            f"prior_count={timezone_history.get('current_timezone_prior_count')} "
            f"mode={_format_timezone_offset_minutes(timezone_history.get('prior_mode_timezone_offset_minutes'))} "
            f"mode_count={timezone_history.get('prior_mode_timezone_count')} "
            f"first_seen={timezone_history.get('timezone_first_seen')} "
            f"drift_from_mode_minutes={timezone_history.get('timezone_drift_from_prior_mode_minutes')}"
        )
        lines.append(
            f"- Prior authored-at timezone offsets seen: "
            f"{_format_timezone_offset_counts(timezone_history.get('author_timezone_offsets_seen') or [])}"
        )
        lines.append(
            f"- Current message/diff stats: message_chars={complexity.get('commit_message_length')} "
            f"message_tokens={complexity.get('commit_message_token_count')} "
            f"files={complexity.get('diff_files_changed')} "
            f"added={complexity.get('diff_total_added_lines')} "
            f"deleted={complexity.get('diff_total_deleted_lines')} "
            f"changed={complexity.get('diff_total_changed_lines')}"
        )
        lines.append(
            f"- Historical commit size baseline: sample_count={complexity.get('historical_commit_size_sample_count')} "
            f"median={complexity.get('historical_commit_size_median')} "
            f"stddev={complexity.get('historical_commit_size_stddev')} "
            f"current_size_ratio_to_median={complexity.get('current_commit_size_ratio_to_historical_median')}"
        )
        lines.append(
            f"- Message-to-diff ratio: current={complexity.get('message_to_diff_ratio')} "
            f"historical_median={complexity.get('historical_message_to_diff_ratio_median')} "
            f"sample_count={complexity.get('message_to_diff_ratio_sample_count')} "
            f"mismatch_flag={complexity.get('message_to_diff_mismatch_flag')}"
        )
    lines.append(f"- Minutes since previous same-repo push: {timing.get('minutes_since_previous_repo_push')}")
    lines.append(f"- Same-repo pushes in prior 1 hour: {timing.get('repo_pushes_prev_1h')}")
    lines.append(f"- Same-actor pushes in prior 1 hour: {timing.get('repo_pushes_by_same_actor_prev_1h')}")
    lines.append("")
    lines.append("## Changed Files")
    files_changed = commit.get("files_changed", []) or []
    if files_changed:
        for item in files_changed:
            lines.append(
                f"- {item.get('path', '')} (+{item.get('added_lines') if item.get('added_lines') is not None else '?'}/-{item.get('deleted_lines') if item.get('deleted_lines') is not None else '?'})"
            )
    else:
        lines.append("- (none)")
    patch_excerpt = commit.get("patch_excerpt") or ""
    if patch_excerpt:
        lines.append("")
        lines.append("## Patch Excerpt")
        lines.append("```diff")
        lines.append(patch_excerpt)
        lines.append("```")
    return "\n".join(lines)


def build_verifier_prompt(case: CommitCase, finding: Finding, variant: dict[str, str], *, evidence_block: str = "", exclude_evidence: bool = False) -> str:
    if not evidence_block and not exclude_evidence:
        evidence_block = render_verifier_evidence(case)
    evidence_refs = ", ".join(finding.get("evidence_refs", []) or ["none"])
    lines: list[str] = []
    lines.append("You are a verifier reviewing a candidate supply-chain triage finding.")
    lines.append("Your job is not to rescore the whole commit. Your job is to test the specific claim below.")
    lines.append(variant["instructions"])
    lines.append("")
    lines.append("Decision rules:")
    lines.append("- `verify`: the claim is supported strongly enough to survive review.")
    lines.append("- `disprove`: the claim is materially undermined or overstated by the evidence.")
    lines.append("- `abstain`: the evidence is incomplete, ambiguous, or insufficient to decide.")
    lines.append("- Distinguish the patch author from the committer. In normal OSS workflows, the committer may be a maintainer who reviewed or merged someone else's patch.")
    lines.append("- Do not treat maintainer or committer history as author history when author and committer differ.")
    lines.append("- Explicitly test any claim that relies on maintainer-behavior deviation: ask whether the bounded history window really shows an unusual timing, path choice, or activity pattern.")
    lines.append("- Pressure-test ordinary explanations for behavior shifts, such as sparse history, release work, handoff, bursty maintenance, or incomplete repo context.")
    lines.append("- Do not accept repo-local timing/path deviation alone as proof of malicious intent unless the claim is corroborated by other concrete evidence in the case.")
    lines.append("- Treat PR/social metadata as supporting evidence only, not as a source of truth for maliciousness.")
    lines.append("- Do not infer role changes, account takeover, or broader GitHub-ecosystem behavior unless that evidence is explicitly present.")
    lines.append("- Read-only git tools may be available; use them when needed to pressure-test the claim, especially on file history or exact file contents.")
    lines.append("")
    lines.append("## Candidate Finding")
    lines.append(f"- Verifier variant: {variant['label']}")
    lines.append(f"- Finding ID: {finding.get('finding_id', '')}")
    lines.append(f"- Finding type: {finding.get('finding_type', '')}")
    lines.append(f"- Severity: {finding.get('severity', '')}")
    lines.append(f"- Claim: {finding.get('claim', '')}")
    lines.append(f"- Suggested action: {finding.get('suggested_action', '')}")
    lines.append(f"- Candidate evidence refs: {evidence_refs}")
    primary_signals = finding.get("primary_signals", [])
    if primary_signals:
        lines.append(f"- Primary signals: {json.dumps(primary_signals)}")
    lines.append("")
    if evidence_block:
        lines.append(evidence_block)
        lines.append("")
    lines.append("Respond in this exact format:")
    lines.append("**Outcome**: [verify/disprove/abstain]")
    lines.append("**Confidence**: [low/medium/high]")
    lines.append("**Rationale**: [2-4 sentences focused on the claim]")
    lines.append("**Evidence Refs**: [comma-separated case field refs or none]")
    return "\n".join(lines)


def build_commit_judgment_verifier_prompt(
    case: CommitCase,
    primary_result: dict[str, Any],
    findings: list[Finding],
    variant: dict[str, str],
    *,
    evidence_block: str = "",
    exclude_evidence: bool = False,
) -> str:
    if not evidence_block and not exclude_evidence:
        evidence_block = render_verifier_evidence(case)
    classification = str(primary_result.get("classification") or "").strip().lower()
    confidence = str(primary_result.get("confidence") or "").strip().lower() or "unknown"
    reasoning = str(primary_result.get("reasoning") or "").strip()

    if classification == "suspicious":
        verify_rule = "the commit as a whole warrants maintainer review or escalation"
        disprove_rule = "the primary suspicious judgment overstates the evidence or should not escalate"
    else:
        verify_rule = "the benign judgment should stand and the commit looks ordinary enough not to escalate"
        disprove_rule = "the benign judgment should not stand because the commit still warrants maintainer review"

    lines: list[str] = []
    lines.append("You are a verifier reviewing the primary commit-level triage judgment.")
    lines.append("Your job is to test the overall classification, not just one finding.")
    lines.append(variant["instructions"])
    lines.append("")
    lines.append("Decision rules:")
    lines.append(f"- `verify`: {verify_rule}.")
    lines.append(f"- `disprove`: {disprove_rule}.")
    lines.append("- `abstain`: the evidence is incomplete, ambiguous, or insufficient to decide.")
    lines.append("- Distinguish the patch author from the committer. In normal OSS workflows, the committer may be a maintainer who reviewed or merged someone else's patch.")
    lines.append("- Do not treat maintainer or committer history as author history when author and committer differ.")
    lines.append("- Explicitly test whether bounded repo-local history actually supports any temporal, cadence, path, or complexity deviation claim.")
    lines.append("- Pressure-test ordinary explanations such as sparse history, release work, bursty maintenance, backfills, timezone travel, DST shifts, or incomplete default-branch context.")
    lines.append("- Do not use repo-local timing/path deviation alone as proof of maliciousness without corroborating patch-level evidence.")
    lines.append("- Treat PR/social metadata as supporting evidence only, not as a source of truth for maliciousness.")
    lines.append("- Read-only git tools may be available; use them when needed to sharpen or falsify the overall judgment.")
    lines.append("")
    lines.append("## Primary Commit Judgment")
    lines.append(f"- Verifier variant: {variant['label']}")
    lines.append(f"- Target classification: {classification or 'unknown'}")
    lines.append(f"- Primary confidence: {confidence}")
    lines.append(f"- Primary reasoning: {reasoning or '(none)'}")
    lines.append(f"- Primary findings emitted: {len(findings)}")
    if findings:
        for index, finding in enumerate(findings[:3], start=1):
            lines.append(
                f"- Finding {index}: type={finding.get('finding_type', '')} severity={finding.get('severity', '')} "
                f"claim={finding.get('claim', '')}"
            )
    lines.append("")
    if evidence_block:
        lines.append(evidence_block)
        lines.append("")
    lines.append("Respond in this exact format:")
    lines.append("**Outcome**: [verify/disprove/abstain]")
    lines.append("**Confidence**: [low/medium/high]")
    lines.append("**Rationale**: [2-4 sentences focused on the overall judgment]")
    lines.append("**Evidence Refs**: [comma-separated case field refs or none]")
    return "\n".join(lines)


def parse_verifier_response(text: str) -> tuple[str, str, str, list[str]]:
    outcome_match = (
        re.search(r"\*\*Outcome\*\*:?\s*(verify|disprove|abstain)", text, flags=re.IGNORECASE)
        or re.search(r"Outcome:?\s*(verify|disprove|abstain)", text, flags=re.IGNORECASE)
    )
    confidence_match = (
        re.search(r"\*\*Confidence\*\*:?\s*(low|medium|high)", text, flags=re.IGNORECASE)
        or re.search(r"Confidence:?\s*(low|medium|high)", text, flags=re.IGNORECASE)
    )
    rationale_match = (
        re.search(r"\*\*Rationale\*\*:?\s*([\s\S]*?)(?:\n\*\*Evidence Refs\*\*:|\nEvidence Refs:|$)", text, flags=re.IGNORECASE)
        or re.search(r"Rationale:?\s*([\s\S]*?)(?:\n\*\*Evidence Refs\*\*:|\nEvidence Refs:|$)", text, flags=re.IGNORECASE)
    )
    refs_match = (
        re.search(r"\*\*Evidence Refs\*\*:?\s*(.+)$", text, flags=re.IGNORECASE | re.MULTILINE)
        or re.search(r"Evidence Refs:?\s*(.+)$", text, flags=re.IGNORECASE | re.MULTILINE)
    )

    outcome = outcome_match.group(1).lower() if outcome_match else "abstain"
    confidence = confidence_match.group(1).lower() if confidence_match else "unknown"
    rationale = rationale_match.group(1).strip() if rationale_match else text.strip()
    refs_raw = refs_match.group(1).strip() if refs_match else "none"
    evidence_refs = [item.strip() for item in refs_raw.split(",") if item.strip() and item.strip().lower() != "none"]
    return outcome, confidence, rationale, evidence_refs


def summarize_verifier_votes(votes: list[VerifierVote]) -> VerificationMatrix:
    verifications = sum(1 for item in votes if item.get("outcome") == "verify")
    disproofs = sum(1 for item in votes if item.get("outcome") == "disprove")
    abstains = sum(1 for item in votes if item.get("outcome") == "abstain")
    ratio = verifications / max(1, verifications + disproofs)

    status = "insufficient"
    if verifications >= 3 and disproofs == 0:
        status = "valid"
    elif disproofs >= 3 and verifications == 0:
        status = "rejected"
    elif verifications > 0 and disproofs > 0:
        status = "contested"
    elif verifications > 0 and disproofs == 0:
        status = "weak"
    elif disproofs > 0 and verifications == 0:
        status = "lean_rejected"

    return {
        "verifications": verifications,
        "disproofs": disproofs,
        "abstains": abstains,
        "verification_ratio": round(ratio, 3),
        "status": status,
    }
