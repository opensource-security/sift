from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any
from urllib import error, parse, request


API_ROOT = "https://api.github.com"
LINK_RE = re.compile(r'<([^>]+)>;\s*rel="([^"]+)"')


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _normalize_branch_name(ref: str) -> str:
    text = (ref or "").strip()
    if text.startswith("refs/heads/"):
        return text[len("refs/heads/") :]
    return text


def _format_rate_limit_reset(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    try:
        return (
            datetime.fromtimestamp(int(text), tz=timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
    except (TypeError, ValueError, OSError):
        return ""


def _parse_sort_key(submitted_at: str, fallback_id: int) -> tuple[int, int]:
    text = (submitted_at or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
        return int(dt.timestamp()), fallback_id
    except ValueError:
        return 0, fallback_id


class GitHubAPIError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        body: str = "",
        retry_after: str = "",
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body
        self.retry_after = retry_after


class GitHubRESTClient:
    def __init__(self, token: str, *, timeout_sec: int) -> None:
        self.token = (token or "").strip()
        self.timeout_sec = timeout_sec
        self.request_count = 0
        self.rate_limit_resource = ""
        self.rate_limit_remaining: int | None = None
        self.rate_limit_reset_at = ""
        self.secondary_rate_limited = False

    def _update_rate_limit(self, headers: Any) -> None:
        remaining_text = (headers.get("X-RateLimit-Remaining") or "").strip()
        if remaining_text:
            try:
                remaining = int(remaining_text)
                if self.rate_limit_remaining is None or remaining < self.rate_limit_remaining:
                    self.rate_limit_remaining = remaining
            except ValueError:
                pass
        resource = (headers.get("X-RateLimit-Resource") or "").strip()
        if resource:
            self.rate_limit_resource = resource
        reset_at = _format_rate_limit_reset(headers.get("X-RateLimit-Reset") or "")
        if reset_at:
            self.rate_limit_reset_at = reset_at

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "sift-pr-social/1",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def get_json(self, path_or_url: str) -> tuple[Any, Any]:
        url = path_or_url if path_or_url.startswith("http") else f"{API_ROOT}{path_or_url}"
        req = request.Request(url, headers=self._headers(), method="GET")
        try:
            with request.urlopen(req, timeout=self.timeout_sec) as resp:
                self.request_count += 1
                self._update_rate_limit(resp.headers)
                content = resp.read().decode("utf-8")
                return json.loads(content), resp.headers
        except error.HTTPError as exc:
            self.request_count += 1
            self._update_rate_limit(exc.headers or {})
            retry_after = (exc.headers.get("Retry-After") or "").strip() if exc.headers else ""
            body = ""
            try:
                body = exc.read().decode("utf-8", errors="replace")
            except Exception:
                body = ""
            if retry_after or "secondary rate limit" in body.lower():
                self.secondary_rate_limited = True
            raise GitHubAPIError(
                f"GitHub API HTTP {exc.code}",
                status_code=exc.code,
                body=body[:500],
                retry_after=retry_after,
            ) from exc
        except (error.URLError, TimeoutError, OSError) as exc:
            raise GitHubAPIError(f"GitHub API request failed: {exc}") from exc

    def get_paginated_json(self, path_or_url: str, *, max_pages: int) -> tuple[list[Any], bool]:
        items: list[Any] = []
        next_url = path_or_url
        pages_fetched = 0
        truncated = False
        while next_url:
            pages_fetched += 1
            if pages_fetched > max_pages:
                truncated = True
                break
            page_items, headers = self.get_json(next_url)
            if isinstance(page_items, list):
                items.extend(page_items)
            next_url = ""
            link_header = headers.get("Link") or ""
            for match in LINK_RE.finditer(link_header):
                candidate_url, rel = match.groups()
                if rel == "next":
                    next_url = candidate_url
                    break
        return items, truncated

    def summary(self) -> dict[str, Any]:
        return {
            "requests_made": self.request_count,
            "rate_limit_resource": self.rate_limit_resource,
            "rate_limit_remaining": self.rate_limit_remaining,
            "rate_limit_reset_at": self.rate_limit_reset_at,
            "secondary_rate_limited": self.secondary_rate_limited,
        }


def _pull_fetch_error(section: str, exc: GitHubAPIError) -> dict[str, Any]:
    return {
        "section": section,
        "message": str(exc),
        "http_status": exc.status_code,
        "retry_after": exc.retry_after,
        "body_excerpt": exc.body,
    }


def _dedupe_latest_reviews(reviews: list[dict[str, Any]], *, author_login: str) -> dict[str, Any]:
    author_key = (author_login or "").strip().lower()
    latest_by_reviewer: dict[str, dict[str, Any]] = {}
    non_author_review_events_total = 0
    for item in reviews:
        user = item.get("user") or {}
        reviewer_login = str(user.get("login") or "").strip()
        if not reviewer_login:
            continue
        reviewer_key = reviewer_login.lower()
        if reviewer_key == author_key:
            continue
        non_author_review_events_total += 1
        candidate = {
            "reviewer_login": reviewer_login,
            "state": str(item.get("state") or "").strip().upper() or "UNKNOWN",
            "submitted_at": str(item.get("submitted_at") or "").strip(),
            "author_association": str(item.get("author_association") or "").strip(),
        }
        existing = latest_by_reviewer.get(reviewer_key)
        candidate_key = _parse_sort_key(candidate["submitted_at"], int(item.get("id") or 0))
        if existing is None:
            latest_by_reviewer[reviewer_key] = {**candidate, "_sort_key": candidate_key}
            continue
        if candidate_key >= existing["_sort_key"]:
            latest_by_reviewer[reviewer_key] = {**candidate, "_sort_key": candidate_key}

    latest_reviews = [
        {
            "reviewer_login": item["reviewer_login"],
            "state": item["state"],
            "submitted_at": item["submitted_at"],
            "author_association": item["author_association"],
        }
        for item in latest_by_reviewer.values()
    ]
    latest_reviews.sort(key=lambda item: (item.get("submitted_at") or "", item["reviewer_login"].lower()))
    latest_reviews.reverse()
    approvals = sum(1 for item in latest_reviews if item.get("state") == "APPROVED")
    changes_requested = sum(1 for item in latest_reviews if item.get("state") == "CHANGES_REQUESTED")
    commented = sum(1 for item in latest_reviews if item.get("state") == "COMMENTED")
    dismissed = sum(1 for item in latest_reviews if item.get("state") == "DISMISSED")
    opinionated = sum(
        1
        for item in latest_reviews
        if item.get("state") in {"APPROVED", "CHANGES_REQUESTED", "COMMENTED"}
    )
    return {
        "review_events_total_raw": len(reviews),
        "non_author_review_events_total": non_author_review_events_total,
        "distinct_non_author_reviewers_total": len(latest_reviews),
        "latest_non_author_opinionated_reviews_total": opinionated,
        "latest_non_author_approvals_total": approvals,
        "latest_non_author_changes_requested_total": changes_requested,
        "latest_non_author_commented_total": commented,
        "latest_non_author_dismissed_total": dismissed,
        "latest_reviews_by_reviewer": latest_reviews,
    }


def _parse_branch_review_policy(rules: Any, *, branch_name: str) -> dict[str, Any]:
    parsed_rules = rules if isinstance(rules, list) else []
    pull_request_rules = [item for item in parsed_rules if (item.get("type") or "") == "pull_request"]
    required_approving_review_count: int | None = None
    require_code_owner_review = False
    dismiss_stale_reviews_on_push = False
    require_last_push_approval = False
    required_review_thread_resolution = False
    bypass_actors_present = False
    for rule in pull_request_rules:
        parameters = rule.get("parameters") or {}
        count = parameters.get("required_approving_review_count")
        if isinstance(count, int):
            required_approving_review_count = max(required_approving_review_count or 0, count)
        require_code_owner_review = (
            require_code_owner_review or bool(parameters.get("require_code_owner_review"))
        )
        dismiss_stale_reviews_on_push = (
            dismiss_stale_reviews_on_push or bool(parameters.get("dismiss_stale_reviews_on_push"))
        )
        require_last_push_approval = (
            require_last_push_approval or bool(parameters.get("require_last_push_approval"))
        )
        required_review_thread_resolution = (
            required_review_thread_resolution or bool(parameters.get("required_review_thread_resolution"))
        )
        bypass_actors_present = bypass_actors_present or bool(rule.get("bypass_actors"))
    return {
        "available": True,
        "policy_source": "repo_rules_branch_snapshot_v1",
        "branch_name": branch_name,
        "rules_total": len(parsed_rules),
        "pull_request_rules_total": len(pull_request_rules),
        "required_pull_request": bool(pull_request_rules),
        "required_approving_review_count": required_approving_review_count,
        "require_code_owner_review": require_code_owner_review,
        "dismiss_stale_reviews_on_push": dismiss_stale_reviews_on_push,
        "require_last_push_approval": require_last_push_approval,
        "required_review_thread_resolution": required_review_thread_resolution,
        "bypass_actors_present": bypass_actors_present,
    }


def build_current_pr_social_history(
    *,
    repo: str,
    pr_number: int | None,
    base_ref: str,
    head_ref: str,
    token: str,
    timeout_sec: int = 30,
    max_review_pages: int = 5,
) -> dict[str, Any]:
    collected_at = now_utc_iso()
    history: dict[str, Any] = {
        "history_source": "github_pr_social_v1",
        "collection_mode": "current_pr_only_v1",
        "available": False,
        "partial_data": False,
        "collected_at_utc": collected_at,
        "repo": repo,
        "pr_number": pr_number,
        "current_pr": {},
        "branch_review_policy_current": {
            "available": False,
            "policy_source": "repo_rules_branch_snapshot_v1",
        },
        "fetch_summary": {
            "requests_made": 0,
            "rate_limit_resource": "",
            "rate_limit_remaining": None,
            "rate_limit_reset_at": "",
            "secondary_rate_limited": False,
        },
        "fetch_errors": [],
        "comparison_notes": [
            "PR/social metadata is supporting evidence only and not a source of truth for maliciousness",
            "all values reflect the current PR snapshot rather than final merge outcome",
            "requested-reviewer counts are current outstanding requests only",
            "current branch rules may differ from the rules that applied to older PRs",
        ],
    }
    if not repo.strip() or not pr_number:
        history["fetch_errors"].append(
            {
                "section": "pull_request",
                "message": "current PR enrichment requires repo and pr_number",
                "http_status": None,
                "retry_after": "",
                "body_excerpt": "",
            }
        )
        return history

    client = GitHubRESTClient(token, timeout_sec=timeout_sec)
    pull_path = f"/repos/{repo}/pulls/{pr_number}"
    try:
        pull, _ = client.get_json(pull_path)
    except GitHubAPIError as exc:
        history["fetch_errors"].append(_pull_fetch_error("pull_request", exc))
        history["fetch_summary"] = client.summary()
        history["partial_data"] = bool(history["fetch_errors"])
        return history

    author = pull.get("user") or {}
    author_login = str(author.get("login") or "").strip()
    requested_reviewers = pull.get("requested_reviewers") or []
    requested_teams = pull.get("requested_teams") or []
    history["available"] = True
    history["current_pr"] = {
        "repo": repo,
        "pr_number": pr_number,
        "state": str(pull.get("state") or "").strip(),
        "draft": bool(pull.get("draft")),
        "base_ref": f"refs/heads/{_normalize_branch_name(str((pull.get('base') or {}).get('ref') or base_ref))}",
        "head_ref": f"refs/heads/{_normalize_branch_name(str((pull.get('head') or {}).get('ref') or head_ref))}",
        "created_at": str(pull.get("created_at") or "").strip(),
        "updated_at": str(pull.get("updated_at") or "").strip(),
        "author_login": author_login,
        "author_association": str(pull.get("author_association") or "").strip(),
        "requested_reviewers_current": {
            "users": len(requested_reviewers),
            "teams": len(requested_teams),
            "total": len(requested_reviewers) + len(requested_teams),
            "user_logins": [
                str(item.get("login") or "").strip()
                for item in requested_reviewers
                if str(item.get("login") or "").strip()
            ],
            "team_slugs": [
                str(item.get("slug") or "").strip()
                for item in requested_teams
                if str(item.get("slug") or "").strip()
            ],
        },
        "author_repo_permission_current": {
            "available": False,
            "reason": "not_collected_in_current_pr_v1",
        },
    }

    reviews_path = f"/repos/{repo}/pulls/{pr_number}/reviews?per_page=100"
    try:
        review_items, review_items_truncated = client.get_paginated_json(reviews_path, max_pages=max_review_pages)
        reviews_current = _dedupe_latest_reviews(review_items, author_login=author_login)
        reviews_current["available"] = True
        reviews_current["review_pages_truncated"] = review_items_truncated
        reviews_current["review_pages_limit"] = max_review_pages
        history["current_pr"]["reviews_current"] = reviews_current
    except GitHubAPIError as exc:
        history["fetch_errors"].append(_pull_fetch_error("pull_request_reviews", exc))
        history["current_pr"]["reviews_current"] = {
            "available": False,
            "review_events_total_raw": 0,
            "non_author_review_events_total": 0,
            "distinct_non_author_reviewers_total": 0,
            "latest_non_author_opinionated_reviews_total": 0,
            "latest_non_author_approvals_total": 0,
            "latest_non_author_changes_requested_total": 0,
            "latest_non_author_commented_total": 0,
            "latest_non_author_dismissed_total": 0,
            "latest_reviews_by_reviewer": [],
            "review_pages_truncated": False,
            "review_pages_limit": max_review_pages,
        }

    current_reviews = history["current_pr"].get("reviews_current") or {}
    requested = history["current_pr"].get("requested_reviewers_current") or {}
    history["current_pr"]["solo_snapshot"] = {
        "is_effectively_solo": bool(
            history["current_pr"].get("reviews_current", {}).get("available")
            and current_reviews.get("distinct_non_author_reviewers_total", 0) == 0
            and requested.get("total", 0) == 0
        ),
        "definition_version": "v1_no_non_author_review_and_no_outstanding_requests",
        "snapshot_only": True,
    }

    branch_name = _normalize_branch_name(str((pull.get("base") or {}).get("ref") or base_ref))
    if branch_name:
        rules_path = f"/repos/{repo}/rules/branches/{parse.quote(branch_name, safe='')}"
        try:
            rules, _ = client.get_json(rules_path)
            history["branch_review_policy_current"] = _parse_branch_review_policy(rules, branch_name=branch_name)
        except GitHubAPIError as exc:
            history["fetch_errors"].append(_pull_fetch_error("branch_review_policy", exc))
            history["branch_review_policy_current"] = {
                "available": False,
                "policy_source": "repo_rules_branch_snapshot_v1",
                "branch_name": branch_name,
                "required_pull_request": None,
                "required_approving_review_count": None,
                "require_code_owner_review": None,
                "dismiss_stale_reviews_on_push": None,
                "require_last_push_approval": None,
                "required_review_thread_resolution": None,
                "bypass_actors_present": None,
            }

    history["fetch_summary"] = client.summary()
    history["partial_data"] = bool(history["fetch_errors"])
    return history


def render_pr_social_history_lines(pr_social_history: dict[str, Any]) -> list[str]:
    if not pr_social_history:
        return []
    lines: list[str] = []
    lines.append(
        "- PR/social metadata is supporting evidence only and not a source of truth for maliciousness."
    )
    lines.append(
        f"- PR/social history source: {pr_social_history.get('history_source') or '(unknown)'} "
        f"(mode={pr_social_history.get('collection_mode') or '(unknown)'}, "
        f"available={pr_social_history.get('available')}, partial={pr_social_history.get('partial_data')})"
    )
    current_pr = pr_social_history.get("current_pr") or {}
    if current_pr:
        lines.append(
            f"- Current PR state: {current_pr.get('state') or '(unknown)'} "
            f"(draft={current_pr.get('draft')})"
        )
        lines.append(
            f"- Current PR author association: {current_pr.get('author_association') or '(unknown)'}"
        )
        requested = current_pr.get("requested_reviewers_current") or {}
        lines.append(
            f"- Current requested reviewers: users={requested.get('users', 0)} "
            f"teams={requested.get('teams', 0)} total={requested.get('total', 0)}"
        )
        reviews = current_pr.get("reviews_current") or {}
        if reviews.get("available"):
            lines.append(
                f"- Current non-author reviews: distinct_reviewers={reviews.get('distinct_non_author_reviewers_total', 0)} "
                f"approvals={reviews.get('latest_non_author_approvals_total', 0)} "
                f"changes_requested={reviews.get('latest_non_author_changes_requested_total', 0)} "
                f"raw_events={reviews.get('review_events_total_raw', 0)}"
            )
            latest_reviews = reviews.get("latest_reviews_by_reviewer") or []
            if latest_reviews:
                reviewer_bits = [
                    f"{item.get('reviewer_login')}:{item.get('state')}"
                    for item in latest_reviews[:6]
                    if item.get("reviewer_login")
                ]
                if reviewer_bits:
                    lines.append(f"- Latest non-author review states: {', '.join(reviewer_bits)}")
        else:
            lines.append("- Current non-author reviews: (unavailable)")
        solo_snapshot = current_pr.get("solo_snapshot") or {}
        lines.append(
            f"- Current PR effectively solo: {solo_snapshot.get('is_effectively_solo')} "
            f"(snapshot_only={solo_snapshot.get('snapshot_only')})"
        )
    branch_policy = pr_social_history.get("branch_review_policy_current") or {}
    if branch_policy.get("available"):
        lines.append(
            f"- Current branch review policy: required_pull_request={branch_policy.get('required_pull_request')} "
            f"required_approvals={branch_policy.get('required_approving_review_count')} "
            f"code_owner_review={branch_policy.get('require_code_owner_review')} "
            f"last_push_approval={branch_policy.get('require_last_push_approval')}"
        )
    else:
        lines.append("- Current branch review policy: (unavailable)")
    fetch_summary = pr_social_history.get("fetch_summary") or {}
    lines.append(
        f"- PR/social fetch summary: requests={fetch_summary.get('requests_made', 0)} "
        f"rate_limit_remaining={fetch_summary.get('rate_limit_remaining')} "
        f"rate_limit_reset_at={fetch_summary.get('rate_limit_reset_at') or '(unknown)'} "
        f"secondary_rate_limited={fetch_summary.get('secondary_rate_limited')}"
    )
    fetch_errors = pr_social_history.get("fetch_errors") or []
    if fetch_errors:
        error_bits = []
        for item in fetch_errors[:4]:
            section = item.get("section") or "unknown_section"
            message = item.get("message") or "error"
            status = item.get("http_status")
            if status:
                error_bits.append(f"{section}: HTTP {status} ({message})")
            else:
                error_bits.append(f"{section}: {message}")
        lines.append(f"- PR/social fetch errors: {'; '.join(error_bits)}")
    return lines
