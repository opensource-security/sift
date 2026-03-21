from __future__ import annotations

import json
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from .types import CommitCase


READONLY_TOOL_BUNDLE_VERSION = "repo_readonly_v1"
DEFAULT_TOOL_MAX_CHARS = 12000
MAX_TOOL_MAX_CHARS = 20000
DEFAULT_LOG_LIMIT = 8
MAX_LOG_LIMIT = 20


def anthropic_readonly_repo_tools() -> list[dict[str, Any]]:
    return [
        {
            "name": "git_show_commit",
            "description": (
                "Read the full git show output for a commit in the analyzed repository, "
                "including message, stat summary, and diff."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "sha": {
                        "type": "string",
                        "description": "Optional commit SHA. Defaults to the analyzed commit.",
                    },
                    "max_chars": {
                        "type": "integer",
                        "description": "Optional output cap in characters, maximum 20000.",
                    },
                },
                "required": [],
            },
        },
        {
            "name": "git_show_file",
            "description": (
                "Read a file at a specific git revision from the analyzed repository without checking it out."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Repository-relative file path.",
                    },
                    "sha": {
                        "type": "string",
                        "description": "Optional revision SHA. Defaults to the analyzed commit.",
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "Optional 1-based start line.",
                    },
                    "end_line": {
                        "type": "integer",
                        "description": "Optional 1-based end line, inclusive.",
                    },
                    "max_chars": {
                        "type": "integer",
                        "description": "Optional output cap in characters, maximum 20000.",
                    },
                },
                "required": ["path"],
            },
        },
        {
            "name": "git_diff_path",
            "description": (
                "Read the diff for a single file path in a specific commit."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Repository-relative file path.",
                    },
                    "sha": {
                        "type": "string",
                        "description": "Optional commit SHA. Defaults to the analyzed commit.",
                    },
                    "max_chars": {
                        "type": "integer",
                        "description": "Optional output cap in characters, maximum 20000.",
                    },
                },
                "required": ["path"],
            },
        },
        {
            "name": "git_log_path",
            "description": (
                "Read recent commit history for a repository path before the analyzed commit."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Repository-relative file path.",
                    },
                    "before_sha": {
                        "type": "string",
                        "description": (
                            "Optional anchor revision. Defaults to the first parent of the analyzed commit, "
                            "or the analyzed commit if it has no parent."
                        ),
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Optional number of log entries, maximum 20.",
                    },
                },
                "required": ["path"],
            },
        },
    ]


def _run_git(repo_path: Path, *args: str) -> tuple[int, str, str]:
    proc = subprocess.run(
        ["git", "-C", str(repo_path), *args],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _normalize_max_chars(raw_value: Any) -> int:
    try:
        parsed = int(raw_value)
    except (TypeError, ValueError):
        return DEFAULT_TOOL_MAX_CHARS
    return max(200, min(parsed, MAX_TOOL_MAX_CHARS))


def _normalize_limit(raw_value: Any) -> int:
    try:
        parsed = int(raw_value)
    except (TypeError, ValueError):
        return DEFAULT_LOG_LIMIT
    return max(1, min(parsed, MAX_LOG_LIMIT))


def _truncate_text(text: str, max_chars: int) -> tuple[str, bool]:
    if len(text) <= max_chars:
        return text, False
    return text[:max_chars], True


def _sanitize_repo_relative_path(path_text: Any) -> str:
    text = str(path_text or "").strip().replace("\\", "/")
    if not text:
        raise ValueError("path is required")
    pure = PurePosixPath(text)
    if pure.is_absolute():
        raise ValueError("path must be repository-relative")
    if any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError("path must not contain empty, '.' , or '..' segments")
    return pure.as_posix()


def _default_anchor_sha(case: CommitCase) -> str:
    parents = (case.get("commit") or {}).get("parent_shas") or []
    if parents:
        return str(parents[0]).strip()
    return str(case.get("commit_sha") or "").strip()


def _default_target_sha(case: CommitCase) -> str:
    return str(case.get("commit_sha") or "").strip()


def _tool_result(name: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {"tool_name": name, **payload}


def _git_show_commit(case: CommitCase, input_payload: dict[str, Any]) -> dict[str, Any]:
    repo_path = Path(case["mirror_path"])
    sha = str(input_payload.get("sha") or _default_target_sha(case)).strip()
    max_chars = _normalize_max_chars(input_payload.get("max_chars"))
    code, out, err = _run_git(repo_path, "show", "--stat", "--patch", "--format=fuller", "--no-ext-diff", sha)
    if code != 0:
        return _tool_result("git_show_commit", {"ok": False, "sha": sha, "error": err.strip() or out.strip()})
    rendered, truncated = _truncate_text(out, max_chars)
    return _tool_result(
        "git_show_commit",
        {
            "ok": True,
            "sha": sha,
            "output": rendered,
            "truncated": truncated,
            "max_chars": max_chars,
        },
    )


def _git_show_file(case: CommitCase, input_payload: dict[str, Any]) -> dict[str, Any]:
    repo_path = Path(case["mirror_path"])
    path = _sanitize_repo_relative_path(input_payload.get("path"))
    sha = str(input_payload.get("sha") or _default_target_sha(case)).strip()
    max_chars = _normalize_max_chars(input_payload.get("max_chars"))
    code, out, err = _run_git(repo_path, "show", f"{sha}:{path}")
    if code != 0:
        return _tool_result("git_show_file", {"ok": False, "sha": sha, "path": path, "error": err.strip() or out.strip()})

    lines = out.splitlines()
    start_line_raw = input_payload.get("start_line")
    end_line_raw = input_payload.get("end_line")
    selected_start = 1
    selected_end = len(lines)
    if start_line_raw is not None:
        try:
            selected_start = max(1, int(start_line_raw))
        except (TypeError, ValueError):
            selected_start = 1
    if end_line_raw is not None:
        try:
            selected_end = max(selected_start, int(end_line_raw))
        except (TypeError, ValueError):
            selected_end = len(lines)
    if lines:
        snippet = "\n".join(lines[selected_start - 1:selected_end])
    else:
        snippet = ""
    rendered, truncated = _truncate_text(snippet, max_chars)
    return _tool_result(
        "git_show_file",
        {
            "ok": True,
            "sha": sha,
            "path": path,
            "line_count": len(lines),
            "selected_start_line": selected_start,
            "selected_end_line": selected_end,
            "content": rendered,
            "truncated": truncated,
            "max_chars": max_chars,
        },
    )


def _git_diff_path(case: CommitCase, input_payload: dict[str, Any]) -> dict[str, Any]:
    repo_path = Path(case["mirror_path"])
    path = _sanitize_repo_relative_path(input_payload.get("path"))
    sha = str(input_payload.get("sha") or _default_target_sha(case)).strip()
    max_chars = _normalize_max_chars(input_payload.get("max_chars"))
    code, out, err = _run_git(
        repo_path,
        "diff-tree",
        "--root",
        "--patch",
        "--stat",
        "--unified=3",
        sha,
        "--",
        path,
    )
    if code != 0:
        return _tool_result("git_diff_path", {"ok": False, "sha": sha, "path": path, "error": err.strip() or out.strip()})
    rendered, truncated = _truncate_text(out, max_chars)
    return _tool_result(
        "git_diff_path",
        {
            "ok": True,
            "sha": sha,
            "path": path,
            "output": rendered,
            "truncated": truncated,
            "max_chars": max_chars,
        },
    )


def _git_log_path(case: CommitCase, input_payload: dict[str, Any]) -> dict[str, Any]:
    repo_path = Path(case["mirror_path"])
    path = _sanitize_repo_relative_path(input_payload.get("path"))
    before_sha = str(input_payload.get("before_sha") or _default_anchor_sha(case)).strip()
    limit = _normalize_limit(input_payload.get("limit"))
    code, out, err = _run_git(
        repo_path,
        "log",
        f"-n{limit}",
        "--format=format:%H%x09%an%x09%ae%x09%aI%x09%s",
        before_sha,
        "--",
        path,
    )
    if code != 0:
        return _tool_result(
            "git_log_path",
            {"ok": False, "before_sha": before_sha, "path": path, "error": err.strip() or out.strip()},
        )
    entries = []
    for line in out.splitlines():
        parts = line.split("\t", 4)
        if len(parts) != 5:
            continue
        sha, author_name, author_email, authored_at, subject = parts
        entries.append(
            {
                "sha": sha,
                "short_sha": sha[:7],
                "author_name": author_name,
                "author_email": author_email,
                "authored_at": authored_at,
                "subject": subject,
            }
        )
    return _tool_result(
        "git_log_path",
        {
            "ok": True,
            "before_sha": before_sha,
            "path": path,
            "limit": limit,
            "entries": entries,
        },
    )


def make_repo_tool_runner(case: CommitCase) -> Callable[[str, dict[str, Any]], dict[str, Any]]:
    tool_impls = {
        "git_show_commit": _git_show_commit,
        "git_show_file": _git_show_file,
        "git_diff_path": _git_diff_path,
        "git_log_path": _git_log_path,
    }

    def run_tool(name: str, input_payload: dict[str, Any]) -> dict[str, Any]:
        tool_fn = tool_impls.get(name)
        if tool_fn is None:
            return _tool_result(name, {"ok": False, "error": f"unknown tool: {name}"})
        try:
            return tool_fn(case, input_payload or {})
        except Exception as exc:
            return _tool_result(name, {"ok": False, "error": str(exc)})

    return run_tool


def render_tool_result(result: dict[str, Any]) -> str:
    return json.dumps(result, ensure_ascii=False)
