from __future__ import annotations

import fnmatch
from typing import Any


SENSITIVE_SURFACE_PROFILE_VERSION = "sensitive_surface_profile_v1"
DEFAULT_SENSITIVE_CLASSES = (
    "ci_workflow",
    "build_config",
    "dependency_manifest",
    "release_publish",
)

DEFAULT_PATH_CLASS_RULES: list[dict[str, Any]] = [
    {
        "path_class": "ci_workflow",
        "patterns": [
            ".github/workflows/**",
            ".circleci/**",
            ".buildkite/**",
            ".ci/**",
            "ci/**",
        ],
    },
    {
        "path_class": "release_publish",
        "patterns": [
            "release/**",
            "releases/**",
            "publish/**",
            "publishing/**",
            "scripts/release/**",
            "scripts/publish/**",
            "tools/release/**",
            "tools/publish/**",
            "tools/signing/**",
            "signing/**",
            "sigstore/**",
        ],
    },
    {
        "path_class": "dependency_manifest",
        "patterns": [
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "requirements*.txt",
            "requirements/**/*.txt",
            "constraints*.txt",
            "constraints/**/*.txt",
            "Pipfile",
            "Pipfile.lock",
            "poetry.lock",
            "package.json",
            "package-lock.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "Cargo.toml",
            "Cargo.lock",
            "go.mod",
            "go.sum",
        ],
    },
    {
        "path_class": "build_config",
        "patterns": [
            "Makefile",
            "**/Makefile",
            "Dockerfile",
            "Dockerfile.*",
            "**/Dockerfile",
            "**/Dockerfile.*",
            "docker-compose*.yml",
            "docker-compose*.yaml",
            "compose*.yml",
            "compose*.yaml",
            "noxfile.py",
            "tox.ini",
            "CMakeLists.txt",
            "meson.build",
            "Brewfile",
        ],
    },
    {
        "path_class": "tests",
        "patterns": [
            "tests/**",
            "test/**",
            "testing/**",
            "**/tests/**",
            "**/test/**",
            "**/testing/**",
            "**/__tests__/**",
            "test_*.py",
            "**/test_*.py",
            "**/*_test.py",
            "**/*.spec.ts",
            "**/*.spec.js",
        ],
    },
    {
        "path_class": "docs",
        "patterns": [
            "docs/**",
            "doc/**",
            "**/*.md",
            "**/*.rst",
            "**/*.txt",
            "README*",
            "CHANGELOG*",
            "NEWS*",
        ],
    },
    {
        "path_class": "source_code",
        "patterns": [
            "src/**",
            "lib/**",
            "pkg/**",
            "**/*.py",
            "**/*.c",
            "**/*.cc",
            "**/*.cpp",
            "**/*.h",
            "**/*.hpp",
            "**/*.go",
            "**/*.rs",
            "**/*.java",
            "**/*.kt",
            "**/*.js",
            "**/*.ts",
            "**/*.tsx",
            "**/*.sh",
        ],
    },
]

REPO_PROFILE_OVERRIDES: dict[str, dict[str, Any]] = {
    "pypa/pip": {
        "prepend_rules": [
            {
                "path_class": "release_publish",
                "patterns": [
                    "tools/release/**",
                    "tools/release.py",
                    ".github/workflows/release.yml",
                ],
            },
            {
                "path_class": "build_config",
                "patterns": [
                    "build-project/**",
                    "tools/ci/**",
                ],
            },
            {
                "path_class": "dependency_manifest",
                "patterns": [
                    "src/pip/_vendor/**",
                    "tools/vendoring/**",
                ],
            },
        ],
    },
}


def _normalize_path(path: str) -> str:
    return (path or "").strip().replace("\\", "/").lstrip("./")


def _matches_any(path: str, patterns: list[str]) -> bool:
    normalized = _normalize_path(path)
    return any(fnmatch.fnmatchcase(normalized, pattern) for pattern in patterns)


def sensitive_surface_profile(repo_id: str) -> dict[str, Any]:
    repo_key = (repo_id or "").strip().lower()
    override = REPO_PROFILE_OVERRIDES.get(repo_key, {})
    rules = [
        *override.get("prepend_rules", []),
        *DEFAULT_PATH_CLASS_RULES,
        *override.get("append_rules", []),
    ]
    sensitive_classes = tuple(override.get("sensitive_classes", DEFAULT_SENSITIVE_CLASSES))
    return {
        "profile_version": SENSITIVE_SURFACE_PROFILE_VERSION,
        "repo": repo_id,
        "rules": rules,
        "sensitive_classes": sensitive_classes,
        "recent_window_commits": int(override.get("recent_window_commits", 10)),
    }


def classify_path_class(path: str, profile: dict[str, Any]) -> str:
    normalized = _normalize_path(path)
    if not normalized:
        return "other"
    for rule in profile.get("rules", []):
        if _matches_any(normalized, list(rule.get("patterns", []))):
            return str(rule.get("path_class") or "other")
    return "other"


def classify_paths(paths: list[str], profile: dict[str, Any]) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for path in paths:
        normalized = _normalize_path(path)
        if not normalized:
            continue
        items.append(
            {
                "path": normalized,
                "path_class": classify_path_class(normalized, profile),
            }
        )
    return items


def path_class_order(profile: dict[str, Any]) -> list[str]:
    ordered: list[str] = []
    for rule in profile.get("rules", []):
        path_class = str(rule.get("path_class") or "").strip()
        if path_class and path_class not in ordered:
            ordered.append(path_class)
    if "other" not in ordered:
        ordered.append("other")
    return ordered


def top_level_directory(path: str) -> str:
    normalized = _normalize_path(path)
    if not normalized:
        return "(unknown)"
    if "/" not in normalized:
        return "(repo_root)"
    return normalized.split("/", 1)[0]
