"""
Named analysis profiles.

A profile bundles model, thinking, effort, verifier count, tool mode,
and result policy into a stable versioned configuration. This replaces
flag soup with a single --profile argument.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sift.runtime.analysis import RunnerConfig, ResultPolicy


@dataclass
class Profile:
    """A named, versioned analysis configuration."""

    name: str
    description: str
    runner_config: RunnerConfig
    result_policy: ResultPolicy
    max_patch_chars: int = 12000
    max_files: int = 200
    max_author_commits: int = 20
    max_path_commits: int = 5
    max_paths_for_history: int = 10
    max_ref_history_commits: int = 20


# -- Built-in profiles -------------------------------------------------------

MAINTAINER_REVIEW_V1 = Profile(
    name="maintainer_review_v1",
    description="Standard maintainer review — Sonnet, adaptive thinking, high effort, 3 verifiers",
    runner_config=RunnerConfig(
        runner="anthropic",
        anthropic_model="claude-sonnet-4-20250514",
        anthropic_thinking="adaptive",
        anthropic_effort="high",
        anthropic_tool_mode="readonly",
        verifier_count=3,
    ),
    result_policy=ResultPolicy(
        maintainer_visible=True,
        blocking=False,
        requested_action="write_summary",
    ),
)

MAINTAINER_REVIEW_FAST_V1 = Profile(
    name="maintainer_review_fast_v1",
    description="Fast maintainer review — Haiku, no thinking, medium effort, 1 verifier",
    runner_config=RunnerConfig(
        runner="anthropic",
        anthropic_model="claude-haiku-4-5-20251001",
        anthropic_thinking="off",
        anthropic_effort="medium",
        anthropic_tool_mode="none",
        verifier_count=1,
    ),
    result_policy=ResultPolicy(
        maintainer_visible=True,
        blocking=False,
        requested_action="write_summary",
    ),
)

MAINTAINER_REVIEW_MAX_V1 = Profile(
    name="maintainer_review_max_v1",
    description="Deep maintainer review — Opus, adaptive thinking, max effort, 5 verifiers",
    runner_config=RunnerConfig(
        runner="anthropic",
        anthropic_model="claude-opus-4-6",
        anthropic_thinking="adaptive",
        anthropic_effort="max",
        anthropic_tool_mode="readonly",
        verifier_count=5,
    ),
    result_policy=ResultPolicy(
        maintainer_visible=True,
        blocking=False,
        requested_action="write_summary",
    ),
)


BUILTIN_PROFILES: dict[str, Profile] = {
    p.name: p
    for p in [
        MAINTAINER_REVIEW_V1,
        MAINTAINER_REVIEW_FAST_V1,
        MAINTAINER_REVIEW_MAX_V1,
    ]
}


def get_profile(name: str) -> Profile:
    """Look up a built-in profile by name."""
    profile = BUILTIN_PROFILES.get(name)
    if profile is None:
        available = ", ".join(sorted(BUILTIN_PROFILES))
        raise ValueError(f"unknown profile: {name!r}. Available: {available}")
    return profile


def list_profiles() -> list[str]:
    """Return sorted list of available profile names."""
    return sorted(BUILTIN_PROFILES)
