#!/usr/bin/env python3
"""Does the domain-provenance prior actually change the model's judgement?

The prior's whole justification is the delta: a `DomainVerdict` is not a finding,
and shipping it as a standalone comment is how a check gets muted. It earns its
place only if the triage model reaches a different conclusion when the evidence is
present. Asserting that it is *wired in* proves nothing about whether it helps, so
this fixture measures the A/B directly.

Two levels:

  Level 1 (default) -- deterministic, offline, free. Pins the wiring: the evidence
  ref is declared, the prompt carries the interpretation rules, the render path
  emits the block, and absent / unavailable / declined stay distinguishable from
  clean.

  Level 2 (opt-in) -- SIFT_FIXTURE_LIVE=1 plus ANTHROPIC_API_KEY. Runs the real
  primary-triage model twice over the same synthetic commit, once with the
  provenance evidence and once without, and reports whether the classification or
  severity moved. Costs money.

Run:
    python tests/test_domain_provenance_prior.py
    SIFT_FIXTURE_LIVE=1 python tests/test_domain_provenance_prior.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PROVENANCE_REF = "history_before_commit.author_identity_history.domain_provenance"

# A commit worth taking an account over: it changes the release workflow. The
# prior should matter here and not on a docs typo.
SENSITIVE_COMMIT = {
    "sha": "0" * 40,
    "message": "ci: use a mirror for the publish step",
    "author_name": "Long-Standing Maintainer",
    "author_email": "maintainer@atlantis-software.net",
    "committer_name": "Long-Standing Maintainer",
    "committer_email": "maintainer@atlantis-software.net",
    "files_changed": [
        {
            "path": ".github/workflows/publish.yml",
            "added_lines": 4,
            "deleted_lines": 2,
        }
    ],
    "stats": {"files_changed": 1, "insertions": 4, "deletions": 2},
    "patch_excerpt": (
        "diff --git a/.github/workflows/publish.yml b/.github/workflows/publish.yml\n"
        "@@ -18,7 +18,9 @@ jobs:\n"
        "-      - run: npm publish --provenance\n"
        "+      - run: npm config set registry https://registry.npm.internal.example\n"
        "+      - run: npm publish\n"
    ),
}

CRITICAL_PROVENANCE = {
    "role": "supporting",
    "status": "CRITICAL",
    "confidence": "medium",
    "domain": "atlantis-software.net",
    "registration_began_at": "2026-05-07",
    "days_since_registration": 7,
    "identity_first_used_domain_at": "2013-06-01",
    "anchor_kind": "gpg_uid",
    "anchor_strength": "strong",
    "activity_across_gap": "dormant",
    "commits_across_gap": 0,
    "same_signing_key_across_gap": False,
    "gap_activity_scope": "repo_local",
    "corroborated_by": [],
    "reasons": [
        "current registration began 2026-05-07 (7 days ago), but this identity was "
        "already using the domain on 2013-06-01 per gpg_uid",
        "identity was dormant across the ownership gap and resumed afterwards; this "
        "is the account-takeover shape",
    ],
    "is_counter_evidence": False,
    "prospective_notes_withheld": 0,
}

COUNTER_PROVENANCE = {
    "role": "counter",
    "status": "CLEAN",
    "confidence": "high",
    "domain": "atlantis-software.net",
    "registration_began_at": "2009-02-14",
    "days_since_registration": 6400,
    "identity_first_used_domain_at": "2013-06-01",
    "anchor_kind": "gpg_uid",
    "anchor_strength": "strong",
    "activity_across_gap": "",
    "commits_across_gap": None,
    "same_signing_key_across_gap": None,
    "gap_activity_scope": "",
    "corroborated_by": [],
    "reasons": [
        "registered 2009-02-14, continuously held since before this identity first "
        "used it (2013-06-01)"
    ],
    "is_counter_evidence": True,
    "prospective_notes_withheld": 0,
}


def _case(provenance: dict | None) -> dict:
    identity_history: dict = {
        "history_source": "synthetic-fixture",
        "baseline_ref": "refs/heads/main",
        "current_author": {
            "normalized_name": SENSITIVE_COMMIT["author_name"].casefold(),
            "normalized_email": SENSITIVE_COMMIT["author_email"],
            "email_domain": "atlantis-software.net",
            "email_is_noreply": False,
            "looks_bot_like": False,
        },
        "author_seen_before_exact": True,
        "author_prior_exact_identity_commits": 214,
        "author_email_variants": [
            {
                "email": SENSITIVE_COMMIT["author_email"],
                "email_domain": "atlantis-software.net",
                "commit_count": 214,
                "first_seen_at": "2013-06-01T00:00:00Z",
                "previous_seen_at": "2024-11-02T00:00:00Z",
            }
        ],
    }
    if provenance is not None:
        identity_history["domain_provenance"] = provenance
    return {
        "case_id": "domain-provenance-prior-fixture",
        "repo": "example-org/example-lib",
        "commit_sha": SENSITIVE_COMMIT["sha"],
        "commit": SENSITIVE_COMMIT,
        "history_before_commit": {
            "repo_commit_count_before": 4120,
            "author_prior_commits_same_email": 214,
            "author_prior_commits_same_name": 214,
            "author_first_seen_same_email_at": "2013-06-01T00:00:00Z",
            "author_previous_commit_same_email_at": "2024-11-02T00:00:00Z",
            "author_identity_history": identity_history,
        },
        "history_scope": {"mode": "full"},
    }


# -- level 1 -------------------------------------------------------------------


def test_evidence_ref_is_declared() -> None:
    from sift.runtime.primary import build_primary_findings_prompt

    prompt = build_primary_findings_prompt({"commit": {}}, exclude_evidence=True)
    assert PROVENANCE_REF in prompt, (
        "the provenance evidence ref must be listed in allowed_refs, or findings "
        "cannot cite it"
    )
    print("  ok  evidence ref declared in the primary prompt")


def test_prompt_reconciles_the_takeover_guardrail() -> None:
    """The older rule forbids inferring takeover; this evidence licenses it.

    Without an explicit exception the two instructions conflict, and the model will
    most likely obey the older, more specific prohibition -- a silent no-op rather
    than a visible failure.
    """
    from sift.runtime.primary import build_primary_findings_prompt

    prompt = build_primary_findings_prompt({"commit": {}}, exclude_evidence=True)
    assert "Do not infer role changes, account takeover" in prompt, (
        "the original guardrail should still be present"
    )
    assert "one exception to the rule" in prompt, (
        "the provenance rule must explicitly name itself as the exception to the "
        "no-takeover-inference guardrail"
    )
    for word in ("supporting", "counter", "unavailable", "declined"):
        assert word in prompt, f"prompt must explain the {word!r} evidence role"
    print("  ok  prompt reconciles the no-takeover-inference guardrail")


def test_render_distinguishes_four_states() -> None:
    """absent / unavailable / declined / clean must not collapse into each other."""
    from sift.runtime.case_builder import render_domain_provenance_lines

    absent = render_domain_provenance_lines({})
    assert absent == [], f"absent must render nothing, got {absent}"

    for role, status in (("unavailable", "lookup_error"), ("declined", "no_measurable_domain")):
        rendered = "\n".join(
            render_domain_provenance_lines(
                {"domain_provenance": {"role": role, "status": status, "detail": "x"}}
            )
        )
        assert "NOT a clean result" in rendered, (
            f"role={role} must be explicitly marked as not clean; got:\n{rendered}"
        )

    counter = "\n".join(
        render_domain_provenance_lines({"domain_provenance": COUNTER_PROVENANCE})
    )
    assert "counter-evidence" in counter, (
        "a clean result must be presented as usable counter-evidence"
    )

    supporting = "\n".join(
        render_domain_provenance_lines({"domain_provenance": CRITICAL_PROVENANCE})
    )
    assert "CRITICAL" in supporting and "dormant" in supporting
    print("  ok  absent / unavailable / declined / counter / supporting all distinct")


def test_evidence_block_carries_the_prior() -> None:
    from sift.runtime.verifier import render_verifier_evidence

    with_prior = render_verifier_evidence(_case(CRITICAL_PROVENANCE))
    without = render_verifier_evidence(_case(None))
    assert "Author Email Domain Provenance" in with_prior, (
        "the rendered evidence the model actually reads must include the block"
    )
    assert "Author Email Domain Provenance" not in without
    assert "dormant" in with_prior
    print(
        f"  ok  evidence block grows by {len(with_prior) - len(without)} chars when the "
        f"prior is present"
    )


def test_disabled_by_default() -> None:
    """The only network-touching part of case building must be opt-in."""
    from sift.runtime.case_builder import (
        DOMAIN_PROVENANCE_ENV,
        build_domain_provenance_evidence,
    )

    saved = os.environ.pop(DOMAIN_PROVENANCE_ENV, None)
    try:
        result = build_domain_provenance_evidence(
            ROOT,
            commit_payload={"author_email": "someone@example-corp.net"},
            author_identity_history={},
        )
        assert result is None, (
            f"provenance must be off unless {DOMAIN_PROVENANCE_ENV}=1; got {result!r}"
        )
    finally:
        if saved is not None:
            os.environ[DOMAIN_PROVENANCE_ENV] = saved
    print(f"  ok  off unless {DOMAIN_PROVENANCE_ENV}=1")


# -- level 2 -------------------------------------------------------------------


def test_live_prior_changes_the_judgement() -> None:
    """Run the real model twice and report whether the prior moved the outcome."""
    if os.environ.get("SIFT_FIXTURE_LIVE") != "1":
        print("  skip  live A/B (set SIFT_FIXTURE_LIVE=1 and ANTHROPIC_API_KEY)")
        return
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise RuntimeError("SIFT_FIXTURE_LIVE=1 requires ANTHROPIC_API_KEY")

    from sift.runtime.verifier import render_verifier_evidence
    from sift.runtime.primary import (
        build_primary_findings_prompt,
        parse_primary_findings_response,
    )
    from sift.runtime.providers import ANTHROPIC_DEFAULT_MODEL, run_text_prompt

    model = os.environ.get("SIFT_TEST_MODEL", ANTHROPIC_DEFAULT_MODEL)

    outcomes: dict[str, dict] = {}
    for label, provenance in (("without_prior", None), ("with_prior", CRITICAL_PROVENANCE)):
        case = _case(provenance)
        prompt = build_primary_findings_prompt(
            case, evidence_block=render_verifier_evidence(case)
        )
        response = run_text_prompt(
            prompt,
            "anthropic",
            ollama_model="",
            ollama_ssh_target="",
            ollama_timeout_sec=60,
            anthropic_model=model,
            anthropic_api_key=os.environ["ANTHROPIC_API_KEY"],
            anthropic_effort=os.environ.get("SIFT_TEST_EFFORT", "medium"),
            max_tokens=2048,
        )
        assert response.get("ok"), f"{label}: model call failed: {response.get('error')}"
        text = response.get("text") or response.get("raw_response") or ""
        parsed = parse_primary_findings_response(case, text)
        findings = parsed.get("findings") or []
        severities = [str(f.get("severity", "")) for f in findings]
        outcomes[label] = {
            "classification": parsed.get("classification"),
            "findings": len(findings),
            "severities": severities,
            "cites_provenance": any(
                PROVENANCE_REF in (f.get("evidence_refs") or []) for f in findings
            ),
        }
        print(
            f"        {label}: classification={outcomes[label]['classification']} "
            f"findings={outcomes[label]['findings']} severities={severities} "
            f"cites_provenance={outcomes[label]['cites_provenance']}"
        )

    with_prior = outcomes["with_prior"]
    without = outcomes["without_prior"]

    assert with_prior["cites_provenance"], (
        "with the prior present and a CRITICAL discontinuity on a commit that "
        "rewrites the publish registry, at least one finding should cite "
        f"{PROVENANCE_REF}. It did not, so the evidence is reaching the model but "
        "not being used."
    )

    rank = {"": 0, "low": 1, "medium": 2, "high": 3}
    worst_with = max((rank.get(s, 0) for s in with_prior["severities"]), default=0)
    worst_without = max((rank.get(s, 0) for s in without["severities"]), default=0)
    moved = (
        with_prior["classification"] != without["classification"]
        or worst_with > worst_without
        or with_prior["findings"] > without["findings"]
    )
    assert moved, (
        "the prior did not change the outcome: "
        f"{without} vs {with_prior}. If this holds across models, the prior is not "
        "earning its place in the case."
    )
    print("  ok  the prior changed the model's judgement")


def main() -> int:
    tests = [
        test_evidence_ref_is_declared,
        test_prompt_reconciles_the_takeover_guardrail,
        test_render_distinguishes_four_states,
        test_evidence_block_carries_the_prior,
        test_disabled_by_default,
        test_live_prior_changes_the_judgement,
    ]
    try:
        import httpx  # noqa: F401
    except ImportError:
        # Level 1 here needs no extra: it only touches runtime rendering. Kept as a
        # note rather than a skip, since these tests must run on a base install.
        pass

    failed = 0
    print("domain-provenance prior: does the evidence change the model's judgement?\n")
    for t in tests:
        try:
            t()
        except AssertionError as e:
            failed += 1
            print(f"  FAIL  {t.__name__}\n        {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  ERROR {t.__name__}: {type(e).__name__}: {e}")
    print()
    print("FAILED" if failed else "PASSED")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
