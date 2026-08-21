#!/usr/bin/env python3
"""Regression fixtures: authored-at timezone drift on two real 2026 ATO incidents.

`case_builder.summarize_author_temporal_complexity_history` computes a per-identity
timezone baseline and reports the current commit's drift from it. That signal
reaches the model through the verifier prompt. Until now nothing pinned it against
a real attack.

Two incidents, chosen because they fail in opposite directions:

  keyv / ChainDrop (2026-08-04)  -- maintainer identity jaredwray, five years of
  US Pacific commits, three payload commits at +0000. Drift +420.

  Injective (2026-07-08)         -- maintainer identity thomasRalee, habitual
  +0800, three payload commits at -0400. Drift -720. Datadog confirmed the raw
  offsets independently, so this one validates against an external source.

Together they pin that the detector keys on deviation from a per-identity
baseline, not on any hardcoded notion of a suspicious offset. That distinction is
load-bearing: keyv's attack offset is +0000, and legitimate release automation in
that same repository also commits at +0000. `benign_bot_control` is the commit
that separates them, and it is the fixture most likely to catch a naive
"UTC means CI means suspicious" rewrite.

The third thing pinned here is a defect, not a success. The history window ingests
the attacker's own earlier commits, so within a single burst the signal decays:
`first_seen` flips after commit 1 and mode support falls 20 -> 19 -> 18. Carried
far enough the mode itself flips and drift collapses to 0, inverting the detector.
Both incidents are far short of that (3 commits against a window of 20, which
needs 11), so the inversion is latent -- pinned so it fails loudly if the window
shrinks or a longer burst enters the corpus.

Two levels:

  Level 1 (default) -- deterministic, offline given a mirror, no API key, no cost.
  Recomputes the real detector over the real objects and asserts every pinned
  number. This is the regression guard.

  Level 2 (opt-in) -- SIFT_FIXTURE_LIVE=1 plus ANTHROPIC_API_KEY. Runs the full
  pipeline and asserts the timezone evidence actually reaches a finding.

Run:
    python tests/test_author_timezone_anomaly.py
    pytest tests/test_author_timezone_anomaly.py
    SIFT_FIXTURE_LIVE=1 python tests/test_author_timezone_anomaly.py

Objects come from a local mirror when one exists (see fixture_repos.py). The keyv
payload commits are already deleted from the default branch and survive upstream
only because GitHub still serves unreachable objects by full SHA.

WARNING: the keyv trees contain a live credential stealer wired to a `preinstall`
hook and to agent auto-run configs. This fixture reads commit metadata only. Never
check these trees out into a working directory and never point a package manager
or an editor at them.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).parent))

from fixture_repos import describe_source, ensure_commits  # noqa: E402

from sift.runtime.case_builder import (  # noqa: E402
    load_commit_header,
    summarize_author_temporal_complexity_history,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "author_timezone"
KEYV = json.loads((FIXTURE_DIR / "keyv_chaindrop_2026.json").read_text())
INJECTIVE = json.loads((FIXTURE_DIR / "injective_ato_2026.json").read_text())
DEFAULT_WINDOW = 20

# Position in the burst -> the role key holding that commit.
BURST_ORDER = ["malicious_1", "malicious_2", "malicious_3"]


def repo_for(fixture: dict) -> Path:
    shas = [c["sha"] for c in fixture["commits"].values()]
    shas += [c["parent_sha"] for c in fixture["commits"].values() if c.get("parent_sha")]
    return ensure_commits(fixture["repo"], shas)


def timezone_block(repo: Path, sha: str, *, window: int = DEFAULT_WINDOW) -> dict:
    """Run the real detector over a real object, exactly as case building does."""
    header = load_commit_header(repo, sha)
    parent = (header.get("parent_shas") or [""])[0]
    summary = summarize_author_temporal_complexity_history(
        repo,
        commit_payload=header,
        history_roots=[parent],
        observed_ref="refs/heads/main",
        default_branch_ref="refs/heads/main",
        repo_is_shallow=False,
        max_author_history_commits=window,
    )
    return (summary or {}).get("timezone") or {}


def check_role(fixture: dict, repo: Path, role: str) -> list[str]:
    """Assert every pinned field for one commit. Returns human-readable notes."""
    record = fixture["commits"][role]
    actual = timezone_block(repo, record["sha"])
    problems = []
    for field, expected in record["expected"].items():
        got = actual.get(field)
        if got != expected:
            problems.append(f"{field}: expected {expected!r}, got {got!r}")
    if problems:
        raise AssertionError(
            f"{fixture['fixture']}/{role} ({record['sha'][:12]}) drifted:\n        "
            + "\n        ".join(problems)
        )
    return [f"{role}={record['expected']['timezone_drift_from_prior_mode_minutes']}"]


def test_keyv_separates_attack_from_maintainer() -> None:
    """The three payload commits drift +420 from a Pacific baseline; the
    maintainer's own last clean commit drifts 0."""
    repo = repo_for(KEYV)
    for role in BURST_ORDER:
        check_role(KEYV, repo, role)
    check_role(KEYV, repo, "benign_human_control")

    mal = timezone_block(repo, KEYV["commits"]["malicious_1"]["sha"])
    ben = timezone_block(repo, KEYV["commits"]["benign_human_control"]["sha"])
    assert mal["timezone_drift_from_prior_mode_minutes"] == 420
    assert ben["timezone_drift_from_prior_mode_minutes"] == 0
    assert mal["timezone_first_seen"] is True, (
        "REGRESSION: the first payload commit no longer registers as a "
        "never-before-seen offset for this identity"
    )
    print(f"  ok  keyv: 3 payload commits drift +420 from mode -07:00 "
          f"(n={mal['prior_mode_timezone_count']}); last clean maintainer commit drifts 0 "
          f"[{describe_source(repo)}]")


def test_keyv_utc_alone_is_not_the_signal() -> None:
    """The load-bearing false positive. Legitimate release automation in this
    repo commits at +0000, the same offset as the attack. What separates them is
    drift against a per-identity baseline -- so a detector that treats UTC as
    inherently suspicious would flag the bot and fail here."""
    repo = repo_for(KEYV)
    bot = check_role(KEYV, repo, "benign_bot_control") and timezone_block(
        repo, KEYV["commits"]["benign_bot_control"]["sha"])
    mal = timezone_block(repo, KEYV["commits"]["malicious_1"]["sha"])

    assert bot["current_timezone_offset_minutes"] == mal["current_timezone_offset_minutes"] == 0, \
        "fixture premise broken: bot control and attack should share the +0000 offset"
    assert bot["timezone_drift_from_prior_mode_minutes"] == 0, (
        "REGRESSION: legitimate release automation at +0000 now shows nonzero drift; "
        "this is the dominant false-positive mode for a UTC-keyed detector"
    )
    assert mal["timezone_drift_from_prior_mode_minutes"] == 420

    # The agent-config commit is genuinely bot-authored with no baseline at all.
    unknown = timezone_block(repo, KEYV["commits"]["bot_config_commit"]["sha"])
    assert unknown["prior_mode_timezone_offset_minutes"] is None, \
        "an identity with no prior commits must yield an unknown mode"
    assert unknown["timezone_drift_from_prior_mode_minutes"] is None, (
        "REGRESSION: drift is being computed against an absent baseline; "
        "no-history must mean no claim, not a default of zero"
    )
    print("  ok  keyv: same +0000 offset, drift 0 for the bot and +420 for the attack; "
          "absent baseline yields no drift claim rather than a default")


def test_injective_matches_analyst_confirmed_offsets() -> None:
    """Datadog reported UTC-4 against a habitual +0800. The recovered objects
    carry exactly that, and the revert stays clean."""
    repo = repo_for(INJECTIVE)
    for role in BURST_ORDER:
        check_role(INJECTIVE, repo, role)
    check_role(INJECTIVE, repo, "benign_revert_control")

    mal = timezone_block(repo, INJECTIVE["commits"]["malicious_1"]["sha"])
    rev = timezone_block(repo, INJECTIVE["commits"]["benign_revert_control"]["sha"])
    assert mal["current_timezone_offset_minutes"] == -240, "attack should be UTC-4"
    assert mal["prior_mode_timezone_offset_minutes"] == 480, "baseline should be +0800"
    assert mal["timezone_drift_from_prior_mode_minutes"] == -720
    assert rev["timezone_drift_from_prior_mode_minutes"] == 0, (
        "REGRESSION: the maintainer's own remediation commit now shows drift; this is "
        "the remediation-misflag negative"
    )
    # Drift sign is opposite to keyv: the detector must not privilege UTC.
    keyv_repo = repo_for(KEYV)
    keyv_drift = timezone_block(
        keyv_repo, KEYV["commits"]["malicious_1"]["sha"]
    )["timezone_drift_from_prior_mode_minutes"]
    assert keyv_drift > 0 > mal["timezone_drift_from_prior_mode_minutes"], (
        "the two incidents should drift in opposite directions; if they agree in sign "
        "the suite no longer proves the detector is baseline-relative"
    )
    print(f"  ok  injective: attack -04:00 vs baseline +08:00 (drift -720, matches Datadog); "
          f"revert drifts 0 [{describe_source(repo)}]")


def test_burst_position_degrades_the_signal() -> None:
    """A defect, pinned deliberately. The history window ingests the attacker's
    own earlier commits, so evaluating a burst commit-by-commit is not
    independent: later commits in the same attack score strictly weaker."""
    for fixture in (KEYV, INJECTIVE):
        repo = repo_for(fixture)
        pinned = fixture["pinned_behavior"]["burst_decay"]
        prior_counts, supports, first_seens = [], [], []
        for role in BURST_ORDER:
            tz = timezone_block(repo, fixture["commits"][role]["sha"])
            prior_counts.append(tz["current_timezone_prior_count"])
            supports.append(tz["prior_mode_timezone_count"])
            first_seens.append(tz["timezone_first_seen"])

        assert prior_counts == pinned["prior_count_by_position"], (
            f"{fixture['fixture']}: burst decay changed, prior_count {prior_counts} "
            f"!= pinned {pinned['prior_count_by_position']}"
        )
        assert supports == pinned["mode_support_by_position"], (
            f"{fixture['fixture']}: mode support {supports} != pinned "
            f"{pinned['mode_support_by_position']}"
        )
        assert first_seens == pinned["first_seen_by_position"], (
            f"{fixture['fixture']}: first_seen {first_seens} != pinned "
            f"{pinned['first_seen_by_position']}"
        )
        assert prior_counts == sorted(prior_counts) and prior_counts[0] == 0, \
            "the first commit of a burst must be the one with a clean baseline"
        # The drift magnitude is what survives; that is why it is the usable signal.
        drifts = {timezone_block(repo, fixture["commits"][r]["sha"])
                  ["timezone_drift_from_prior_mode_minutes"] for r in BURST_ORDER}
        assert drifts == {pinned["drift_is_stable_minutes"]}, (
            f"{fixture['fixture']}: drift should be constant across the burst, got {drifts}"
        )
        print(f"  ok  {fixture['fixture']}: first_seen {first_seens}, mode support "
              f"{supports} -- signal decays with burst position, drift holds at "
              f"{pinned['drift_is_stable_minutes']}")


def test_inversion_threshold_is_not_reached() -> None:
    """Latent hazard. Once malicious commits exceed half the window the mode
    becomes the attacker's own offset and drift collapses to 0. Neither incident
    reaches it. Pinned so that shrinking the window, or adding a longer burst,
    fails here rather than silently producing a confident 'no anomaly'."""
    pinned = KEYV["pinned_behavior"]["inversion_threshold"]
    window = pinned["default_window"]
    burst = pinned["malicious_commits_in_incident"]
    needed = pinned["commits_needed_to_invert_at_default_window"]
    assert needed == window // 2 + 1, "inversion arithmetic drifted from the pinned model"
    assert burst < needed, "this incident now reaches the inversion threshold"

    # The mode must survive the whole burst at every plausible window size.
    for fixture in (KEYV, INJECTIVE):
        repo = repo_for(fixture)
        baseline = timezone_block(repo, fixture["commits"]["malicious_1"]["sha"])[
            "prior_mode_timezone_offset_minutes"]
        for w in (5, 10, 20, 50):
            for role in BURST_ORDER:
                tz = timezone_block(repo, fixture["commits"][role]["sha"], window=w)
                assert tz["prior_mode_timezone_offset_minutes"] == baseline, (
                    f"REGRESSION: {fixture['fixture']}/{role} at window={w} inverted -- mode "
                    f"is now {tz['prior_mode_timezone_offset_minutes']}, was {baseline}. The "
                    f"attacker's own commits have taken over the baseline."
                )
    print(f"  ok  inversion not reached: {burst} payload commits vs {needed} needed at "
          f"window {window}; mode holds at windows 5/10/20/50")


def test_live_analysis_surfaces_timezone_evidence() -> None:
    """Level 2, opt-in: the drift has to actually reach a finding, not just exist
    in the case dict."""
    if os.environ.get("SIFT_FIXTURE_LIVE") != "1":
        print("  skip  live analysis (set SIFT_FIXTURE_LIVE=1 and ANTHROPIC_API_KEY)")
        return
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise RuntimeError("SIFT_FIXTURE_LIVE=1 requires ANTHROPIC_API_KEY")

    from sift.runtime.analysis import analyze_commit

    repo = repo_for(INJECTIVE)
    sha = INJECTIVE["commits"]["malicious_1"]["sha"]
    result = analyze_commit(repo_path=repo, sha=sha)
    findings = getattr(result, "findings", None) or []
    assert findings, (
        "REGRESSION: no findings for a commit that adds credential-exfiltration "
        "telemetry from a never-before-seen timezone"
    )
    print(f"  ok  live analysis surfaced {len(findings)} finding(s) for {sha[:12]}")


def main() -> int:
    tests = [
        test_keyv_separates_attack_from_maintainer,
        test_keyv_utc_alone_is_not_the_signal,
        test_injective_matches_analyst_confirmed_offsets,
        test_burst_position_degrades_the_signal,
        test_inversion_threshold_is_not_reached,
        test_live_analysis_surfaces_timezone_evidence,
    ]
    failed = 0
    print("author_timezone_anomaly: does authored-at timezone drift separate "
          "maintainer-identity ATO from the maintainer?\n")
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
