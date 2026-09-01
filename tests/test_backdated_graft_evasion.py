#!/usr/bin/env python3
"""Regression fixtures: a 2026 campaign the behavioral detectors do NOT catch.

Every other incident pinned in this suite is one sift's history layer detects.
This one is the opposite, and it is here so the suite stops implying coverage
that does not exist.

Two repos from the UNK_DeadDrop / "deepfake_guard" campaign (Proofpoint
2026-06-08), captured live on 2026-09-01 before takedown, both carrying a
`curl -ks … | bash` loader on a `preinstall` hook pointed at buildwithknexus[.]xyz:

  madlabsinc/mevn-cli   -- loader grafted onto a genuine release commit on both
  master and develop, with the anchor's author timestamp, committer timestamp and
  subject line copied verbatim.

  nanxiaobei/hugo-paper -- owner-account compromise; the signed merge of PR #267
  replaced by an unsigned twin carrying a byte-identical loader.

What the detectors do with them:

  timezone drift    0/4 on mevn-cli, 0/2 on hugo-paper. The attacker reused each
                    maintainer's own UTC offset (+0530, +0800), so every payload
                    commit agrees with its baseline. keyv and Injective are caught
                    because the attacker's real offset leaked; nothing leaks here.

  identity flags    empty on mevn-cli. On hugo-paper the malicious twin raises
                    exactly the same three flags as the legitimate merge one commit
                    earlier -- both are GitHub-UI merges -- so the flags are noise,
                    not detection.

  GPG signature     separates the hugo-paper twin from what it replaced, cleanly
                    and offline. sift's runtime layer does not look at it.

What does survive is one signal per repo, and neither covers the other:

  parent-timestamp clone   fires on 4/4 mevn-cli payload commits with zero false
                           positives in 769 genuine ones; silent on hugo-paper.

  absent signature         separates the hugo-paper twin; not applicable to
                           mevn-cli, which is unsigned throughout.

Two levels:

  Level 1 (default) -- deterministic, offline given a mirror, no API key, no cost.
  Level 2 (opt-in)  -- SIFT_FIXTURE_LIVE=1 plus ANTHROPIC_API_KEY. Asserts that
  patch-content triage still reaches a finding when the behavioral layer is blind,
  which is the only thing standing between this campaign and a clean report.

Run:
    python tests/test_backdated_graft_evasion.py
    pytest tests/test_backdated_graft_evasion.py
    SIFT_FIXTURE_LIVE=1 python tests/test_backdated_graft_evasion.py

WARNING: these trees carry a live credential-stealer loader wired to a
`preinstall` hook. This fixture reads commit metadata and patches only. Never
check one out into a working directory and never point a package manager or an
editor at one.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).parent))

from fixture_repos import describe_source, ensure_commits  # noqa: E402

from sift.runtime.case_builder import (  # noqa: E402
    load_commit_header,
    summarize_author_identity_history,
    summarize_author_temporal_complexity_history,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "backdated_graft"
MEVN = json.loads((FIXTURE_DIR / "mevn_cli_2026.json").read_text())
HUGO = json.loads((FIXTURE_DIR / "hugo_paper_2026.json").read_text())
DEFAULT_WINDOW = 20
IOC = "buildwithknexus"


def repo_for(fixture: dict) -> Path:
    shas: list[str] = []
    for record in fixture["commits"].values():
        shas.append(record["sha"])
        if record.get("parent_sha"):
            shas.append(record["parent_sha"])
    repo = ensure_commits(fixture["repo"], shas)

    # Unlike the incident fixtures, these assertions are about a *baseline*, so
    # the objects alone are not enough -- a window of history behind them has to
    # be present. The upstream fallback in ensure_commits fetches at depth 2,
    # which satisfies every sha above and still leaves the baseline empty. Say so
    # plainly rather than failing later on a count that looks like a regression.
    anchor = next(iter(fixture["commits"].values()))["sha"]
    depth = len(git(repo, "rev-list", "--first-parent", f"--max-count={DEFAULT_WINDOW + 1}",
                    anchor).split())
    if depth <= DEFAULT_WINDOW:
        raise RuntimeError(
            f"{fixture['repo']} in {repo} has only {depth} commits of first-parent "
            f"history behind {anchor[:12]}; these fixtures need more than "
            f"{DEFAULT_WINDOW}. Deepen the mirror (git fetch --unshallow) -- a "
            f"depth-2 capture holds every pinned object and still yields no baseline."
        )
    return repo


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    return result.stdout


def blocks(fixture: dict, repo: Path, record: dict) -> tuple[dict, dict]:
    """Run the real detectors over a real object, as case building does."""
    header = load_commit_header(repo, record["sha"])
    parent = (header.get("parent_shas") or [""])[0]
    common = dict(
        commit_payload=header,
        history_roots=[parent],
        observed_ref=record["observed_ref"],
        default_branch_ref=fixture["default_branch_ref"],
        repo_is_shallow=False,
        max_author_history_commits=DEFAULT_WINDOW,
    )
    temporal = summarize_author_temporal_complexity_history(repo, **common) or {}
    identity = summarize_author_identity_history(repo, **common) or {}
    return temporal, identity


def clones_parent_timestamp(repo: Path, sha: str) -> bool:
    """Author time, committer time and subject all identical to the parent's."""
    fmt = "%aI%x00%cI%x00%s"
    own = git(repo, "show", "-s", f"--format={fmt}", sha).strip()
    parent = git(repo, "show", "-s", f"--format={fmt}", f"{sha}^").strip()
    return bool(own) and own == parent


def test_forged_offset_defeats_timezone_drift() -> None:
    """The evasion. Every payload commit agrees with its own baseline, because
    the attacker authored it with the maintainer's habitual offset."""
    checked = 0
    for fixture in (MEVN, HUGO):
        repo = repo_for(fixture)
        for role, record in fixture["commits"].items():
            expected = record.get("expected_timezone")
            if not expected:
                continue
            temporal, _ = blocks(fixture, repo, record)
            actual = temporal.get("timezone") or {}
            problems = [
                f"{field}: expected {value!r}, got {actual.get(field)!r}"
                for field, value in expected.items()
                if actual.get(field) != value
            ]
            if problems:
                raise AssertionError(
                    f"{fixture['fixture']}/{role} ({record['sha'][:12]}) drifted:\n        "
                    + "\n        ".join(problems)
                )
            if record["carries_loader"]:
                assert actual["timezone_drift_from_prior_mode_minutes"] == 0, (
                    "fixture premise broken: this incident is pinned BECAUSE the "
                    "timezone detector is blind to it"
                )
                assert actual["timezone_first_seen"] is False
                checked += 1
    assert checked == 4, f"expected 4 loader-carrying commits with pinned timezone, got {checked}"
    print(f"  ok  {checked} payload commits, all drift 0 and first_seen False -- "
          f"the forged offset defeats the timezone detector outright")


def test_identity_flags_do_not_discriminate() -> None:
    """mevn-cli raises nothing at all. hugo-paper raises three flags -- and so
    does the legitimate merge one commit earlier, so they separate nothing."""
    mevn_repo = repo_for(MEVN)
    for role in ("malicious_master_hook", "malicious_master_refine"):
        record = MEVN["commits"][role]
        _, identity = blocks(MEVN, mevn_repo, record)
        assert identity.get("identity_flags") == [], (
            f"REGRESSION: {role} now raises {identity.get('identity_flags')!r}. If a "
            f"real signal has been added this fixture should be updated deliberately, "
            f"not left asserting a miss that no longer happens."
        )

    hugo_repo = repo_for(HUGO)
    malicious = blocks(HUGO, hugo_repo, HUGO["commits"]["malicious_head"])[1]
    benign = blocks(HUGO, hugo_repo, HUGO["commits"]["benign_signed_parent"])[1]
    assert malicious.get("identity_flags") == benign.get("identity_flags"), (
        "REGRESSION: the malicious twin and the legitimate merge it replaced no longer "
        "raise identical identity flags. That would be an improvement, but it must be "
        "pinned deliberately -- this fixture exists to record that they were identical."
    )
    assert malicious.get("identity_flags"), "fixture premise broken: expected flags on both"
    print(f"  ok  mevn-cli raises no identity flags; hugo-paper raises "
          f"{len(malicious['identity_flags'])} that the legitimate parent raises too")


def test_parent_timestamp_clone_catches_mevn_cli_only() -> None:
    """The one signal that works on mevn-cli, and its limit.

    All four payload commits copy their anchor's author time, committer time and
    subject verbatim. No genuine commit on develop does. hugo-paper's attacker did
    not do this, so the signal is silent there -- one operator, two shapes."""
    mevn_repo = repo_for(MEVN)
    for role, record in MEVN["commits"].items():
        got = clones_parent_timestamp(mevn_repo, record["sha"])
        assert got == record["clones_parent_timestamp"], (
            f"{role} ({record['sha'][:12]}): expected clones_parent_timestamp="
            f"{record['clones_parent_timestamp']}, got {got}"
        )
    malicious = [r for r in MEVN["commits"].values() if r["carries_loader"]]
    assert all(r["clones_parent_timestamp"] for r in malicious), (
        "REGRESSION: a loader-carrying commit no longer clones its parent timestamp; "
        "the only signal that separates this graft from genuine history has weakened"
    )
    anchors = [r for r in MEVN["commits"].values() if not r["carries_loader"]]
    assert anchors and not any(r["clones_parent_timestamp"] for r in anchors), (
        "the genuine anchors must NOT trip the signal, or it separates nothing"
    )

    hugo_repo = repo_for(HUGO)
    for role, record in HUGO["commits"].items():
        got = clones_parent_timestamp(hugo_repo, record["sha"])
        assert got is False, f"hugo-paper/{role} unexpectedly clones its parent timestamp"
    print(f"  ok  parent-timestamp clone: {len(malicious)}/{len(malicious)} mevn-cli "
          f"payload commits, 0/{len(anchors)} anchors, 0 on hugo-paper "
          f"[{describe_source(mevn_repo)}]")


def test_signature_separates_the_hugo_paper_twin() -> None:
    """The signal for the repo the timestamp check misses -- and sift's blindness
    to it. Reading a signature as present/absent needs no key and no network."""
    repo = repo_for(HUGO)
    for role, record in HUGO["commits"].items():
        raw = git(repo, "cat-file", "commit", record["sha"])
        count = sum(1 for line in raw.splitlines() if line.startswith("gpgsig"))
        assert count == record["gpgsig_header_count"], (
            f"hugo-paper/{role}: expected {record['gpgsig_header_count']} gpgsig "
            f"header(s), got {count}"
        )
    malicious = HUGO["commits"]["malicious_head"]["gpgsig_header_count"]
    benign = HUGO["commits"]["benign_signed_parent"]["gpgsig_header_count"]
    assert malicious == 0 and benign == 1, "fixture premise broken"

    # The blindness itself: no signature field reaches the case blocks.
    temporal, identity = blocks(HUGO, repo, HUGO["commits"]["malicious_head"])
    surfaced = [
        key for key in list(temporal) + list(identity)
        if "sig" in key.lower() or "gpg" in key.lower()
    ]
    assert not surfaced, (
        f"signature state now reaches the case as {surfaced!r}. That is the fix this "
        f"fixture argues for -- update the fixture to assert detection instead of "
        f"blindness."
    )
    print("  ok  unsigned twin vs signed parent (0 vs 1 gpgsig); no signature field "
          "reaches the case blocks")


def test_merge_base_baseline_is_clean() -> None:
    """Acceptance test for the off-default-branch baseline.

    mevn-cli's loader sits on master while the default branch is develop. The
    baseline must come from the merge-base -- the genuine anchor -- and not from
    the grafted branch, which the attacker force-pushed and therefore controls."""
    repo = repo_for(MEVN)
    for role in ("malicious_master_hook", "malicious_master_refine"):
        record = MEVN["commits"][role]
        temporal, _ = blocks(MEVN, repo, record)
        expected = record["expected_baseline"]
        assert temporal, (
            "REGRESSION: the temporal block is empty again for a commit off the "
            "default branch. An empty block removes every author baseline from the "
            "prompt with no caveat; it should degrade, not vanish."
        )
        for field, value in expected.items():
            assert temporal.get(field) == value, (
                f"{role}: {field} expected {value!r}, got {temporal.get(field)!r}"
            )
        assert temporal["baseline_root_sha"] == MEVN["commits"]["benign_master_anchor"]["sha"], (
            "the baseline must be the genuine anchor reachable from the default branch"
        )
        assert temporal["author_prior_commits_default_branch"] == DEFAULT_WINDOW, (
            "the recovered baseline should be a full window of genuine history"
        )
        caveats = temporal.get("history_caveats") or []
        assert "baseline_taken_at_merge_base_with_default_branch" in caveats
        assert "observed_ref_differs_from_default_branch" in caveats
    print("  ok  master graft baselines at the genuine merge-base anchor "
          "(20 commits), caveated as off-default")


def test_loader_is_present_in_every_payload_commit() -> None:
    """Fixture integrity: if upstream reaps or rewrites these objects, fail loudly
    rather than quietly asserting detector behavior about the wrong tree."""
    for fixture in (MEVN, HUGO):
        repo = repo_for(fixture)
        for role, record in fixture["commits"].items():
            patch = git(repo, "show", "--format=", record["sha"])
            hit = IOC in patch.lower()
            if record["carries_loader"]:
                assert hit, (
                    f"{fixture['fixture']}/{role} ({record['sha'][:12]}) no longer "
                    f"contains the loader IOC; the object may have been rewritten"
                )
            else:
                assert not hit, (
                    f"{fixture['fixture']}/{role} is pinned as a benign anchor but "
                    f"contains the loader IOC"
                )
    print("  ok  loader present in every payload commit, absent from every anchor")


def test_live_analysis_still_finds_the_loader() -> None:
    """Level 2, opt-in. With the behavioral layer blind, patch-content triage is
    the only thing left. If it misses, this campaign reports clean."""
    if os.environ.get("SIFT_FIXTURE_LIVE") != "1":
        print("  skip  live analysis (set SIFT_FIXTURE_LIVE=1 and ANTHROPIC_API_KEY)")
        return
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise RuntimeError("SIFT_FIXTURE_LIVE=1 requires ANTHROPIC_API_KEY")

    from sift.runtime.analysis import analyze_commit

    repo = repo_for(MEVN)
    record = MEVN["commits"]["malicious_master_hook"]
    result = analyze_commit(
        repo_path=repo,
        sha=record["sha"],
        ref=record["observed_ref"],
        default_branch_ref=MEVN["default_branch_ref"],
    )
    findings = (result or {}).get("findings") or []
    assert findings, (
        "REGRESSION: no findings for a commit adding a curl|bash preinstall hook. "
        "The behavioral evidence is blind to this incident, so patch-content triage "
        "is the whole defense."
    )
    print(f"  ok  live analysis surfaced {len(findings)} finding(s) for {record['sha'][:12]}")


def main() -> int:
    tests = [
        test_forged_offset_defeats_timezone_drift,
        test_identity_flags_do_not_discriminate,
        test_parent_timestamp_clone_catches_mevn_cli_only,
        test_signature_separates_the_hugo_paper_twin,
        test_merge_base_baseline_is_clean,
        test_loader_is_present_in_every_payload_commit,
        test_live_analysis_still_finds_the_loader,
    ]
    failed = 0
    print("backdated_graft_evasion: what does the history layer do with a campaign "
          "that forges its timestamps?\n")
    for test in tests:
        try:
            test()
        except AssertionError as exc:
            failed += 1
            print(f"  FAIL  {test.__name__}\n        {exc}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"  ERROR {test.__name__}: {type(exc).__name__}: {exc}")
    print()
    print("FAILED" if failed else "PASSED")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
