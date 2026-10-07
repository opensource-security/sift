#!/usr/bin/env python3
"""Regression fixture: email-domain enrichment evidence (megalodon 2026 / ctx / xz).

Pins the deterministic email-domain classification that separated the 2026
megalodon forged-bot commits from genuine platform bots (measured margin
-1 -> +1 on the 2026 incident corpus), plus the two shapes that
must stay correct as the module evolves:

  - ctx-class domain resurrection: RDAP creation date resets on
    re-registration, so registered_at > author-first-seen is the tell.
  - xz-class freemail null: a freemail identity must produce NO domain
    signal -- the correct output is silence, deferring to behavioral signals.

Everything here is level 1: deterministic, offline, no API key, no cost.
The pre-cutoff incidents (xz) are usable precisely because these assertions
are deterministic -- LLM-judge contamination does not apply.

Run:
    python tests/test_email_domain_enrichment.py
    pytest tests/test_email_domain_enrichment.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sift.runtime.case_builder import build_realtime_case  # noqa: E402
from sift.runtime.email_domain import (  # noqa: E402
    build_email_domain_context,
    render_email_domain_evidence,
)

FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "email_domain_enrichment_2026.json").read_text()
)
SNAPSHOT = FIXTURE["snapshot"]
ANCHOR = FIXTURE["anchor_timestamp_utc"]


def _context(identity_key: str, mode: str = "retrospective", **history_extra):
    identity = FIXTURE["identities"][identity_key]
    commit = {
        "author_name": identity["author_name"],
        "author_email": identity["author_email"],
        "committer_name": identity["author_name"],
        "committer_email": identity["author_email"],
    }
    history = {"anchor_timestamp_utc": ANCHOR, **history_extra}
    return build_email_domain_context(commit, history, SNAPSHOT, mode)


def test_megalodon_forged_bots_flagged() -> None:
    for key, domain in (("megalodon_tiledesk", "noreply.dev"), ("megalodon_wiznet", "automated.dev")):
        author = _context(key)["author"]
        assert author["email_domain"] == domain
        assert author["domain_classification"] == "custom"
        assert author["bot_identity_on_nonplatform_domain"] is True, key
        assert author["domain_registered"] is True


def test_genuine_identities_stay_silent() -> None:
    for key, expected_class in (
        ("bufferzone", "github_infra"),
        ("real_dependabot", "github_infra"),
        ("xz_jia_tan", "freemail"),
        ("benign_human_custom", "custom"),
    ):
        author = _context(key)["author"]
        assert author["domain_classification"] == expected_class, key
        assert author["bot_identity_on_nonplatform_domain"] is False, key


def test_xz_freemail_produces_no_domain_intel() -> None:
    author = _context("xz_jia_tan")["author"]
    assert author["bot_shaped_identity"] is False
    for field in ("domain_registered", "domain_registered_at", "domain_age_at_commit_days", "mx_present"):
        assert author[field] is None, field


def test_temporal_gate_on_dns_state() -> None:
    retro = _context("megalodon_tiledesk", mode="retrospective")["author"]
    realtime = _context("megalodon_tiledesk", mode="realtime")["author"]
    assert retro["mx_present"] is False  # noreply.dev cannot receive mail
    assert realtime["mx_present"] is None  # post-anchor observation: realtime-hidden
    assert realtime["domain_registered_at"] == retro["domain_registered_at"]  # historical fact: both modes
    expected_age = FIXTURE["pinned_behavior"]["noreply_dev_age_days_at_anchor"]
    assert abs(realtime["domain_age_at_commit_days"] - expected_age) < 1.0


def test_ctx_style_resurrection_detected_in_realtime() -> None:
    synthetic = FIXTURE["synthetic_resurrection"]
    intel = {
        "observed_at": SNAPSHOT["observed_at"],
        "domains": {"resurrected.example": synthetic["domain_entry"]},
    }
    commit = {
        "author_name": synthetic["author_name"],
        "author_email": synthetic["author_email"],
        "committer_name": synthetic["author_name"],
        "committer_email": synthetic["author_email"],
    }
    history = {
        "anchor_timestamp_utc": "2026-07-01T00:00:00Z",
        "author_first_seen_same_email_at": synthetic["author_first_seen_same_email_at"],
    }
    author = build_email_domain_context(commit, history, intel, "realtime")["author"]
    assert author["domain_registered_after_author_first_seen"] is True
    rendered = render_email_domain_evidence(build_email_domain_context(commit, history, intel, "realtime"))
    assert "domain resurrection" in rendered


def test_v2_snapshot_band_passthrough() -> None:
    """v2 snapshots (provenance-written) carry registrable_domain + band; the
    stdlib reader passes them through and renders them, in both modes."""
    synthetic = FIXTURE["synthetic_resurrection"]
    entry = dict(synthetic["domain_entry"])
    entry["registrable_domain"] = "resurrected.example"
    entry["provenance"] = {
        "band": "LIKELY",
        "confidence": "medium",
        "role": "supporting",
        "used_since": "2021-03-01T00:00:00Z",
        "used_anchor_kind": "commit_author_date",
        "held_since": "2026-06-01T00:00:00Z",
        "gap_verdict": "dormant",
        "assessed_at": "2026-08-21T12:00:00Z",
    }
    intel = {"snapshot_version": "email_domain_intel_v2", "observed_at": "2026-08-21T12:00:00Z",
             "writer": "provenance", "domains": {"resurrected.example": entry}}
    commit = {"author_name": synthetic["author_name"], "author_email": synthetic["author_email"],
              "committer_name": synthetic["author_name"], "committer_email": synthetic["author_email"]}
    history = {"anchor_timestamp_utc": "2026-07-01T00:00:00Z",
               "author_first_seen_same_email_at": synthetic["author_first_seen_same_email_at"]}
    for mode in ("retrospective", "realtime"):
        context = build_email_domain_context(commit, history, intel, mode)
        author = context["author"]
        assert author["registrable_domain"] == "resurrected.example"
        assert author["provenance_band"] == "LIKELY", mode
        assert author["provenance_gap_verdict"] == "dormant"
        rendered = render_email_domain_evidence(context)
        assert "provenance verdict: LIKELY" in rendered, mode
        assert "gap dormant" in rendered


def test_render_realtime_omits_dns_lines() -> None:
    retro = render_email_domain_evidence(_context("megalodon_tiledesk", mode="retrospective"))
    realtime = render_email_domain_evidence(_context("megalodon_tiledesk", mode="realtime"))
    assert "NON-platform domain" in retro and "NON-platform domain" in realtime
    assert "MX present: False" in retro
    assert "MX present" not in realtime


def _git(repo: Path, *args: str, author: tuple[str, str] | None = None) -> None:
    cmd = ["git", "-C", str(repo)]
    if author:
        cmd += ["-c", f"user.name={author[0]}", "-c", f"user.email={author[1]}"]
    subprocess.run(cmd + list(args), check=True, capture_output=True)


def test_realtime_case_builder_wiring() -> None:
    """End-to-end: build_realtime_case attaches the block and prompt section."""
    forged = FIXTURE["identities"]["megalodon_tiledesk"]
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp) / "repo"
        repo.mkdir()
        _git(repo, "init", "-q", "-b", "main")
        (repo / "app.py").write_text("print('ok')\n")
        _git(repo, "add", "."); _git(repo, "commit", "-q", "-m", "init", author=("Maintainer", "m@tiledesk.com"))
        (repo / "ci.yml").write_text("run: echo hi\n")
        _git(repo, "add", ".")
        _git(repo, "commit", "-q", "-m", "ci: add build optimization step",
             author=(forged["author_name"], forged["author_email"]))
        sha = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
        ).stdout.strip()
        case = build_realtime_case(
            repo, sha, "refs/heads/main", "2026-05-18T13:00:00Z",
            repo="fixture/forged-bot", email_domain_intel=SNAPSHOT,
        )
    context = case["email_domain_context"]
    assert case["feature_availability"]["email_domain_intel"] is True
    assert context["author"]["bot_identity_on_nonplatform_domain"] is True
    assert context["author"]["mx_present"] is None  # realtime builder: DNS state hidden
    assert "EMAIL DOMAIN EVIDENCE" in case["agent_prompt"]
    assert "NON-platform domain" in case["agent_prompt"]


def main() -> int:
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}: {exc}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
