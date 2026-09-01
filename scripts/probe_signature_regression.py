#!/usr/bin/env python3
"""Measurement probe: does a class-conditioned signature-verification baseline
flag owner-ATO force-pushes as anomalies?

This is a MEASUREMENT ONLY. It touches nothing in sift/runtime and wires nothing
into the product. It reads commit metadata from the pinned bare mirrors with
plain git -- no keyring, no GitHub API, no network. The signal is structural:
a commit either carries a gpgsig header (%G? != N) or it does not.

The hypothesis (see the plan in the 2026-09-01 session): the useful signal is
not "unsigned = bad" but "unsigned where this repo's commits of the same CLASS
are normally signed", scored against the commit's own preceding history so an
attacker's burst cannot reset the baseline. GitHub auto-signs web-flow merges,
so the discriminating class is the PR-merge; direct pushes are frequently
unsigned and must not fire.

Run:  python scripts/probe_signature_regression.py \
          --out .runartifacts/calibration-2026-09-01/signature_regression
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict, deque
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tests.fixture_repos import mirror_candidates  # noqa: E402
from sift.runtime.case_builder import normalize_identity_email  # noqa: E402

MIN_SUPPORT = 5  # need this many prior same-class commits before a class can score
PR_MERGE_RE = re.compile(r"^Merge pull request #\d+", re.IGNORECASE)
NUL = "\x00"

# Each repo lists the scan tips whose ancestry to walk (a ref or a bare sha) and
# the malicious commits to mark. A tip given as a sha lets us score commits that
# are unreachable from any branch (reaped after disclosure) via their own history.
CORPUS = [
    {
        "repo": "nanxiaobei/hugo-paper",
        "tips": ["refs/remotes/gh/main",
                 "c26b0568c89264413375c3c58f36ac2a9a779d9e"],  # pre-rewrite twin, off-branch
        "malicious": {
            "a68d2c9b2ad9d857b09dcb30a578ac1de6487061": "owner-ATO unsigned twin of PR #267 merge",
            "c26b0568c89264413375c3c58f36ac2a9a779d9e": "owner-ATO twin (pre-rewrite object)",
        },
    },
    {
        "repo": "jaredwray/keyv",
        "tips": ["refs/heads/main",
                 "ee2681a9b62f3637b0eb5133c36c864d3376cc5b",
                 "d8c850c7800e514d582741a1f852b61122c31213",
                 "f97eabcdd057105f1fce3f05d6c029dac3f2ac78"],
        "malicious": {
            "ee2681a9b62f3637b0eb5133c36c864d3376cc5b": "ChainDrop payload",
            "d8c850c7800e514d582741a1f852b61122c31213": "ChainDrop payload (stayed signed)",
            "f97eabcdd057105f1fce3f05d6c029dac3f2ac78": "ChainDrop payload",
        },
    },
    {
        "repo": "InjectiveLabs/injective-ts",
        "tips": ["refs/heads/master",
                 "5486f13e799d9c90095c5f581a04ad867d768f66",
                 "01219285b16ce85c70cdf47a71a551ff5e41f1ed"],
        "malicious": {
            "5486f13e799d9c90095c5f581a04ad867d768f66": "Injective ATO payload",
            "01219285b16ce85c70cdf47a71a551ff5e41f1ed": "Injective ATO payload",
        },
    },
    {
        "repo": "madlabsinc/mevn-cli",
        "tips": ["refs/remotes/gh/master"],
        "malicious": {
            "3a30d0d7ca9f877fb1be33929a8a34f887fe5702": "deepfake-guard graft (hook wiring)",
            "ceb455875c320a764fa6ac102674f161509d3394": "deepfake-guard graft (loader refine)",
        },
    },
    {
        "repo": "DaviRain-Su/pz",
        "tips": ["refs/remotes/gh/zig-implementation"],
        "malicious": {
            "9324422aad16fcdea671c46582ac8c41dfd2c8f0": "deepfake-guard trap in upstream-sync merge",
        },
    },
]


def resolve_mirror(repo_slug: str) -> Path:
    for cand in mirror_candidates(repo_slug):
        if cand.exists() and (cand / "HEAD").exists():
            return cand
    raise SystemExit(f"no mirror found for {repo_slug} (looked in upstream-mirrors / $SIFT_FIXTURE_MIRRORS)")


def walk(mirror: Path, tip: str):
    """Yield commits reachable from `tip`, oldest first (--reverse)."""
    fmt = "%x00".join(["%H", "%P", "%G?", "%an", "%ae", "%s"])
    proc = subprocess.run(
        ["git", "-C", str(mirror), "log", "--reverse", f"--format={fmt}", tip],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(f"  skip tip {tip[:16]}: {proc.stderr.strip().splitlines()[-1:]}\n")
        return
    for line in proc.stdout.split("\n"):
        if not line:
            continue
        h, parents, g, an, ae, subj = (line.split(NUL) + [""] * 6)[:6]
        parent_list = parents.split() if parents else []
        pr_subject = bool(PR_MERGE_RE.match(subj))
        yield {
            "sha": h,
            "signed": g != "N",           # gpgsig header present (any validity code but N)
            "gpg_code": g,
            "n_parents": len(parent_list),
            "pr_subject": pr_subject,
            # a commit that presents as a web-flow PR merge but is not a real 2-parent
            # merge -- a forged-merge structure, tell on its own, needs no signing baseline
            "forged_merge_shape": pr_subject and len(parent_list) < 2,
            "identity": normalize_identity_email(ae) or an.strip().lower(),
            "author": an,
            "subject": subj,
        }


def commit_class(c: dict) -> str:
    # Reference group is what the commit PRESENTS as: GitHub auto-signs web-flow PR
    # merges, so any commit with that subject is judged against the PR-merge baseline,
    # regardless of parent count -- an unsigned single-parent impostor then scores
    # against a class that is ~always signed, instead of hiding in the direct class.
    return "pr_merge" if c["pr_subject"] else "direct"


def score_repo(entry: dict, window: int) -> dict:
    mirror = resolve_mirror(entry["repo"])
    malicious = entry["malicious"]
    maxlen = window if window > 0 else None  # 0 => unbounded (cumulative-since-start)

    scored: dict[str, dict] = {}     # sha -> record (first scoring wins; baseline is deterministic per sha)
    class_totals: dict[str, list[int]] = {}  # overall (for the baseline-regime summary)

    for tip in entry["tips"]:
        # trailing window of signed/unsigned per class and per (class,identity), BEFORE current commit
        cls_win: dict[str, deque] = defaultdict(lambda: deque(maxlen=maxlen))
        id_win: dict[tuple, deque] = defaultdict(lambda: deque(maxlen=maxlen))

        for c in walk(mirror, tip):
            cls = commit_class(c)
            key = (cls, c["identity"])
            cwin, iwin = cls_win[cls], id_win[key]
            support = len(cwin)
            rate = (sum(cwin) / support) if support else None
            id_support = len(iwin)
            id_rate = (sum(iwin) / id_support) if id_support else None

            # directional class-conditioned score: unsigned where the class is normally signed
            if (not c["signed"]) and support >= MIN_SUPPORT:
                score = rate
            else:
                score = 0.0

            if c["sha"] not in scored:
                scored[c["sha"]] = {
                    **{k: c[k] for k in ("sha", "signed", "gpg_code", "n_parents",
                                          "forged_merge_shape", "author", "subject", "identity")},
                    "class": cls,
                    "score": round(score, 4),
                    "class_signed_rate_before": None if rate is None else round(rate, 4),
                    "class_support_before": support,
                    "identity_signed_rate_before": None if id_rate is None else round(id_rate, 4),
                    "identity_support_before": id_support,
                    "malicious": c["sha"] in malicious,
                    "label": malicious.get(c["sha"], ""),
                }
                class_totals.setdefault(cls, [0, 0])
                class_totals[cls][0] += int(c["signed"])
                class_totals[cls][1] += 1

            # slide the window AFTER scoring this commit
            cwin.append(int(c["signed"]))
            iwin.append(int(c["signed"]))

    population = list(scored.values())
    # rank: score desc, then class_support desc (more confident baseline breaks ties)
    population.sort(key=lambda r: (r["score"], r["class_support_before"]), reverse=True)
    for i, r in enumerate(population, 1):
        r["rank"] = i

    n = len(population)
    mal = [r for r in population if r["malicious"]]
    for r in mal:
        r["benign_ranked_at_or_above"] = sum(
            1 for x in population if (not x["malicious"]) and x["score"] >= r["score"] and r["score"] > 0
        )

    baseline_regime = {
        cls: {"signed": s, "total": t, "signed_rate": round(s / t, 3) if t else None}
        for cls, (s, t) in sorted(class_totals.items())
    }
    return {
        "repo": entry["repo"],
        "mirror": str(mirror),
        "population_size": n,
        "baseline_regime": baseline_regime,
        "malicious": mal,
        "top": population[:8],
    }


def render_md(results: list[dict], window: int) -> str:
    baseline_desc = (f"trailing window of {window} same-class commits" if window > 0
                     else "cumulative since start")
    L = ["# Signature-regression probe — ranked separation\n",
         f"Class-conditioned, time-ordered, directional signature baseline ({baseline_desc})",
         "over the pinned mirrors. Structural signal only (gpgsig present/absent); no keys, no API, no network.",
         f"A commit scores only when unsigned **and** its class has ≥ {MIN_SUPPORT} prior",
         "same-class commits in the window; the score is that window's signed-rate (1.0 = the class is",
         "always signed there, so an unsigned member is maximally anomalous). Score 0 = no signal.\n",
         "`benign@≥` = how many genuine commits rank at or above the malicious one (0 = a clean",
         "top-of-list flag; higher = buried among legitimately-unsigned commits).\n"]
    for r in results:
        L.append(f"\n## {r['repo']}  ·  {r['population_size']} commits scanned")
        regime = "  ".join(
            f"{cls}={m['signed_rate']} ({m['signed']}/{m['total']})"
            for cls, m in r["baseline_regime"].items()
        )
        L.append(f"\nbaseline signed-rate by class: {regime}\n")
        L.append("| commit | class | signed | forged-merge | score | class-rate before | support | rank | benign@≥ | note |")
        L.append("|---|---|---|---|---|---|---|---|---|---|")
        for m in r["malicious"]:
            L.append(
                f"| `{m['sha'][:10]}` | {m['class']} | {'yes' if m['signed'] else '**no**'} "
                f"| {'**yes**' if m.get('forged_merge_shape') else 'no'} "
                f"| **{m['score']}** | {m['class_signed_rate_before']} | {m['class_support_before']} "
                f"| {m['rank']}/{r['population_size']} | {m.get('benign_ranked_at_or_above','-')} | {m['label']} |"
            )
    L.append("\n## Reading\n")
    L.append("- **score ≈ 1.0, benign@≥ = 0** → the signal cleanly isolates the commit (owner-ATO force-push shape).")
    L.append("- **score = 0** → correctly silent: the commit's class is normally unsigned here, so there is no regression to see. Another detector (timezone drift) must carry it.")
    L.append("- The split across repos is the finding: this signal is high-precision on the force-push-a-twin shape and honestly blind elsewhere.\n")
    return "\n".join(L)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path,
                    default=ROOT / ".runartifacts" / "calibration-2026-09-01" / "signature_regression")
    ap.add_argument("--window", type=int, default=50,
                    help="trailing window of same-class commits for the baseline; 0 = cumulative")
    args = ap.parse_args()

    results = []
    for entry in CORPUS:
        sys.stderr.write(f"scanning {entry['repo']} …\n")
        results.append(score_repo(entry, args.window))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    (args.out.with_suffix(".json")).write_text(json.dumps(results, indent=2) + "\n")
    (args.out.with_suffix(".md")).write_text(render_md(results, args.window))

    # terminal summary
    baseline_desc = f"trailing-{args.window}" if args.window > 0 else "cumulative"
    print(f"\n== signature-regression probe (baseline: {baseline_desc}) ==")
    for r in results:
        print(f"\n{r['repo']}  ({r['population_size']} commits)")
        for m in r["malicious"]:
            flag = "FLAG" if m["score"] >= 0.5 and m.get("benign_ranked_at_or_above", 99) == 0 else \
                   ("weak" if m["score"] > 0 else "silent")
            print(f"  {m['sha'][:10]} {m['class']:8s} signed={'Y' if m['signed'] else 'N'} "
                  f"score={m['score']:<6} rank={m['rank']}/{r['population_size']} "
                  f"benign@≥={m.get('benign_ranked_at_or_above','-')}  [{flag}]  {m['label']}")
    print(f"\nwrote {args.out.with_suffix('.json')} and {args.out.with_suffix('.md')}")


if __name__ == "__main__":
    main()
