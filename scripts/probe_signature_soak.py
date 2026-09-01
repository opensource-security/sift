#!/usr/bin/env python3
"""P0 benign soak for the signature-regression signal.

Runs the SAME class-conditioned, trailing-window, directional scorer as
`probe_signature_regression.py` over a corpus of popular, uncompromised
dependency repos, and counts how often it FLAGS a commit. The precision premise
of the whole productionization effort is that this number is ~0 per benign repo.

Metadata-only and passive: each repo is cloned bare + blobless (`--filter=tree:0`,
recent history via `--shallow-since`) so only commit objects arrive; nothing is
ever checked out and no tree/blob is fetched. Signature state is structural
(`%G?`: gpgsig present = anything but N). No keys, no GitHub API, no model, $0.

A "flag" = a commit the audit would surface: score >= FLAG_THRESHOLD (unsigned in
a normally-signed class) OR forged_merge_shape (a `Merge pull request #N` subject
on a <2-parent commit). Every flag is dumped for inspection -- a benign flag is
the precision cost we are trying to measure, not a crash.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from collections import defaultdict, deque  # noqa: E402
from scripts.probe_signature_regression import walk, commit_class, MIN_SUPPORT  # noqa: E402

FLAG_THRESHOLD = 0.9
SHALLOW_SINCE = "2023-09-01"   # ~2 years of recent history per repo

CORPUS = [
    # JS / npm
    "facebook/react", "vuejs/core", "sveltejs/svelte", "vitejs/vite",
    "expressjs/express", "axios/axios", "prettier/prettier", "eslint/eslint",
    "webpack/webpack", "sindresorhus/execa", "date-fns/date-fns", "chalk/chalk",
    # Python
    "psf/requests", "pallets/flask", "pydantic/pydantic", "fastapi/fastapi",
    "django/django", "numpy/numpy",
    # Go
    "gin-gonic/gin", "spf13/cobra", "prometheus/prometheus",
    # Rust
    "serde-rs/serde", "tokio-rs/tokio", "clap-rs/clap",
]


def ensure_clone(repo: str, cache: Path) -> Path | None:
    path = cache / (repo.replace("/", "__") + ".git")
    if (path / "HEAD").exists():
        return path
    cache.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        ["git", "clone", "--bare", "--filter=tree:0", f"--shallow-since={SHALLOW_SINCE}",
         "-q", f"https://github.com/{repo}", str(path)],
        capture_output=True, text=True, timeout=300,
    )
    if r.returncode != 0 or not (path / "HEAD").exists():
        sys.stderr.write(f"  clone failed {repo}: {r.stderr.strip().splitlines()[-1:]}\n")
        return None
    return path


def default_ref(path: Path) -> str:
    r = subprocess.run(["git", "-C", str(path), "symbolic-ref", "HEAD"],
                       capture_output=True, text=True)
    return r.stdout.strip() or "HEAD"


def score_repo(repo: str, path: Path, window: int) -> dict:
    ref = default_ref(path)
    cls_win: dict[str, deque] = defaultdict(lambda: deque(maxlen=(window if window > 0 else None)))
    class_totals: dict[str, list[int]] = {}
    flags: list[dict] = []
    n = 0

    for c in walk(path, ref):
        n += 1
        cls = commit_class(c)
        cwin = cls_win[cls]
        support = len(cwin)
        rate = (sum(cwin) / support) if support else 0.0
        score = rate if (not c["signed"] and support >= MIN_SUPPORT) else 0.0

        class_totals.setdefault(cls, [0, 0])
        class_totals[cls][0] += int(c["signed"])
        class_totals[cls][1] += 1

        if score >= FLAG_THRESHOLD or c["forged_merge_shape"]:
            flags.append({
                "sha": c["sha"][:12], "class": cls, "signed": c["signed"],
                "forged_merge_shape": c["forged_merge_shape"],
                "score": round(score, 3), "class_rate_before": round(rate, 3),
                "support": support, "author": c["author"], "subject": c["subject"][:80],
            })
        cwin.append(int(c["signed"]))

    regime = {cls: {"signed_rate": round(s / t, 3) if t else None, "n": t}
              for cls, (s, t) in sorted(class_totals.items())}
    return {
        "repo": repo, "commits": n, "baseline_regime": regime,
        "n_flags": len(flags),
        "n_flags_score": sum(1 for f in flags if f["score"] >= FLAG_THRESHOLD),
        "n_flags_forged": sum(1 for f in flags if f["forged_merge_shape"]),
        "flags": flags,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--window", type=int, default=50)
    ap.add_argument("--cache", type=Path,
                    default=ROOT / ".runartifacts" / "benign-soak" / "mirrors",
                    help="where to keep the bare blobless clones (gitignored; reused across runs)")
    ap.add_argument("--out", type=Path,
                    default=ROOT / ".runartifacts" / "calibration-2026-09-01" / "signature_soak")
    args = ap.parse_args()

    results = []
    for repo in CORPUS:
        sys.stderr.write(f"soak {repo} …\n")
        path = ensure_clone(repo, args.cache)
        if path is None:
            continue
        results.append(score_repo(repo, path, args.window))

    n_repos = len(results)
    total_commits = sum(r["commits"] for r in results)
    total_flags = sum(r["n_flags"] for r in results)
    total_score_flags = sum(r["n_flags_score"] for r in results)
    total_forged = sum(r["n_flags_forged"] for r in results)
    summary = {
        "repos_scanned": n_repos, "total_commits": total_commits,
        "total_flags": total_flags, "score_flags": total_score_flags,
        "forged_merge_flags": total_forged,
        "flags_per_repo": round(total_flags / n_repos, 3) if n_repos else None,
        "window": args.window, "flag_threshold": FLAG_THRESHOLD,
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.with_suffix(".json").write_text(
        json.dumps({"summary": summary, "results": results}, indent=2) + "\n")

    print("\n== P0 benign soak ==")
    print(f"repos={n_repos}  commits={total_commits}  "
          f"flags={total_flags} (score={total_score_flags}, forged-merge={total_forged})  "
          f"flags/repo={summary['flags_per_repo']}")
    print(f"\n{'repo':26s} {'commits':>7} {'flags':>5}  regime (signed-rate by class)")
    for r in sorted(results, key=lambda x: -x["n_flags"]):
        reg = " ".join(f"{c}={m['signed_rate']}({m['n']})" for c, m in r["baseline_regime"].items())
        print(f"{r['repo']:26s} {r['commits']:>7} {r['n_flags']:>5}  {reg}")
    print(f"\nwrote {args.out.with_suffix('.json')}")


if __name__ == "__main__":
    main()
