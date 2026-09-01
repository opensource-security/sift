# Signature-regression probe — findings

> Reproduce with `python scripts/probe_signature_regression.py`. Raw run outputs
> (`signature_regression*.{json,md}`) are written under `.runartifacts/` and are
> not tracked in git; this document is the curated summary.

Prototype for the "audit a repo before depending on it" reframe: does a
repo-scoped, **class-conditioned, time-ordered** signature-verification baseline
flag the owner-ATO force-push shape as an anomaly, without drowning in
legitimately-unsigned commits? Measurement only — touches nothing in
`sift/runtime`, wires nothing into the product. Runs offline on the pinned bare
mirrors with plain `git`: **no keyring, no GitHub API, no network**. The signal
is structural — a commit carries a `gpgsig` header (`%G? != N`) or it doesn't.

Script: `scripts/probe_signature_regression.py`. Raw output:
`signature_regression.{json,md}` beside this file. ~22k commits scanned across
six repos in a few seconds; $0.

## What the probe computes

For each commit, score it against the signed-rate of **its own class**, in
**its own repo**, over a **trailing window of the last 50 same-class commits**
preceding it (so an attacker's own burst can't lower the baseline, and a repo
that adopted signing partway through is judged by its recent norm, not its
lifetime average). Class is what the commit *presents as*: GitHub
auto-signs web-flow PR merges, so any commit whose subject is `Merge pull
request #N` is judged against the PR-merge baseline regardless of parent count;
everything else is `direct`. The score is directional — only *unsigned where the
class is normally signed* scores; *signed where unsigned is normal* is the benign
"someone adopted signing" direction and scores zero.

## Result: clean separation on the shape it targets, honest silence elsewhere

Trailing-50 baseline (raw: `signature_regression_w50.{json,md}`; the cumulative
run is kept alongside as `signature_regression.{json,md}` for comparison):

| repo | malicious | class | recent signed-rate | score | rank | benign@≥ | verdict |
|---|---|---|---|---|---|---|---|
| hugo-paper | `a68d2c9b` twin | pr_merge | ~100% | **1.0** | **1 / 614** | **0** | **isolated** |
| hugo-paper | `c26b0568` pre-rewrite twin | pr_merge | ~100% | 1.0 | 2 / 614 | 0 | **isolated** |
| keyv | `ee2681a9` | direct | ~100% | **1.0** | **1 / 2231** | **0** | **isolated** |
| keyv | `f97eabcd` | direct | ~100% | 0.98 | 2 / 2231 | 0 | **isolated** |
| keyv | `d8c850c7` | direct | — | 0.0 | 2170 | — | **silent — stayed signed** |
| injective | `5486f13e`, `01219285` | direct | ~0% | 0.0 | ~6168 / 6360 | 0 | **correctly silent** |
| mevn-cli | `3a30d0d7`, `ceb45587` | direct | ~4% | 0.04 | ~485 / 726 | ~484 | **correctly silent** |
| pz | `9324422a` | direct | ~36% | 0.36 | 200 / 6679 | 202 | **not isolated (weak)** |

**hugo-paper and keyv are both textbook isolates now.** hugo's twin is the lone
unsigned member of a ~always-signed PR-merge class; keyv's two payloads are
unsigned commits in a repo whose recent direct commits are ~100% signed. All
three score ≥ 0.98, rank 1–2, with zero benign commits at or above them. The
owner-ATO force-push and the drop-signing-mid-ATO shapes both isolate cleanly.

**The silences are the point, not a weakness.** injective, mevn-cli, and pz
place their payload in a commit class that is *normally unsigned* (direct pushes,
4–11% signed), so there is no regression to detect and the signal correctly
stays quiet — those ATOs are carried by the timezone-drift and patch-content
detectors instead. The probe demonstrates the signal is baseline-relative
("unsigned in a normally-signed slot"), not the naive "unsigned = bad" that would
fire on thousands of legitimate commits.

**keyv d8c850c7 is the intrinsic blind spot:** the attacker kept signing on that
commit, so no signature signal exists. (2 of the 3 keyv payloads dropped it.)

## The baseline is windowed — and it matters (confirmed)

The primary run uses a **trailing window** (last 50 same-class commits), not a
cumulative-since-start average, and re-running proved why. Under the cumulative
baseline keyv's payloads ranked 1–2 only by a hair: the lifetime class rate is
68% because it averages in years of early unsigned history, and **705** old
unsigned commits shared that ~0.68 neighborhood — a threshold there would flag
hundreds. The trailing-50 window scores those same payloads **1.0 / 0.98** with
**zero benign commits at or above them**, because keyv's *recent* direct commits
are ~100% signed. Windowing also cleaned the silence side: injective's score
went from a residual 0.036 to exactly **0.0**, since its recent direct commits
are all unsigned and there is no local regression to see.

**Robust to window size.** Swept at 30 / 50 / 100: hugo-paper is rank 1–2,
benign@≥ 0 at every window; keyv is a clean isolate at 50 and 100 (slightly
noisier at 30, rank 3/10, where a shorter window catches a couple of recent
benign unsigned blips); injective/mevn/pz stay silent or weak throughout. The
sweet spot is 50–100. hugo-paper was clean under *any* baseline because its
PR-merge class is ~always signed across all of history; keyv is the case that
required the window. pz is genuinely window-sensitive (score 0.19→0.36→0.50 as
the window shrinks) and never isolates — its recent direct class is a real ~36%
mix, so an unsigned commit there is unremarkable. Correctly weak, not flagged.

**2. A second, baseline-free tell: forged merge shape.** The twin has a
`Merge pull request #267` subject but **one parent** — a single-parent commit
masquerading as a web-flow PR merge (a real one is a 2-parent merge). Scanned
across all five repos, this shape occurs **once in ~16,600 commits**: the twin.
Zero benign false positives, no signing baseline required. It is arguably the
more robust primitive — it catches the impostor structure even against a repo
that doesn't sign, and even a signature-preserving attacker (who merges through
the web UI) can't produce a 1-parent "Merge pull request" commit through normal
GitHub flows.

## Verdict on the reframe

For the **owner-account force-push-a-twin** vector (hugo-paper, the maintainer-
domain/ATO class), a repo-scoped audit built from these two structural signals —
class-conditioned signature regression + forged-merge shape — cleanly isolates
the malicious commit from ~16,600 real commits with zero false positives, using
only offline git metadata. It does **not** replace the behavioral detectors; it
is a high-precision, narrow complement that fires where they're weakest (an
attacker who *is* the owner, so identity history looks fine) and stays honestly
silent where the payload rides a normally-unsigned commit.

**Next step if pursued:** (a) ~~trailing-window baseline~~ — done, confirmed above:
keyv sharpens to a clean isolate at window 50–100; (b) add the authoritative
GitHub-API `verification` field as a phase-two arm (catches the web-UI-merge
attacker the structural check would miss, at the cost of network + auth); (c) only
then consider promoting a `signature_state` surface into the case builder — the
first small, reversible product change.
