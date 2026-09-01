# P0 — benign soak results

> Reproduce with `python scripts/probe_signature_soak.py`. Raw run output
> (`signature_soak.json`) and the bare blobless clones are written under
> `.runartifacts/` and are not tracked in git; this document is the curated summary.

Ran the class-conditioned, trailing-window (50) signature scorer over **24 popular
uncompromised dependency repos, 53,510 commits** across JS/Python/Go/Rust
(`scripts/probe_signature_soak.py`; raw `signature_soak.json`). Metadata-only,
passive, offline, $0 — bare blobless clones, nothing checked out. The gate was
"~0 flags per benign repo." **It is not met by the naive signals, and the reason
is decision-relevant.**

## Result: the naive signals drown; the specific one is low-FP but not zero

| signal | benign flags | per repo | verdict |
|---|---|---|---|
| **score only** (unsigned in a normally-signed class) | 598 | 24.9 | **fails hard** |
| **forged-merge shape** (`Merge pull request #N`, <2 parents) | 55 | 2.3 | **fails** |
| **forged-merge ∧ unsigned** (the hugo-twin fingerprint) | 9 | 0.375 | 23/24 repos clean; see below |

**Why score-only drowns.** Of 598 flags, only 10 are bots — the rest are *core
maintainers* making legitimate unsigned commits in repos that mostly sign (top
flagged authors: Rich Harris/svelte, Alice Ryhl/tokio, the vite team). A repo
that signs 88% has ~12% legitimately-unsigned commits, each scoring ~0.9. The
score cannot separate a maintainer who didn't sign from an attacker who couldn't.
**Unsigned-in-a-signing-repo is not, by itself, a usable flag.**

**Why forged-merge-shape alone is noisy.** All 55 raw hits are **signed** except
9; numpy (14) and prometheus (37) use rebase/fast-forward merges, which
legitimately produce single-parent commits that keep the `Merge pull request #N`
subject. The shape is a normal artifact of a common merge strategy.

**Why even the conjunction isn't zero.** The 9 `forged-merge ∧ unsigned` flags
are **all in prometheus/prometheus**, all benign — real maintainers (Levi
Harrison, Julien Pivotto, Bartłomiej Płotka, …) whose rebase-merges landed
unsigned. prometheus produces 37 single-parent PR-merge commits, 9 of them
unsigned, as routine workflow. That is **structurally identical to the
hugo-paper attack artifact** (unsigned, single-parent, PR-merge subject). A
per-repo rarity guard does not separate them: 37/1977 is genuinely rare in
prometheus too, so "rare deviant shape" flags the benign 9 just as it flags the
malicious twin.

## What this means for productionization

The clean isolation seen on the incident corpus was partly an artifact of those
repos being ~100% signed with **no benign unsigned blips**. The open-source world
is messier: legitimate unsigned maintainer commits and unsigned rebase-merges are
common, and the latter reproduce the attack's exact structural fingerprint.

- **Kills the autonomous-flag framing.** Neither "score" nor "forged-merge" nor
  their conjunction is clean enough to *autonomously* flag/gate a commit. A
  deterministic `sift-audit` that emitted these as verdicts would surface ~0.4–25
  false positives per repo, all looking like ordinary maintainer merges — which
  erodes trust fast. **This weakens Shape B (standalone deterministic screen).**
- **Supports the evidence-to-judgment-layer framing.** The `forged-merge ∧
  unsigned` signal is a genuinely *low-rate* anomaly (0 in 23/24 repos, 9 in one
  rebase-merge repo). As **one input to a layer that also sees the patch, the
  author identity, and timing** — i.e. sift's existing triage model, exactly how
  `domain_provenance` and timezone drift are already consumed — that residual FP
  is fine, because the judgment layer has the context to discount a payload-free
  unsigned rebase-merge from a known maintainer. **This is the strongest
  remaining path, and it is Shape A**, not B.

## Revised gate outcome

P0 does not cleanly pass, but it does not kill the effort — it **redefines the
viable signal and its role**:

- The usable signal is the **`forged-merge ∧ unsigned` conjunction**, not score
  and not forged-merge alone.
- It is **not an autonomous detector** — its benign FP class (unsigned
  rebase/ff PR-merges) is structurally inseparable from the attack. It must feed a
  **judgment layer with additional context**, never gate on its own.
- Therefore the next question is no longer "ship the audit" (Shape B) but the
  **marginal-value A/B (Q1 / P2)**: does handing this conjunction to the triage
  model, on patch-ambiguous cases, improve the verdict without new false
  positives? That measurement now moves ahead of P1.

**Recommendation:** drop the standalone-audit path as primary; pursue the
signature signal only as env-gated triage *evidence* (Shape A), and let P2 decide
whether it earns its prompt surface. Keep `forged-merge ∧ unsigned` (not score) as
the concrete evidence line. The forged-merge-shape flag on its own remains useful
as *context* ("this presents as a PR merge but is single-parent"), never as a
verdict.
