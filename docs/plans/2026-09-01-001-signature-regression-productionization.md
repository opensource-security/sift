<!--
Plan: gauge whether/how to productionize the signature-regression signal
prototyped 2026-09-01 (scripts/probe_signature_regression.py). Decision-first:
measure marginal value and false-positive cost before writing product code.
Status: proposed (not yet executed).
-->

# feat: Gauge productionizing the signature-regression signal

**Target repo:** `sift`. Prototype under review: `scripts/probe_signature_regression.py` and
`docs/findings/2026-09-01-signature-regression-probe.md`. This is a
**gauge** — a de-risking plan whose deliverable at each phase is a measurement
and a go/no-go, not a shipped feature. Several phases can end in "do not
productionize," and that is a valid, cheap outcome.

## Summary

The prototype established a narrow, high-precision, fully-offline signal:
*an unsigned commit occupying a class that this repo normally signs*, scored
against a trailing window of preceding same-class commits, plus a baseline-free
*forged-merge-shape* tell (a `Merge pull request #N` subject on a <2-parent
commit). On the corpus it cleanly isolates the two owner-ATO-with-a-signing-
baseline repos (hugo-paper, keyv) with zero false positives above them, and
stays correctly silent where the payload rides a normally-unsigned commit
(injective, mevn-cli, pz).

Two facts frame the whole productionization question and must not be lost:

1. **The signal is narrow by construction.** It fires only where a signing
   baseline exists *and* the payload lands in a normally-signed slot. Most
   dependencies have no signing baseline, so recall across the open-source world
   is low. This is a **corroborator**, never a primary gate.
2. **The per-commit product may already win without it.** The 2026-09-01
   calibration caught hugo-paper at high confidence from *patch content* alone
   (the `preinstall.js` loader). So the signal's marginal value in the triage
   product is concentrated on the cases where patch content is ambiguous or
   absent — which is exactly where it must be measured, not on the obvious-loader
   cases where the model already succeeds.

Together these point at a real possibility the gauge must be willing to reach:
the signal's best home may **not** be the per-commit triage model at all, but a
standalone, deterministic, offline **repo-audit / pre-dependency screen** — the
frame that motivated the prototype in the first place.

## Two candidate product shapes

The gauge evaluates both. They are not mutually exclusive, but they have very
different cost, surface area, and fit.

### Shape A — evidence line in per-commit triage

A `signature_state` block computed at case-build time and rendered into the
prompt as **evidence the model reads**, exactly like
`author_temporal_complexity_history` and `author_identity_history.domain_provenance`
today — *not* emitted as a standalone finding. The per-commit "baseline" is the
trailing window of same-class history preceding the observed commit, which the
case builder already assembles (merge-base baseline + author history landed in
`87aeebe`/`3f6f5ca`).

- **Fit:** matches the domain-provenance precedent precisely (computed, attached,
  read as evidence, off by default / env-gated). Reuses existing wiring.
- **Cost:** model calls to measure marginal value; product surface area in the
  hottest path (`build_realtime_case`).
- **Risk:** may be redundant with patch content on the loud cases and only helps
  on the quiet ones — which must be demonstrated, not assumed.

### Shape B — standalone repo-audit screen (`sift-audit`, deterministic)

A batch tool that scans a repo's history and ranks signature-regression +
forged-merge anomalies as a pre-dependency report. **No model, no API key,
offline, deterministic, $0 per run** — essentially the prototype promoted to a
first-class CLI with a report renderer.

- **Fit:** a narrow, structural, offline signal is a natural fit for a cheap
  deterministic screen. It answers a question the triage product does not:
  "before I add this dependency, does its history show an integrity regression?"
- **Cost:** lowest — no model, no new evidence surface in the triage prompt.
- **Risk:** a new product surface (`sift-audit`) and its own UX; recall is low so
  it must be framed honestly as a screen that flags a specific class, not a
  clean bill of health.

**Recommendation going in:** Shape B is the cheaper, better-fit home and should
be the default target; Shape A should be pursued *only if* Q1 below shows real
marginal value on patch-ambiguous cases. State this bias openly so the
measurements are allowed to overturn it.

> **Update (P0 executed 2026-09-01):** the measurements *did* overturn this bias.
> The benign soak showed the signal is not clean enough to autonomously flag
> (its benign false-positive class — unsigned rebase/ff PR-merges — is
> structurally identical to the attack), so **Shape B is downgraded and Shape A
> — the conjunction as evidence to the judgment layer — is now the primary path.**
> See P0 under the phased sequence and
> `docs/findings/2026-09-01-signature-regression-p0-soak.md`.

## Go/no-go questions the gauge must answer

**Q1 — Marginal value in triage (gates Shape A).** With the `signature_state`
evidence block in the prompt, does the model's verdict/confidence improve on the
targeted shape *where patch content is ambiguous*, without regressing elsewhere?
The obvious-loader cases are the wrong test (the model already wins); the test is
a patch-ambiguous variant.

**Q2 — Benign silence at scale (gates both shapes).** On a broad benign corpus
(many popular repos' recent history, no known compromise), does the signal stay
silent? The whole value proposition is precision; a non-trivial false-positive
rate on the legitimately-unsigned world kills it. Target: ~0 flags per benign
repo at the window/threshold chosen.

**Q3 — Is the offline structural arm enough, or is the GitHub-API `verification`
arm required (gates the network dependency)?** Structural `%G?` catches the
force-push-unsigned-twin but misses an attacker who merges through the web UI
(GitHub re-signs it). Quantify how many realistic ATO shapes the API arm adds,
and whether that recall is worth breaking the offline/stdlib property.

**Q4 — Adversarial durability.** Red-team the signal before shipping. An attacker
who knows it can: merge via the web UI (stays GitHub-Verified → structural arm
blind); sign with a self-registered key (badge state depends on account
binding); or avoid the normally-signed slot entirely (drop to a direct commit,
where the signal is silent by design). Bound the evasion cost and state it — the
signal raises attacker effort, it does not bind.

## Measurements (reuse what exists)

- **Q1 (marginal value)** — a FULL/BARE evidence-impact experiment: add a
  `signature_state` arm and measure verdict/
  confidence deltas on the ATO positives + matched negatives, and on a
  *patch-ambiguous* variant (strip or neutralize the loud loader lines, keep the
  signature evidence). This is the inverse of the patch-blind calibration we
  already ran. Cost: calibration-scale (tens of dollars).
- **Q2 (benign soak)** — the prototype *is* the measurement engine. Point it at a
  benign corpus (e.g. top-N npm/PyPI dependency repos by download, recent history
  only), count flags at window 50–100. Offline, $0 compute, passive fetch. This
  is the single most important number for the whole decision.
- **Q3 (API arm)** — add a phase-two arm to the probe that reads the GitHub
  commit `verification` field, run it on the same corpus, and diff its flags
  against the structural arm. Measures marginal recall of the network dependency.
- **Q4 (adversarial)** — analytic, plus constructing the evasion cases in a
  throwaway repo and confirming the signal's response. No corpus needed.

## Integration design sketch (for whichever shape survives)

- **Computation:** a `signature_state` surface in `case_builder.py` (Shape A) or
  a `sift/audit/` module (Shape B). Either way **stdlib-only** — the signal is
  `git log --format=%G?...`, which the prototype already proves needs nothing
  beyond `subprocess`. It therefore lives in core `runtime`/a new stdlib module,
  **not** the `provenance` extra.
- **The API-verified arm is the exception:** it needs `httpx` and a token, so it
  belongs behind an env gate mirroring `SIFT_DOMAIN_PROVENANCE` (call it
  `SIFT_SIGNATURE_VERIFY`), never in the always-on offline path. One-way import
  rule applies.
- **Evidence, not finding (Shape A):** render into the prompt like
  `author_temporal_complexity_history`; let the triage model weigh it. Do not add
  a 13th finding type. Name the source and observation basis on the line, per the
  two-path convention in CLAUDE.md.
- **Forged-merge-shape as a cheap always-on flag:** it is baseline-free and had
  1 hit in ~16,600 commits. It can render unconditionally in both shapes at
  near-zero cost and near-zero FP.
- **Replay/realtime asymmetry (known trap):** wire into `build_realtime_case`
  (the product path); `build_replay_case` lacks the preceding-history surface, so
  either add it or explicitly scope the signal to realtime and document it in the
  evidence-availability table. Measuring on replay would under-represent it, the
  same mistake the CLAUDE.md evidence-surface note warns about.

## Risks & failure modes

- **No-baseline repos (the majority):** signal correctly silent → low recall.
  Must be framed as a corroborator/screen, not a gate. A "no flags" audit result
  must never render as "safe."
- **Process migrations produce benign transitions:** a repo adopting signing, or
  switching merge strategy (merge→squash), shifts class rates. The trailing
  window and directional scoring (only unsigned-where-signed-expected) handle the
  common cases in the prototype, but the benign soak (Q2) is where this is
  actually proven or disproven.
- **Bot / release-automation identities:** handled in the prototype (keyv's
  `github-actions[bot]` scored fine), but confirm at scale.
- **GitHub key rotation / historical re-verification:** `%G?` is stable on the
  commit object; the API `verification` field is computed live and can change.
  A structural-first design is more durable; note it if the API arm ships.
- **Maintenance surface:** every new evidence line is prompt real estate and a
  thing to keep calibrated. Shape B avoids this entirely.

## Phased sequence with decision gates

Each phase is cheap and gates the next. Kill criteria are explicit.

- **P0 — Benign soak (Q2). DONE 2026-09-01 — see
  `docs/findings/2026-09-01-signature-regression-p0-soak.md`.** Ran the
  scorer over 24 repos / 53,510 commits. **Outcome: the naive signals fail the
  gate and P0 redefines the viable signal.** Score-only = 24.9 FP/repo (legit
  maintainer unsigned commits); forged-merge-shape alone = 2.3/repo (benign
  rebase/ff merges); the **`forged-merge ∧ unsigned` conjunction = 0.375/repo, 0
  in 23/24 repos**, with all 9 flags in one rebase-merge repo (prometheus) and
  structurally identical to the attack. Conclusion: the signal is **not an
  autonomous flag** — its benign FP class is inseparable from the attack — so
  **Shape B (standalone deterministic audit) is weakened and the effort pivots to
  Shape A**: the conjunction as env-gated triage *evidence* feeding the judgment
  layer. **P2 now moves ahead of P1.**
- **P1 — Promote the probe to `sift-audit` (Shape B) if P0 passes.** Deterministic
  CLI + report renderer; the forged-merge flag included. **Gate:** does the report
  read as actionable to a human deciding on a dependency? This is the low-risk
  ship — no model, no prompt surface.
- **P2 — Marginal-value A/B (Q1), only if Shape A is still wanted.** Add the
  `signature_state` evidence arm to the Q1 experiment; measure on
  patch-ambiguous cases. **Gate:** demonstrable verdict/confidence lift with no
  new false positives. *If it merely restates what patch content already tells the
  model, do not add it to triage* — ship B only.
- **P3 — API-verification arm (Q3), only if recall demands it.** Env-gated,
  measured against the structural arm on the P0 corpus. **Gate:** the added recall
  justifies the network dependency; otherwise stay offline-only.
- **P4 — Adversarial write-up (Q4)** before any of the above is called
  production-ready: document the evasion envelope so the signal is never
  oversold.

## Honest null outcomes (all acceptable)

- **"Ship B, not A"** — the deterministic audit screen is useful; the triage
  evidence line is redundant with patch content. (Most likely outcome given the
  calibration.)
- **"Keep it as an offline probe"** — if the benign soak (P0) shows the precision
  doesn't hold at scale, neither product ships and the probe stays a research
  tool.
- **"Structural only, no API arm"** — if P3 shows thin marginal recall.

The measurement order is deliberately cheapest-and-most-decisive-first (P0 is
$0 and can sink the whole thing), so we spend model budget in P2 only after the
precision premise has survived contact with a broad benign corpus.

## Rough effort / cost

| phase | compute cost | build effort | decisive? |
|---|---|---|---|
| P0 benign soak | $0 (offline git) | small (corpus assembly + probe run) | **yes — can kill everything** |
| P1 `sift-audit` | $0 | medium (CLI + renderer) | ships the low-risk product |
| P2 marginal-value A/B | tens of $ (model) | small (reuse Q1 setup) | gates Shape A |
| P3 API arm | $0 compute, needs token | small | gates the network dependency |
| P4 adversarial | $0 | small (write-up) | ship-readiness gate |
