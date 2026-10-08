# Testing notes

What the regression fixtures guard, and why they are built the way they are.
`README.md` has the one-line way to run them.

## Shape of the suite

There is no general unit-test suite. `tests/` holds regression fixtures pinned
to specific real incidents, each runnable directly (`python tests/<file>.py`)
or under pytest, with no pytest dependency. Level-1 assertions are
deterministic and free; level-2 assertions that call a live model are opt-in
behind `SIFT_FIXTURE_LIVE=1`.

## Provenance: three tests, three failure classes

- `test_domain_provenance.py` replays the two real incidents from recorded
  RDAP/CT responses against a pinned `now`.
- `test_provenance_scenarios.py` is the band ladder as a table of
  (shape → expected band/role), covering the space *around* those incidents.
  The two deliberate caps live here: a weak (author-date) anchor never reaches
  CRITICAL, and corroboration never moves a band.
- `test_provenance_pipeline_anchors.py` tests the wiring from `case_builder`
  history through to a verdict. Four defects once lived in that path
  simultaneously while every incident fixture passed, because those fixtures
  construct their own anchors and enter at `assess_domain`.

Provenance tests set `SIFT_FIXTURE_REPLAY=1` for themselves. Replay is opt-in:
production defaults to live network access, because a fixture cache that is
never populated on a runner would make every lookup a `CacheMiss`.

`SIFT_FIXTURE_LIVE` controls the HTTP cache in `sift/provenance/http_cache.py`:
unset replays recorded responses and a miss raises; `1` fetches live and
records on miss; `refresh` re-records unconditionally.

## The timezone detector: what is easy to break

`test_author_timezone_anomaly.py` pins
`case_builder.summarize_author_temporal_complexity_history` against two real
2026 account-takeover incidents (keyv/ChainDrop, drift +420 from a US Pacific
baseline; Injective, drift −720 from +0800 and independently confirmed by
Datadog). Three things it guards:

- **`+0000` is not the signal.** Legitimate release automation in the keyv
  repo commits at `+0000`, the same offset as the attack. Only drift against a
  *per-identity* baseline separates them, and an identity with no history must
  yield an unknown mode rather than a default of zero drift.
- **Burst position degrades the signal.** The history window ingests the
  attacker's own earlier commits, so `first_seen` flips after the first
  payload commit and mode support decays 20 → 19 → 18. Per-commit evaluation
  of a burst is therefore *not* independent.
- **Inversion is latent.** Once malicious commits exceed half the window the
  mode becomes the attacker's offset and drift collapses to 0. Both incidents
  are far short (3 commits vs the 11 needed at the default window of 20), so
  the test pins the arithmetic rather than the symptom.

## Fixture commit objects: mirror first

`tests/fixture_repos.py` resolves fixture commits from a local bare mirror
before falling back to the `~/.cache/sift-fixtures` cache and then to GitHub.
Use `ensure_commits(repo_slug, shas)`; do not shallow-fetch from GitHub
directly in a new fixture.

The reason is not speed. Malicious commits get reaped after disclosure, and
the fixture only finds out by erroring. `icflorescu/mantine-datatable@f72462d9`
has a full SHA published in vendor writeups and a repository that is still
live, yet the object is purged network-wide: `upload-pack` says "not our ref",
REST says 422, and all ten post-incident forks agree. Several keyv commits in
the corpus are already unreachable from any branch and survive upstream only
because GitHub still serves unreachable objects by full SHA.

Mirrors are read, never written. They live at `$SIFT_FIXTURE_MIRRORS`
(colon-separated) or `../upstream-mirrors` relative to the repo root, as
`<name>.git`. When capturing an unreachable object, pin it with
`git update-ref refs/mirror/<sha> <sha>` or the next `gc` in that mirror reaps
it.

**These trees carry live credential stealers wired to `preinstall` hooks and
to `.claude`/`.vscode` agent auto-run configs. The fixtures read commit
metadata and patches only. Never check one out into a working directory, and
never point a package manager or an editor at one.**
