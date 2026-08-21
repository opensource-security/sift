"""Anchoring `used_since`, and testing activity across an ownership gap.

The subject of a provenance check is **the account's identity history, not the
PR's commit emails**. An attacker holding an account can set the git author to
anything, including a noreply address, so reading only the PR head would hand
them a one-line bypass. Divergence between the PR author email and every
historical one is a separate signal, not the input.

Anchor sources, ranked by how hard they are to forge:

  strong  GPG UID binding signatures. Fetched from `github.com/<user>.gpg`. Each
          UID carries its own self-signature creation date, so a key bearing
          `x@olddomain.net` bound in 2015 attests use of that domain in 2015 --
          per-domain, not one key-wide date.

  strong  GH Archive push events. Server-side timestamps, unlike git author
          dates. NOT WIRED: `case_builder.build_gharchive_context` is keyed on a
          `GroundTruthCommit` research fixture, and no general
          (email -> earliest push) index exists in this tree. `gharchive_anchor`
          documents the shape and returns None until one is built.

  weak    Commit author dates from repo-local history. Attacker-settable, so
          floored at the account creation date when one is known.
"""

from __future__ import annotations

import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

from sift.provenance import names
from sift.provenance.http_cache import CacheMiss, build_client
from sift.provenance.verdict import (
    CONTINUOUS,
    DORMANT,
    INDETERMINATE,
    MEDIUM,
    STRONG,
    WEAK,
    GapActivity,
    UseAnchor,
)
from sift.runtime.case_builder import (
    identity_email_domain,
    parse_iso_datetime,
    run_git,
)

_GITHUB_HOST = "github.com"

# GitHub answers `.gpg` for every account with HTTP 200 and an armored block, so
# "no keys" is a body to recognize rather than a status code to check.
_NO_KEYS_MARKER = "hasn't uploaded any GPG keys"

_UID_RE = re.compile(r'^:user ID packet: "(?P<uid>.*)"$')
_CREATED_RE = re.compile(r"^\s*version \d+, created (?P<created>\d+)")
_PUBKEY_RE = re.compile(r"^:public key packet:")
_EMAIL_IN_UID_RE = re.compile(r"<([^>]+)>")


# -- GPG UID anchors -----------------------------------------------------------


def fetch_gpg_keys(login: str, *, client: httpx.Client | None = None) -> str:
    """Armored public keys for a GitHub login, or "" when there are none."""
    safe = (login or "").strip()
    if not safe or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", safe):
        return ""
    url = f"https://{_GITHUB_HOST}/{safe}.gpg"
    try:
        names.assert_url_host(url, _GITHUB_HOST)
    except ValueError:
        return ""

    owns_client = client is None
    client = client or build_client()
    try:
        response = client.get(url, headers={"Accept": "text/plain"})
    except CacheMiss:
        raise
    except httpx.HTTPError:
        return ""
    finally:
        if owns_client:
            client.close()

    if response.status_code != 200:
        return ""
    text = response.text
    if _NO_KEYS_MARKER in text:
        return ""
    return text


def parse_gpg_packets(armored: str, *, gpg_binary: str = "gpg") -> list[tuple[str, datetime]]:
    """(uid, bound_at) pairs from an armored key block.

    Shells out to `gpg --list-packets` rather than taking a library dependency:
    PGPy 0.6.0 imports `imghdr`, removed from the stdlib in Python 3.13 by PEP
    594, so it cannot be imported at all on current Python. `gpg` is present on
    GitHub runners, and its output additionally exposes each UID's own binding
    signature date, which a key-wide `created` field would not.

    Fails closed: anything unparseable yields no anchors rather than a bad one.
    """
    if not armored.strip():
        return []
    try:
        proc = subprocess.run(
            [gpg_binary, "--list-packets"],
            input=armored,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        return []

    out: list[tuple[str, datetime]] = []
    pending_uid: str | None = None
    key_created: datetime | None = None
    awaiting_key_created = False

    for line in proc.stdout.splitlines():
        if _PUBKEY_RE.match(line):
            pending_uid = None
            awaiting_key_created = True
            continue

        uid_match = _UID_RE.match(line)
        if uid_match:
            pending_uid = uid_match.group("uid")
            awaiting_key_created = False
            continue

        created_match = _CREATED_RE.match(line)
        if not created_match:
            continue
        try:
            when = datetime.fromtimestamp(int(created_match.group("created")), tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            continue

        if awaiting_key_created:
            # The `created` on a public key packet line is the key's own date.
            key_created = when if key_created is None or when < key_created else key_created
            awaiting_key_created = False
            continue
        if pending_uid is not None:
            out.append((pending_uid, when))
            pending_uid = None

    # A UID with no usable binding signature still attests use, just no earlier
    # than the key itself.
    if not out and key_created is not None:
        for line in proc.stdout.splitlines():
            uid_match = _UID_RE.match(line)
            if uid_match:
                out.append((uid_match.group("uid"), key_created))

    return out


def gpg_anchors(
    login: str, *, client: httpx.Client | None = None, gpg_binary: str = "gpg"
) -> dict[str, UseAnchor]:
    """Earliest attested use per registrable domain, from GPG UIDs."""
    armored = fetch_gpg_keys(login, client=client)
    anchors: dict[str, UseAnchor] = {}
    for uid, bound_at in parse_gpg_packets(armored, gpg_binary=gpg_binary):
        for email in _EMAIL_IN_UID_RE.findall(uid):
            resolved = names.resolve_email(email)
            if not resolved.ok:
                continue
            domain = resolved.registrable
            existing = anchors.get(domain)
            if existing is None or bound_at < existing.first_seen:
                anchors[domain] = UseAnchor(
                    domain=domain,
                    first_seen=bound_at,
                    kind="gpg_uid",
                    strength=STRONG,
                    evidence=f"GPG UID {uid!r} bound {bound_at.date().isoformat()}",
                )
    return anchors


def gharchive_anchor(email: str, *, index=None) -> UseAnchor | None:
    """Earliest server-side push timestamp for an email. Not yet available.

    GH Archive push `created_at` is not attacker-settable, which would make this
    the strongest anchor here. `case_builder.build_gharchive_context` is keyed on
    a `GroundTruthCommit` and an event lookup built for replaying specific
    incidents, so there is no general (email -> earliest push) index to query.
    Pass one in as `index` when it exists; until then this returns None so callers
    fall back to repo-local history.
    """
    if index is None:
        return None
    domain = identity_email_domain(email)
    if not domain:
        return None
    when = index.get(email.strip().casefold())
    if when is None:
        return None
    resolved = names.resolve_email(email)
    if not resolved.ok:
        return None
    return UseAnchor(
        domain=resolved.registrable,
        first_seen=when,
        kind="gharchive_push",
        strength=STRONG,
        evidence="earliest GH Archive push event for this address",
    )


# -- repo-local anchors --------------------------------------------------------


def anchors_from_identity_history(
    identity_history: dict,
    *,
    account_created_at: datetime | None = None,
) -> dict[str, UseAnchor]:
    """Anchors from `case_builder`'s author identity history.

    Reuses the per-email `first_seen_at` that `summarize_author_identity_history`
    already computes rather than re-walking git. Author dates are settable by
    whoever made the commit, hence WEAK, and floored at the account creation date
    when one is known: a commit claiming to predate the account is evidence of
    date forgery, not of long-standing use.
    """
    anchors: dict[str, UseAnchor] = {}
    buckets = list(
        identity_history.get("author_email_variants")
        or identity_history.get("email_variants")
        or []
    )

    # `author_email_variants` holds only the *alternate* addresses. A contributor
    # who has always used one address has an empty list, and their first-seen date
    # lives in the flat `author_email_first_seen_at` field instead. Omitting it
    # left the single-address contributor -- the common case, and the one this
    # check exists for -- with no anchor at all, hence a permanent UNKNOWN.
    current = identity_history.get("current_author")
    if isinstance(current, dict):
        primary_email = str(current.get("email") or "")
        primary_first_seen = str(
            identity_history.get("author_email_first_seen_at") or ""
        )
        if primary_email and primary_first_seen:
            buckets.append({"email": primary_email, "first_seen_at": primary_first_seen})

    for entry in buckets:
        if not isinstance(entry, dict):
            continue
        email = str(entry.get("email") or "")
        first_seen_raw = str(entry.get("first_seen_at") or "")
        if not email or not first_seen_raw:
            continue
        resolved = names.resolve_email(email)
        if not resolved.ok:
            continue
        first_seen = parse_iso_datetime(first_seen_raw)
        if first_seen is None:
            continue
        if first_seen.tzinfo is None:
            first_seen = first_seen.replace(tzinfo=timezone.utc)
        forged = False
        if account_created_at is not None and first_seen < account_created_at:
            first_seen = account_created_at
            forged = True
        domain = resolved.registrable
        existing = anchors.get(domain)
        if existing is None or first_seen < existing.first_seen:
            anchors[domain] = UseAnchor(
                domain=domain,
                first_seen=first_seen,
                kind="commit_author_date",
                strength=WEAK,
                evidence=(
                    f"earliest repo-local commit authored as {email}"
                    + (
                        "; author date predated the account and was floored to "
                        "account creation"
                        if forged
                        else ""
                    )
                ),
            )
    return anchors


def merge_anchors(*sources: dict[str, UseAnchor]) -> dict[str, UseAnchor]:
    """Earliest anchor per domain, keeping the strongest source on a tie."""
    rank = {STRONG: 0, MEDIUM: 1, WEAK: 2}
    merged: dict[str, UseAnchor] = {}
    for source in sources:
        for domain, anchor in source.items():
            existing = merged.get(domain)
            if existing is None:
                merged[domain] = anchor
                continue
            if anchor.first_seen < existing.first_seen or (
                anchor.first_seen == existing.first_seen
                and rank[anchor.strength] < rank[existing.strength]
            ):
                merged[domain] = anchor
    return merged


# -- gap activity --------------------------------------------------------------


def _trusted_revisions(repo_path: Path) -> list[str]:
    """The repo's default branch, the only ref gap evidence may be read from.

    Never `--all`: under `pull_request_target` the PR head (and any branch the
    contributor can push) is present in the analysis repo, so an attacker could
    manufacture the commits that suppress their own discontinuity signal.
    Counter-evidence sourced from attacker-writable refs is worse than no
    counter-evidence (docs/domain-provenance-plan.md, open question 1 —
    resolved 2026-08-21). An empty return means the scope could not be
    resolved and the gap test must not run.
    """
    for probe in (["symbolic-ref", "-q", "refs/remotes/origin/HEAD"], ["symbolic-ref", "-q", "HEAD"]):
        code, out, _ = run_git(repo_path, *probe)
        ref = out.strip()
        if code == 0 and ref:
            verify_code, _, _ = run_git(repo_path, "rev-parse", "--verify", "-q", f"{ref}^{{commit}}")
            if verify_code == 0:
                return [ref]
    return []


def _git_log_window(
    repo_path: Path,
    *,
    author_email: str,
    revisions: list[str],
    since: datetime,
    until: datetime,
) -> list[tuple[str, str]]:
    """(sha, signing_key) for commits by this author inside a window."""
    code, out, _ = run_git(
        repo_path,
        "log",
        *revisions,
        "--no-merges",
        f"--author={author_email}",
        "--fixed-strings",
        f"--since={since.isoformat()}",
        f"--until={until.isoformat()}",
        "--pretty=%H%x1f%GK",
        "--max-count=500",
    )
    if code != 0:
        return []
    rows: list[tuple[str, str]] = []
    for line in out.splitlines():
        if not line.strip():
            continue
        sha, _, key = line.partition("\x1f")
        rows.append((sha.strip(), key.strip()))
    return rows


def _commits_outside(
    repo_path: Path,
    *,
    author_email: str,
    revisions: list[str],
    before: datetime,
    after: datetime,
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Commits by this author strictly before and strictly after the gap.

    Presence is decided from commit SHAs, not signing keys: `%GK` is empty for
    unsigned commits, so keying "did they commit" off signatures would read every
    unsigned history as no history at all.
    """
    base = [
        "log",
        *revisions,
        "--no-merges",
        f"--author={author_email}",
        "--fixed-strings",
        "--pretty=%H%x1f%GK",
        "--max-count=200",
    ]

    def rows(extra: list[str]) -> list[tuple[str, str]]:
        code, out, _ = run_git(repo_path, *(base + extra))
        if code != 0:
            return []
        found: list[tuple[str, str]] = []
        for line in out.splitlines():
            if not line.strip():
                continue
            sha, _, key = line.partition("\x1f")
            found.append((sha.strip(), key.strip()))
        return found

    return (
        rows([f"--until={before.isoformat()}"]),
        rows([f"--since={after.isoformat()}"]),
    )


def gap_activity(
    repo_path: Path,
    *,
    author_email: str,
    gap_start: datetime,
    gap_end: datetime,
    scope: str = "repo_local",
    history_revisions: list[str] | None = None,
) -> GapActivity | None:
    """Was this identity active across the ownership gap?

    Repo-local scope. The consequence, stated plainly: a first-time contributor
    has no repo-local history at all, so the verdict is `unknown` by construction
    and can never be `dormant`. That is correct -- with no history here there is
    no continuity claim for a takeover to break -- but it means this discriminator
    does no work on exactly the population a reviewer is least sure about.
    Account-wide scope via a GH Archive index is what would fix it.

    Evidence is read only from `history_revisions` (the caller's trusted
    baseline — the ref under review's default-branch side), or, when absent,
    the repo's own default branch. Never from `--all`: attacker-pushable refs
    could otherwise manufacture the in-gap commits that suppress a
    discontinuity. If no trusted revision resolves, the gap is not tested
    (returns None → INDETERMINATE downstream) rather than tested against
    untrusted history.
    """
    if not repo_path or not Path(repo_path).exists():
        return None
    if gap_end <= gap_start:
        return None
    revisions = [r for r in (history_revisions or []) if r and r.strip()]
    if not revisions:
        revisions = _trusted_revisions(Path(repo_path))
    if not revisions:
        return None

    # Strictly after `gap_start`. The anchor is itself the earliest commit at
    # that timestamp, and `git log --since` is inclusive, so an inclusive window
    # counts the anchoring commit as activity *inside* the gap it defines. Every
    # repo-local anchor then read as CONTINUOUS -- inverting a takeover into
    # counter-evidence, the worst possible direction for this check to fail.
    in_gap = _git_log_window(
        Path(repo_path),
        author_email=author_email,
        revisions=revisions,
        since=gap_start + timedelta(seconds=1),
        until=gap_end,
    )
    before, after = _commits_outside(
        Path(repo_path),
        author_email=author_email,
        revisions=revisions,
        before=gap_start,
        after=gap_end,
    )

    # `%GK` is empty on unsigned commits and "0" on some git versions; neither is
    # a key, so neither can establish continuity.
    keys_before = {key for _sha, key in before if key and key != "0"}
    keys_after = {key for _sha, key in after if key and key != "0"}
    same_key = bool(keys_before & keys_after)

    if in_gap:
        verdict = CONTINUOUS
    elif before and after:
        # Committed on both sides but never during the gap: the dormant-then-
        # resumed shape.
        verdict = DORMANT
    else:
        verdict = INDETERMINATE

    return GapActivity(
        gap_start=gap_start,
        gap_end=gap_end,
        commits_in_gap=len(in_gap),
        same_signing_key=same_key,
        scope=scope,
        verdict=verdict,
    )
