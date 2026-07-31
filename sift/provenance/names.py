"""Input hardening for domain strings.

Domains reach this package out of PR metadata: commit author emails, GPG UIDs,
profile fields. All of that is text the PR author chose, and the next thing the
package does with it is interpolate it into a URL and fetch it. Inside a
`pull_request_target` job that makes an unvalidated path a server-side request
forgery primitive.

Everything here runs before any network call. Nothing else in the package may
build a URL from a domain that has not been through `resolve_domain`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import idna
import tldextract

from sift.runtime.case_builder import identity_email_domain, identity_email_is_noreply

# tldextract with its network refresh disabled: reproducible across runs and in
# CI, at the cost of a PSL snapshot that ages with the installed version.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", re.IGNORECASE)
_MAX_NAME_LEN = 253
_MAX_LABEL_LEN = 63

# Rejected outright: characters that only appear when someone is trying to make
# a domain string act as something other than a domain.
_FORBIDDEN_CHARS = set("/\\?#@:[]%&=+ \t\r\n\x00'\"<>|^`{}*!$(),;~")

# Out of scope by construction. A takeover of gmail.com is not a finding about
# this contributor, and a noreply address has no registrable domain to lose.
_SKIP_EXACT = frozenset(
    {
        "users.noreply.github.com",
        "github.com",
        "localhost",
        "localdomain",
    }
)

_SKIP_SUFFIXES = (
    ".local",
    ".localdomain",
    ".internal",
    ".intranet",
    ".corp",
    ".home",
    ".lan",
    # RFC 2606 / RFC 6761 reserved.
    ".test",
    ".example",
    ".invalid",
    ".localhost",
)

# Large mailbox providers. Not exhaustive by design: a miss costs one wasted
# lookup that returns CLEAN, not a false finding.
_MAILBOX_PROVIDERS = frozenset(
    {
        "gmail.com",
        "googlemail.com",
        "outlook.com",
        "hotmail.com",
        "hotmail.co.uk",
        "live.com",
        "msn.com",
        "yahoo.com",
        "yahoo.co.uk",
        "ymail.com",
        "aol.com",
        "icloud.com",
        "me.com",
        "mac.com",
        "proton.me",
        "protonmail.com",
        "protonmail.ch",
        "pm.me",
        "tutanota.com",
        "tuta.io",
        "fastmail.com",
        "fastmail.fm",
        "zoho.com",
        "gmx.de",
        "gmx.net",
        "gmx.com",
        "web.de",
        "mail.ru",
        "yandex.ru",
        "yandex.com",
        "qq.com",
        "163.com",
        "126.com",
        "sina.com",
        "naver.com",
        "hey.com",
        "duck.com",
        "users.sourceforge.net",
        "example.com",
        "example.org",
        "example.net",
    }
)

# Reason codes. `skipped` means measurement was declined and is a distinct state
# from `rejected` (hostile input) and from a lookup that was attempted and
# failed; see verdict.py.
REJECTED = "rejected"
SKIPPED = "skipped"
RESOLVED = "resolved"


@dataclass(frozen=True)
class ResolvedDomain:
    """Outcome of validating one domain string.

    `registrable` is populated only when `status == RESOLVED`, and is the only
    value in this package that may be interpolated into a URL.
    """

    raw: str
    status: str
    registrable: str = ""
    reason: str = ""

    @property
    def ok(self) -> bool:
        return self.status == RESOLVED


def _reject(raw: str, reason: str) -> ResolvedDomain:
    return ResolvedDomain(raw=raw, status=REJECTED, reason=reason)


def _skip(raw: str, reason: str) -> ResolvedDomain:
    return ResolvedDomain(raw=raw, status=SKIPPED, reason=reason)


def _looks_like_ip(text: str) -> bool:
    if text.count(".") == 3 and all(part.isdigit() for part in text.split(".")):
        return True
    return ":" in text


def resolve_domain(raw: str) -> ResolvedDomain:
    """Validate a domain string and reduce it to its registrable domain."""
    text = (raw or "").strip().strip(".").lower()
    if not text:
        return _reject(raw, "empty")
    if len(text) > _MAX_NAME_LEN:
        return _reject(raw, f"longer than {_MAX_NAME_LEN} characters")
    if _FORBIDDEN_CHARS & set(text):
        return _reject(raw, "contains characters not valid in a hostname")
    if _looks_like_ip(text):
        return _reject(raw, "IP literal, not a domain")
    if ".." in text:
        return _reject(raw, "empty label")
    if "." not in text:
        return _reject(raw, "no dot; not a fully qualified domain")

    # A-label normalization. Done before the charset check so a Unicode homograph
    # cannot resolve to a host that differs from the one we logged.
    try:
        encoded = idna.encode(text, uts46=True).decode("ascii")
    except (idna.IDNAError, UnicodeError, ValueError) as exc:
        return _reject(raw, f"not encodable as IDNA: {type(exc).__name__}")

    labels = encoded.split(".")
    for label in labels:
        if not label:
            return _reject(raw, "empty label")
        if len(label) > _MAX_LABEL_LEN:
            return _reject(raw, f"label longer than {_MAX_LABEL_LEN} characters")
        if not _LABEL_RE.match(label):
            return _reject(raw, f"invalid label {label!r}")

    if encoded in _SKIP_EXACT or encoded.endswith(_SKIP_SUFFIXES):
        return _skip(raw, "reserved or non-public namespace")

    parts = _EXTRACT(encoded)
    if not parts.suffix or not parts.domain:
        # Unknown or absent public suffix. Guessing two labels here would invent
        # a registrable domain that may not exist; the caller must treat this as
        # unmeasurable instead.
        return _reject(raw, "no known public suffix")

    registrable = f"{parts.domain}.{parts.suffix}"

    if registrable in _MAILBOX_PROVIDERS or registrable in _SKIP_EXACT:
        return _skip(raw, "shared mailbox provider")

    return ResolvedDomain(raw=raw, status=RESOLVED, registrable=registrable)


def resolve_email(email: str) -> ResolvedDomain:
    """Validate the domain part of an email address.

    Uses the same normalization as `case_builder` so the provenance package and
    the commit-triage pipeline agree on what an author's email domain is.
    """
    text = (email or "").strip()
    if not text:
        return _reject(email, "empty")
    if identity_email_is_noreply(text):
        return _skip(email, "noreply address; no registrable domain")
    domain = identity_email_domain(text)
    if not domain:
        return _reject(email, "no domain part")
    return resolve_domain(domain)


def assert_url_host(url: str, expected_host: str) -> None:
    """Last line of defence before a request leaves.

    Every fetch in this package passes through here. If a validated domain has
    somehow been used to build a URL pointing somewhere other than the intended
    service, fail loudly rather than making the request.
    """
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    if parts.scheme != "https":
        raise ValueError(f"refusing non-https URL: {url!r}")
    if parts.hostname != expected_host:
        raise ValueError(
            f"refusing request to {parts.hostname!r}; expected {expected_host!r}"
        )
