"""The single egress chokepoint for the provenance package.

Implemented as an `httpx.BaseTransport` wrapper rather than a helper function so
that no caller can bypass it by constructing its own client, and so the same
object serves as both the production cache and the test fixture store.

Four modes. The default is **live**, because this runs in production; replay is an
explicit opt-in for tests.

  unset            -- live fetch, no recording. What a real analysis run does.
  SIFT_FIXTURE_REPLAY=1 -- replay only. A cache miss raises `CacheMiss`, so
                      level-1 tests are free, offline, and deterministic.
  SIFT_FIXTURE_LIVE=1   -- live fetch, recording on miss. For adding fixtures.
  SIFT_FIXTURE_LIVE=refresh -- live fetch always, overwriting existing records.

The default used to be replay, which meant every production run raised `CacheMiss`
on its first RDAP request and the whole check degraded to "unavailable" while the
fixture suite passed. Measured on a real Actions run before this was fixed. A test
harness must never be the default path for shipped code.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

import httpx

_FIXTURE_ROOT = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "provenance"

# Response headers worth keeping. Everything else is noise that would churn the
# fixtures on every re-record.
_KEPT_HEADERS = ("content-type", "retry-after")

MODE_REPLAY = "replay"
MODE_RECORD = "record"
MODE_REFRESH = "refresh"
MODE_LIVE = "live"


class CacheMiss(RuntimeError):
    """Replay mode encountered a URL with no recorded response."""

    def __init__(self, url: str, key: str) -> None:
        super().__init__(
            f"no recorded response for {url}\n"
            f"  expected fixture: {key}.json\n"
            f"  record it with SIFT_FIXTURE_LIVE=1"
        )
        self.url = url
        self.key = key


def current_mode() -> str:
    raw = (os.environ.get("SIFT_FIXTURE_LIVE") or "").strip().lower()
    if raw == "1":
        return MODE_RECORD
    if raw == "refresh":
        return MODE_REFRESH
    if (os.environ.get("SIFT_FIXTURE_REPLAY") or "").strip() == "1":
        return MODE_REPLAY
    # Live is the default: this package ships in an Action, and a fixture cache
    # that is never populated there would make every lookup a CacheMiss.
    return MODE_LIVE


@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0
    fetches: int = 0

    @property
    def lookups(self) -> int:
        return self.hits + self.misses


def cache_key(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:32]


class RecordingTransport(httpx.BaseTransport):
    """Replay-or-record transport wrapping httpx's default."""

    def __init__(
        self,
        *,
        fixture_dir: Path | None = None,
        mode: str | None = None,
        inner: httpx.BaseTransport | None = None,
    ) -> None:
        self.fixture_dir = Path(fixture_dir) if fixture_dir else _FIXTURE_ROOT
        self.mode = mode or current_mode()
        self._inner = inner
        self.stats = CacheStats()

    # -- fixture store ----------------------------------------------------

    def _path_for(self, url: str) -> Path:
        return self.fixture_dir / f"{cache_key(url)}.json"

    def _load(self, url: str) -> dict | None:
        path = self._path_for(url)
        if not path.is_file():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def _store(self, url: str, response: httpx.Response) -> None:
        self.fixture_dir.mkdir(parents=True, exist_ok=True)
        record = {
            "url": url,
            "status": response.status_code,
            "headers": {
                name: response.headers[name]
                for name in _KEPT_HEADERS
                if name in response.headers
            },
            "body": response.text,
        }
        path = self._path_for(url)
        path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # -- transport --------------------------------------------------------

    def _replay(self, record: dict, request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=int(record.get("status", 0)),
            headers=record.get("headers") or {},
            text=record.get("body") or "",
            request=request,
        )

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)

        if self.mode != MODE_REFRESH:
            record = self._load(url)
            if record is not None:
                self.stats.hits += 1
                return self._replay(record, request)

        self.stats.misses += 1
        if self.mode == MODE_REPLAY:
            raise CacheMiss(url, cache_key(url))

        if self._inner is None:
            self._inner = httpx.HTTPTransport(retries=1)
        response = self._inner.handle_request(request)
        response.read()
        self.stats.fetches += 1
        if self.mode != MODE_LIVE:
            self._store(url, response)
        return response

    def close(self) -> None:
        if self._inner is not None:
            self._inner.close()


_USER_AGENT = (
    "sift-domain-provenance/0.1 "
    "(+https://github.com/opensource-security/sift; supply-chain research)"
)


def build_client(
    *,
    timeout: float = 12.0,
    transport: httpx.BaseTransport | None = None,
) -> httpx.Client:
    """The only sanctioned way to get an HTTP client in this package.

    `follow_redirects` is off: a redirect to another host would defeat the host
    assertion in `names.assert_url_host`. Callers that need to follow one must
    re-validate the target explicitly.
    """
    return httpx.Client(
        transport=transport or RecordingTransport(),
        timeout=timeout,
        follow_redirects=False,
        headers={"User-Agent": _USER_AGENT},
    )
