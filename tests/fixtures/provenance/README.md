# Recorded provenance fixtures

Filenames are `sha256(url)[:32].json` — see `sift/provenance/http_cache.py`.
This index exists so the files are navigable by hand; nothing reads it.

Re-record with `SIFT_FIXTURE_LIVE=1`, or force with `SIFT_FIXTURE_LIVE=refresh`.

**Only successful responses are kept here.** A fixture holding a 404 or 502 would
replay a service error as though it were data — an empty CT result and a crt.sh
outage are different facts, and the first draft of this fixture set conflated them.
A missing fixture degrades correctly: CT and Wayback are corroboration-only, so
their absence lowers confidence and never raises a band.

crt.sh answers roughly one request in three; recording its fixtures takes retries.
No successful crt.sh response for `figlief.com` was obtained, so its CT history is
genuinely unestablished rather than known-empty.

| fixture | status | URL |
|---|---|---|
| `131232d49c7ac3b8333662b17f4e46e5.json` | 200 | `https://web.archive.org/cdx/search/cdx?url=figlief.com&output=json&fl=timestamp,original,digest,statuscode&collapse=timestamp:6&limit=3000` |
| `3d969e8e3ba6c283b7676da16be547dd.json` | 200 | `https://web.archive.org/cdx/search/cdx?url=atlantis-software.net&output=json&fl=timestamp,original,digest,statuscode&collapse=timestamp:6&limit=3000` |
| `6857fdab132fce8d05015327b72a72cf.json` | 200 | `https://crt.sh/?q=atlantis-software.net&output=json` |
| `6b42e3b128ef5edda18dfb769f235a69.json` | 200 | `https://rdap.verisign.com/net/v1/domain/atlantis-software.net` |
| `7e81efd8af8ba99ab37f37264ee3ce8b.json` | 200 | `https://rdap.publicinterestregistry.org/rdap/domain/python.org` |
| `9561752ad8ec8c14ccfc435b32e91ff0.json` | 200 | `https://rdap.verisign.com/com/v1/domain/figlief.com` |
| `96dbebdbe0dcaa0102a1a68655e4e1bf.json` | 200 | `https://data.iana.org/rdap/dns.json` |
| `d6abc5eb9652010a80b95a1870d99554.json` | 200 | `https://github.com/di.gpg` |
| `fdd562942ee1b491ada784c53ad4d21a.json` | 400 | `https://rdap.publicinterestregistry.org/rdap/domain/de.wikipedia.org` |
