<img src="logo.png" align="right" width="140" alt="scan-gateway logo" />

# scan-gateway

A pluggable malware-scan orchestrator for file uploads: tries configured
scanner plugins (in order), falls back to a built-in local heuristic check
when none can complete a scan, and raises a typed exception when something
is flagged. It doesn't scan anything itself -- it's a gateway in front of
whichever scanners you plug in.

```python
from pathlib import Path

from scan_gateway import ScanGateway, ThreatDetectedError
from scan_gateway.scanners.clamav import ClamAVScanner

gateway = ScanGateway(scanners=[ClamAVScanner(host="clamav.internal")])

try:
    await gateway.scan(Path("upload.pdf"))
except ThreatDetectedError as exc:
    print(f"{exc.scanner_name} flagged this: {exc.verdict}")
```

If `ClamAVScanner` can't be reached, `ScanGateway` falls back to its
built-in `LocalHeuristicScanner` (YARA + a couple of PDF-structural
keyword checks) automatically -- the caller never needs to know which
layer actually scanned the file.

## Writing a scanner plugin

This is the whole point of the package, so it comes first.

1. Add `scan-gateway` as a dependency (optional at runtime if your plugin
   only relies on structural typing, see below).
2. Implement a class with:
   - `name: str` -- used in log lines and in exception messages so it's
     obvious which plugin did what.
   - `async def scan(self, path: Path) -> None` -- return `None` when
     clean. Raise `scan_gateway.ThreatDetectedError(self.name, verdict)`
     when the file is flagged. Raise
     `scan_gateway.ScannerUnavailableError(self.name, reason)` when the
     scan itself couldn't be completed for operational reasons
     (connection refused, timeout, malformed response, etc) -- never for
     "clean", and never confuse the two: `ScanGateway` treats
     `ScannerUnavailableError` as "try the next scanner", and
     `ThreatDetectedError` as "stop, this file is rejected".

   Because `Scanner` is a `typing.Protocol`, your class doesn't need to
   import or subclass anything from `scan_gateway` at all -- structural
   typing means "has a `.name` and a matching `.scan()`" is enough.

3. Decide how your plugin gets configured:
   - **Auto-discovered** (zero code change on the consuming app's side):
     your class needs a zero-argument constructor, reading whatever
     config it needs from its own environment variables. Register it in
     *your own* `pyproject.toml`:
     ```toml
     [project.entry-points."scan_gateway.scanners"]
     my_scanner = "my_scanner_pkg.plugin:MyScanner"
     ```
     Once both packages are installed, `ScanGateway(discover_plugins=True)`
     (the default) finds and instantiates it automatically.
   - **Explicitly registered**: if your plugin needs config only known at
     runtime (hosts, API keys, secrets) that can't reasonably live in an
     environment variable your class reads unprompted, document that
     consuming apps should import and instantiate it themselves, then pass
     the instance to `ScanGateway(scanners=[...])`. This is exactly how
     the bundled `ClamAVScanner` works (see below) -- it is **not**
     auto-discovered, on purpose.

   Nothing stops you from supporting both: a constructor with defaults
   that fall back to environment variables, auto-discovered for the common
   case, still explicitly constructible when a caller wants to pass
   config directly.

4. `pip install` your plugin package alongside `scan-gateway`. That's it --
   no code change required in `scan-gateway` itself.

The `"scan_gateway.scanners"` entry-point group name is a stable public
contract. It will not change in a way that breaks existing plugins without
a major version bump.

## What ships built-in, and why

| Scanner | Built-in? | Auto-discovered? |
|---|---|---|
| `scanners.clamav.ClamAVScanner` | Yes | No -- needs runtime host/port, same constraint any plugin needing real secrets has |
| `scanners.local_heuristic.LocalHeuristicScanner` | Yes, and not swappable via entry points | N/A -- it's the fallback `ScanGateway` always has, not a plugin slot |

**ClamAV** ships in the box because it's the obvious, free, well-known
default -- but it's wired the same way any third-party plugin needing
secrets would be: explicit construction with its own host/port/timeout,
passed into `ScanGateway(scanners=[...])`. It deliberately does *not*
register itself via the entry-point mechanism, since that mechanism exists
to solve "code `scan-gateway` doesn't know about at import time" -- and
`scan-gateway` does know about its own bundled `ClamAVScanner`.

**The local heuristic fallback is intentionally not pluggable.** It's the
one check every caller is guaranteed to get when nothing else could run --
letting it be swapped via a `pip install` would mean one bad or malicious
plugin package could silently disable the only guaranteed scan for anyone
who installs it. If you genuinely need to replace it (e.g. in tests), use
the explicit, auditable `ScanGateway(fallback=my_scanner)` constructor
override -- a code-level decision, not something a package index can
change out from under a deployment.

## Exceptions

| Exception | Meaning | Who raises it |
|---|---|---|
| `ScanGatewayError` | Base class for everything this package raises | -- |
| `ThreatDetectedError` | A scanner positively flagged the file. Carries `.scanner_name` and `.verdict` | Any `Scanner` |
| `ScannerUnavailableError` | A scanner couldn't complete the scan for operational reasons. Carries `.scanner_name` and `.reason` | Any `Scanner`; caught internally by `ScanGateway`, not expected to reach your code directly |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for dev setup, commit conventions
(required for automated releases), and what belongs in core vs. a scanner
module.

## Development

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pip install -e tests/fixtures/plugins   # enables the real-plugin discovery test
ruff check .
pytest
```

The one integration test that needs a real `clamd` instance
(`tests/integration/test_clamav_live.py`) is skipped unless
`SCAN_GATEWAY_TEST_CLAMD_HOST` is set.

## Releasing

Releases are fully automated from [Conventional Commits](https://www.conventionalcommits.org/)
on `main`:

1. [release-please](https://github.com/googleapis/release-please) watches
   every push to `main`, computes the next version from commit prefixes
   (`feat:` → minor, `fix:` → patch, `BREAKING CHANGE:`/`!` → major), and
   keeps a standing "release PR" with the version bump and generated
   `CHANGELOG.md` up to date.
2. Merging that release PR creates a GitHub Release + tag.
3. The Release publishing triggers `.github/workflows/python-publish.yml`,
   which builds the sdist/wheel and publishes to PyPI via [Trusted
   Publishing](https://docs.pypi.org/trusted-publishers/) (OIDC) -- no
   stored API token.

This means every commit to `main` should use a Conventional Commits prefix
for version bumps to compute correctly.
