# Contributing to scan-gateway

Thanks for considering a contribution. This file covers *working on
scan-gateway itself* (the core package: `ScanGateway`, the built-in
scanners, discovery). If you just want to **write a scanner plugin**, you
don't need any of this — see the [README's "Writing a scanner
plugin"](README.md#writing-a-scanner-plugin) section instead; a plugin is
its own separate package and doesn't touch this repo at all.

## Dev setup

```bash
git clone https://github.com/sanfx/scan-gateway.git
cd scan-gateway
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pip install -e tests/fixtures/plugins   # enables the real-plugin discovery test
```

## Running checks

```bash
ruff check .          # lint
ruff format .         # auto-format (run before committing)
pytest                # full suite -- the one real-clamd test auto-skips
                      # unless SCAN_GATEWAY_TEST_CLAMD_HOST is set
```

All three must pass before opening a PR. CI runs the same checks.

## Commit messages: Conventional Commits are required

Releases are fully automated by [release-please](https://github.com/googleapis/release-please),
which reads commit prefixes on `main` to decide the next version and
generate `CHANGELOG.md`. Every commit (or at minimum, every squashed PR
title) must use one of:

| Prefix | Effect |
|---|---|
| `fix: ...` | patch release (0.1.0 → 0.1.1) |
| `feat: ...` | minor release (0.1.0 → 0.2.0) |
| `feat!: ...` or a `BREAKING CHANGE:` footer | major release (0.1.0 → 1.0.0) |
| `chore:`, `docs:`, `test:`, `refactor:`, `ci:` | no release triggered on their own |

A PR with a non-conforming title/commits will still merge, but won't
produce the version bump you might expect -- match the prefix to what
actually changed.

## What belongs in core vs. a scanner module

- **`protocol.py`, `exceptions.py`, `gateway.py`, `discovery.py`** -- the
  orchestration mechanism itself. Changes here affect every scanner,
  built-in or third-party, so they need the strongest justification and
  the most test coverage. In particular:
  - The `"scan_gateway.scanners"` entry-point group name
    (`discovery.py`) is a stable public contract -- don't rename it
    without a major-version bump and a clear migration note.
  - `LocalHeuristicScanner` being non-pluggable is a deliberate security
    decision (see the README's "What ships built-in, and why" section),
    not an oversight -- a PR trying to make it swappable via entry points
    needs to address that reasoning directly, not route around it.
- **`scanners/clamav.py`** -- the one bundled real scanner. Bug fixes and
  protocol-correctness improvements are welcome; it should stay a thin,
  dependency-free (stdlib-only) INSTREAM client, not grow ClamAV features
  unrelated to the scan/verdict path this package cares about.
- **`scanners/local_heuristic.py` + `scanners/rules/suspicious_pdf.yar`**
  -- the built-in fallback. Because it's not swappable, a change here
  affects every consumer that doesn't configure its own scanner. New
  YARA rules or keyword heuristics should be conservative (prefer missing
  a detection over false-flagging a legitimate file) -- this layer exists
  specifically because it runs even when nothing else is configured, so a
  false positive here has no second opinion to fall back on.
- **A genuinely new built-in scanner** (not ClamAV, not the heuristic
  fallback) is a bigger discussion than a typical PR -- open an issue
  first. The expectation is that most new scanners should be third-party
  plugins, not additions to this repo.

## Tests

- Unit tests (`tests/unit/`) should never need a real network service.
  `ClamAVScanner` is tested via fake `asyncio.open_connection` doubles
  (see `test_clamav_scanner.py`); `discover_scanner_plugins()` is tested
  both via a monkeypatched `entry_points()` and the real, installed
  `tests/fixtures/plugins` package (proves genuine distribution-based
  discovery, not just the mocked path).
- `tests/integration/test_clamav_live.py` is the one exception -- it
  needs a real `clamd` and is skip-gated on `SCAN_GATEWAY_TEST_CLAMD_HOST`
  being set. Don't make more tests depend on a real service without the
  same explicit opt-in gating.
- New behavior needs a new test in the same file/style as its neighbors,
  not a separate ad hoc script.

## Pull requests

1. One logical change per PR -- a scanner fix and a discovery-mechanism
   change are two PRs, not one.
2. Update the README if you change anything a plugin author or a
   consumer of `ScanGateway` would notice (new constructor arg, changed
   exception behavior, etc).
3. CI (lint + tests) must pass before merge.
4. Use a Conventional Commits–formatted PR title -- that's what
   release-please actually reads when the PR is squash-merged.
