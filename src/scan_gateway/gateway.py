"""The orchestrator: tries explicitly-registered scanners (in order), then
any auto-discovered plugins, falling back to the built-in local heuristic
scanner when none of them can complete a scan."""

import logging
from pathlib import Path

from scan_gateway.discovery import discover_scanner_plugins
from scan_gateway.exceptions import ScannerUnavailableError
from scan_gateway.protocol import Scanner
from scan_gateway.scanners.local_heuristic import LocalHeuristicScanner

logger = logging.getLogger(__name__)


class ScanGateway:
    def __init__(
        self,
        scanners: list[Scanner] | None = None,
        *,
        discover_plugins: bool = True,
        fallback: Scanner | None = None,
    ):
        """`scanners` are explicitly-registered instances -- e.g. this app's
        own ClamAVScanner, constructed with real host/port/secrets -- and
        run first, in the given order. When `discover_plugins` is True
        (default), third-party plugins registered under the
        "scan_gateway.scanners" entry-point group are appended after them,
        in whatever order importlib.metadata returns (not guaranteed
        stable). `fallback` overrides the built-in local heuristic scanner;
        almost never needed outside tests."""
        self._scanners: list[Scanner] = list(scanners or [])
        if discover_plugins:
            self._scanners.extend(discover_scanner_plugins())
        self._fallback = fallback or LocalHeuristicScanner()

    async def scan(self, path: Path) -> None:
        """Raise ThreatDetectedError if `path` is flagged by any configured
        scanner or, failing that, the built-in local fallback.
        ScannerUnavailableError from the fallback itself propagates
        uncaught -- if nothing could scan the file at all, that's a hard
        failure for the caller to decide about, not a silent pass. Clean
        returns None -- callers don't need to know which layer scanned it."""
        for scanner in self._scanners:
            try:
                await scanner.scan(path)
                return  # first clean/flagged outcome wins -- no need to run the rest
            except ScannerUnavailableError as exc:
                logger.warning("scanner %r unavailable (%s), trying next", scanner.name, exc.reason)
                continue

        if self._scanners:
            logger.warning("no configured scanner could complete a scan for %s, using local fallback", path)
        else:
            logger.info("no scanner configured, using local fallback scan for %s", path)
        await self._fallback.scan(path)
