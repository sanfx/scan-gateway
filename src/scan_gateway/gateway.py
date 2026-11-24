"""The orchestrator: tries explicitly-registered scanners (in order), then
any auto-discovered plugins, falling back to the built-in local heuristic
scanner when none of them can complete a scan."""

import logging
from collections.abc import Callable
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
        on_degraded: Callable[[str, str], None] | None = None,
    ):
        """Build an orchestrator over explicit and/or auto-discovered scanners.

        Args:
            scanners: Explicitly-registered instances -- e.g. this app's own
                ClamAVScanner, constructed with real host/port/secrets --
                run first, in the given order.
            discover_plugins: When True (default), third-party plugins
                registered under the "scan_gateway.scanners" entry-point
                group are appended after `scanners`, in whatever order
                importlib.metadata returns (not guaranteed stable).
            fallback: Overrides the built-in local heuristic scanner;
                almost never needed outside tests.
            on_degraded: Optional callback invoked as `(scanner_name, reason)`
                each time a configured scanner raises ScannerUnavailableError
                and scanning falls through to the next scanner / the local
                fallback. Synchronous and best-effort -- an exception raised
                by the callback itself is logged and swallowed, never
                allowed to turn a successful fallback scan into a failure.
                Lets a consumer surface "a scanner has been down for N
                scans" as its own metric/alert without this package needing
                to know about any particular metrics backend.

        Returns:
            None.
        """
        self._scanners: list[Scanner] = list(scanners or [])
        if discover_plugins:
            self._scanners.extend(discover_scanner_plugins())
        self._fallback = fallback or LocalHeuristicScanner()
        self._on_degraded = on_degraded

    async def scan(self, path: Path) -> None:
        """Scan `path` through every configured scanner, falling back to the
        built-in local scanner when none of them can complete the scan.

        Args:
            path: Filesystem path of the file to scan.

        Returns:
            None if the file is clean -- callers don't need to know which
            layer scanned it.

        Raises:
            ThreatDetectedError: If any configured scanner or the fallback
                flags the file.
            ScannerUnavailableError: If the fallback itself can't complete
                the scan -- propagates uncaught, since that means nothing
                could scan the file at all, a hard failure for the caller
                to decide about, not a silent pass.
        """
        for scanner in self._scanners:
            try:
                await scanner.scan(path)
                return  # first clean/flagged outcome wins -- no need to run the rest
            except ScannerUnavailableError as exc:
                logger.warning("scanner %r unavailable (%s), trying next", scanner.name, exc.reason)
                if self._on_degraded is not None:
                    try:
                        self._on_degraded(scanner.name, exc.reason)
                    except Exception:
                        logger.exception("on_degraded callback raised; ignoring")
                continue

        if self._scanners:
            logger.warning(
                "no configured scanner could complete a scan for %s, using local fallback", path
            )
        else:
            logger.info("no scanner configured, using local fallback scan for %s", path)
        await self._fallback.scan(path)
