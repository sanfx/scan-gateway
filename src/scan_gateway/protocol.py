"""The extension point third-party scan-gateway plugins implement."""

from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class Scanner(Protocol):
    """Anything with a `.name` and an async `.scan(path)` satisfies this --
    structural typing (PEP 544), not inheritance, so a third-party package
    has zero import-time coupling to scan-gateway beyond declaring its
    entry point (or being passed to ScanGateway explicitly)."""

    name: str

    async def scan(self, path: Path) -> None:
        """Raise ThreatDetectedError if `path` is flagged, or
        ScannerUnavailableError if the scan couldn't be completed for
        operational reasons. Return None if clean."""
        ...
