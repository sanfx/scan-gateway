"""A minimal, always-clean Scanner -- used only to prove that
discover_scanner_plugins() finds a real installed distribution's entry
point, not just a monkeypatched one."""

from pathlib import Path


class FakeScanner:
    name = "fake"

    async def scan(self, path: Path) -> None:
        return None
