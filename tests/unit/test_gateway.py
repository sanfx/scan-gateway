"""Unit tests for ScanGateway's ordering/fallback logic, using small fake
Scanner doubles -- no real ClamAV or YARA involved."""

from pathlib import Path

import pytest

from scan_gateway.exceptions import ScannerUnavailableError, ThreatDetectedError
from scan_gateway.gateway import ScanGateway


class CleanScanner:
    def __init__(self, name: str):
        self.name = name
        self.called = False

    async def scan(self, path: Path) -> None:
        self.called = True


class FlaggingScanner:
    def __init__(self, name: str, verdict: str = "test-verdict"):
        self.name = name
        self.verdict = verdict
        self.called = False

    async def scan(self, path: Path) -> None:
        self.called = True
        raise ThreatDetectedError(self.name, self.verdict)


class UnavailableScanner:
    def __init__(self, name: str):
        self.name = name
        self.called = False

    async def scan(self, path: Path) -> None:
        self.called = True
        raise ScannerUnavailableError(self.name, "connection refused")


async def test_first_clean_scanner_short_circuits(tmp_path):
    first = CleanScanner("first")
    second = CleanScanner("second")
    gateway = ScanGateway(scanners=[first, second], discover_plugins=False)

    await gateway.scan(tmp_path / "f.pdf")

    assert first.called
    assert not second.called


async def test_threat_detected_propagates_immediately(tmp_path):
    flagging = FlaggingScanner("bad", verdict="EICAR")
    never_reached = CleanScanner("never")
    gateway = ScanGateway(scanners=[flagging, never_reached], discover_plugins=False)

    with pytest.raises(ThreatDetectedError) as exc_info:
        await gateway.scan(tmp_path / "f.pdf")

    assert exc_info.value.scanner_name == "bad"
    assert exc_info.value.verdict == "EICAR"
    assert not never_reached.called


async def test_unavailable_scanner_falls_through_to_next(tmp_path):
    unavailable = UnavailableScanner("down")
    clean = CleanScanner("up")
    gateway = ScanGateway(scanners=[unavailable, clean], discover_plugins=False)

    await gateway.scan(tmp_path / "f.pdf")

    assert unavailable.called
    assert clean.called


async def test_all_scanners_unavailable_uses_builtin_fallback(tmp_path):
    unavailable = UnavailableScanner("down")
    fallback = CleanScanner("fallback")
    gateway = ScanGateway(scanners=[unavailable], discover_plugins=False, fallback=fallback)

    await gateway.scan(tmp_path / "f.pdf")

    assert fallback.called


async def test_no_scanners_configured_uses_fallback_directly(tmp_path):
    fallback = CleanScanner("fallback")
    gateway = ScanGateway(discover_plugins=False, fallback=fallback)

    await gateway.scan(tmp_path / "f.pdf")

    assert fallback.called


async def test_discover_plugins_false_disables_discovery(tmp_path, monkeypatch):
    def _boom():
        raise AssertionError("discover_scanner_plugins should not be called")

    monkeypatch.setattr("scan_gateway.gateway.discover_scanner_plugins", _boom)
    fallback = CleanScanner("fallback")

    gateway = ScanGateway(discover_plugins=False, fallback=fallback)
    await gateway.scan(tmp_path / "f.pdf")

    assert fallback.called


async def test_on_degraded_called_with_scanner_name_and_reason(tmp_path):
    calls = []
    unavailable = UnavailableScanner("down")
    clean = CleanScanner("up")
    gateway = ScanGateway(
        scanners=[unavailable, clean],
        discover_plugins=False,
        on_degraded=lambda name, reason: calls.append((name, reason)),
    )

    await gateway.scan(tmp_path / "f.pdf")

    assert calls == [("down", "connection refused")]


async def test_on_degraded_not_called_when_first_scanner_succeeds(tmp_path):
    calls = []
    clean = CleanScanner("up")
    gateway = ScanGateway(
        scanners=[clean], discover_plugins=False, on_degraded=lambda *args: calls.append(args)
    )

    await gateway.scan(tmp_path / "f.pdf")

    assert calls == []


async def test_on_degraded_exception_does_not_break_fallback_scan(tmp_path):
    unavailable = UnavailableScanner("down")
    fallback = CleanScanner("fallback")

    def _boom(scanner_name, reason):
        raise RuntimeError("metrics backend down too")

    gateway = ScanGateway(
        scanners=[unavailable], discover_plugins=False, fallback=fallback, on_degraded=_boom
    )

    await gateway.scan(tmp_path / "f.pdf")  # must not raise

    assert fallback.called


async def test_explicit_scanners_run_before_discovered_plugins(tmp_path, monkeypatch):
    explicit = CleanScanner("explicit")
    discovered = CleanScanner("discovered")
    monkeypatch.setattr("scan_gateway.gateway.discover_scanner_plugins", lambda: [discovered])

    gateway = ScanGateway(scanners=[explicit], discover_plugins=True)
    assert gateway._scanners == [explicit, discovered]

    await gateway.scan(tmp_path / "f.pdf")
    assert explicit.called
    assert not discovered.called  # explicit one already returned clean
