"""Unit tests for ClamAVScanner -- fake reader/writer doubles over
asyncio.open_connection, no real clamd needed."""

import asyncio

import pytest

from scan_gateway.exceptions import ScannerUnavailableError, ThreatDetectedError
from scan_gateway.scanners.clamav import ClamAVScanner


class _FakeWriter:
    def __init__(self):
        self.written = bytearray()
        self.closed = False

    def write(self, data: bytes) -> None:
        self.written.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


class _FakeReader:
    def __init__(self, response: bytes):
        self._response = response

    async def read(self, n: int) -> bytes:
        return self._response


async def _patch_connection(monkeypatch, response: bytes):
    writer = _FakeWriter()
    reader = _FakeReader(response)

    async def _fake_open_connection(host, port):
        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", _fake_open_connection)
    return reader, writer


async def test_clean_response_returns_none(tmp_path, monkeypatch):
    await _patch_connection(monkeypatch, b"stream: OK\0")
    path = tmp_path / "f.pdf"
    path.write_bytes(b"hello")

    scanner = ClamAVScanner(host="clamd.local")
    await scanner.scan(path)  # no exception == clean


async def test_found_response_raises_threat_detected(tmp_path, monkeypatch):
    await _patch_connection(monkeypatch, b"stream: Eicar-Test-Signature FOUND\0")
    path = tmp_path / "f.pdf"
    path.write_bytes(b"hello")

    scanner = ClamAVScanner(host="clamd.local")
    with pytest.raises(ThreatDetectedError) as exc_info:
        await scanner.scan(path)

    assert exc_info.value.scanner_name == "clamav"
    assert "FOUND" in exc_info.value.verdict


async def test_unparseable_response_raises_unavailable(tmp_path, monkeypatch):
    await _patch_connection(monkeypatch, b"garbage\0")
    path = tmp_path / "f.pdf"
    path.write_bytes(b"hello")

    scanner = ClamAVScanner(host="clamd.local")
    with pytest.raises(ScannerUnavailableError) as exc_info:
        await scanner.scan(path)

    assert exc_info.value.scanner_name == "clamav"


async def test_connection_refused_raises_unavailable(tmp_path, monkeypatch):
    async def _refused(host, port):
        raise OSError("connection refused")

    monkeypatch.setattr(asyncio, "open_connection", _refused)
    path = tmp_path / "f.pdf"
    path.write_bytes(b"hello")

    scanner = ClamAVScanner(host="clamd.local")
    with pytest.raises(ScannerUnavailableError):
        await scanner.scan(path)


async def test_timeout_raises_unavailable(tmp_path, monkeypatch):
    async def _hangs(host, port):
        await asyncio.sleep(10)

    monkeypatch.setattr(asyncio, "open_connection", _hangs)
    path = tmp_path / "f.pdf"
    path.write_bytes(b"hello")

    scanner = ClamAVScanner(host="clamd.local", timeout_seconds=0.05)
    with pytest.raises(ScannerUnavailableError):
        await scanner.scan(path)
