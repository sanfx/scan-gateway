"""Built-in default scanner: streams a file to a clamd instance over TCP
using ClamAV's own INSTREAM protocol (not HTTP -- clamd doesn't speak
HTTP). Hand-rolled rather than the stale third-party pyclamd package --
pure stdlib asyncio/struct, no extra dependency.

Not auto-registered via entry-point discovery (see README): its host/port
are runtime configuration, not static package metadata, so the consuming
app constructs it explicitly with its own config and passes it to
ScanGateway's `scanners=[...]`, the same way it would wire any plugin
that needs secrets/hosts only known at runtime.
"""

import asyncio
import struct
from pathlib import Path

from scan_gateway.exceptions import ScannerUnavailableError, ThreatDetectedError

_CHUNK_SIZE = 1024 * 1024


class ClamAVScanner:
    name = "clamav"

    def __init__(self, host: str, port: int = 3310, timeout_seconds: float = 15):
        """Configure a scanner for a clamd instance reachable at host:port.

        Args:
            host: Hostname or IP of the clamd instance.
            port: TCP port clamd listens on. Defaults to 3310.
            timeout_seconds: Seconds to wait for a response before raising
                ScannerUnavailableError. Defaults to 15.

        Returns:
            None.
        """
        self._host = host
        self._port = port
        self._timeout_seconds = timeout_seconds

    async def scan(self, path: Path) -> None:
        """Stream `path` to clamd via INSTREAM and raise on a positive match.

        Args:
            path: Filesystem path of the file to scan.

        Returns:
            None if clamd reports the file clean.

        Raises:
            ThreatDetectedError: If clamd's verdict isn't "OK".
            ScannerUnavailableError: If the connection times out or fails,
                or clamd's response can't be parsed.
        """
        try:
            verdict = await asyncio.wait_for(
                self._scan_via_clamd(path), timeout=self._timeout_seconds
            )
        except (TimeoutError, OSError, RuntimeError) as exc:
            raise ScannerUnavailableError(
                self.name, f"{self._host}:{self._port} ({type(exc).__name__}: {exc})"
            ) from exc

        if verdict != "OK":
            raise ThreatDetectedError(self.name, verdict)

    async def _scan_via_clamd(self, path: Path) -> str:
        """Speak ClamAV's zINSTREAM protocol over a fresh TCP connection.

        Args:
            path: Filesystem path of the file to stream to clamd.

        Returns:
            str: "OK" if clean, or clamd's own FOUND/signature text if flagged.

        Raises:
            RuntimeError: If clamd's response contains neither "OK" nor "FOUND".
        """
        reader, writer = await asyncio.open_connection(self._host, self._port)
        try:
            writer.write(b"zINSTREAM\0")
            with path.open("rb") as f:
                while chunk := f.read(_CHUNK_SIZE):
                    writer.write(struct.pack("!L", len(chunk)))
                    writer.write(chunk)
                    await writer.drain()
            writer.write(struct.pack("!L", 0))  # zero-length chunk signals end of stream
            await writer.drain()
            response = await reader.read(4096)
        finally:
            writer.close()
            await writer.wait_closed()

        text = response.decode("utf-8", errors="replace").strip("\0").strip()
        if "FOUND" in text:
            return text
        if "OK" in text:
            return "OK"
        raise RuntimeError(f"unexpected ClamAV response: {text!r}")
