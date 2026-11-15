"""Exercises ClamAVScanner against a real clamd instance. Unlike a local
binary (e.g. Ghostscript's `shutil.which("gs")`), there's no local
executable to probe for -- clamd is a remote daemon -- so this is gated on
an explicit env var instead, set only where a real instance is reachable
(e.g. a CI job with VPN access, or manually with the VPN up)."""

import os
import socket

import pytest

from scan_gateway.exceptions import ThreatDetectedError
from scan_gateway.scanners.clamav import ClamAVScanner

_CLAMD_HOST = os.environ.get("SCAN_GATEWAY_TEST_CLAMD_HOST")
_CLAMD_PORT = int(os.environ.get("SCAN_GATEWAY_TEST_CLAMD_PORT", "3310"))


def _clamd_reachable() -> bool:
    if not _CLAMD_HOST:
        return False
    try:
        with socket.create_connection((_CLAMD_HOST, _CLAMD_PORT), timeout=1):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not _clamd_reachable(),
    reason="no real clamd reachable (set SCAN_GATEWAY_TEST_CLAMD_HOST to run)",
)


async def test_eicar_flagged_by_real_clamav(tmp_path):
    eicar_bytes = (
        rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )
    path = tmp_path / "eicar.txt"
    path.write_bytes(eicar_bytes)

    scanner = ClamAVScanner(host=_CLAMD_HOST, port=_CLAMD_PORT)
    with pytest.raises(ThreatDetectedError):
        await scanner.scan(path)
