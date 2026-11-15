"""Unit tests for LocalHeuristicScanner against real fixture PDFs -- no
mocking needed, it's pure raw-byte/YARA matching."""

import pytest

from scan_gateway.exceptions import ThreatDetectedError
from scan_gateway.scanners.local_heuristic import LocalHeuristicScanner


async def test_clean_pdf_passes(fixtures_dir):
    scanner = LocalHeuristicScanner()
    await scanner.scan(fixtures_dir / "clean.pdf")  # no exception == clean


async def test_eicar_string_flagged_via_yara(fixtures_dir):
    scanner = LocalHeuristicScanner()
    with pytest.raises(ThreatDetectedError) as exc_info:
        await scanner.scan(fixtures_dir / "eicar.pdf")

    assert exc_info.value.scanner_name == "local-heuristic"
    assert "EICAR" in exc_info.value.verdict


async def test_js_plus_openaction_flagged(fixtures_dir):
    scanner = LocalHeuristicScanner()
    with pytest.raises(ThreatDetectedError) as exc_info:
        await scanner.scan(fixtures_dir / "js_openaction.pdf")

    assert "auto-trigger" in exc_info.value.verdict


async def test_launch_action_flagged_alone(fixtures_dir):
    scanner = LocalHeuristicScanner()
    with pytest.raises(ThreatDetectedError) as exc_info:
        await scanner.scan(fixtures_dir / "launch_action.pdf")

    assert "Launch" in exc_info.value.verdict
