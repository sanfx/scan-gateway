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


async def test_benign_destination_openaction_passes(fixtures_dir):
    """Regression test for a real false positive: a plain destination-array
    /OpenAction (e.g. "open to page 1" -- written by every major PDF
    exporter) is not a script action, and incidental /JS, /AA bytes sitting
    outside any object (here, in a PDF comment) must not be treated as a
    real pairing. The old raw-byte substring check flagged this."""
    scanner = LocalHeuristicScanner()
    await scanner.scan(fixtures_dir / "benign_destination_openaction.pdf")


async def test_js_via_page_aa_flagged(fixtures_dir):
    """A script action reachable via a *page's* /AA (not just the Catalog's
    /OpenAction) must still be flagged -- the Catalog's own /OpenAction here
    is a harmless destination array, same as the benign fixture above."""
    scanner = LocalHeuristicScanner()
    with pytest.raises(ThreatDetectedError) as exc_info:
        await scanner.scan(fixtures_dir / "js_via_page_aa.pdf")

    assert "auto-trigger" in exc_info.value.verdict


async def test_falls_back_to_raw_byte_check_when_unparseable(fixtures_dir):
    """A file pikepdf can't open at all (corrupt/truncated) must not
    silently skip the script+auto-trigger check -- falls back to the
    original raw-byte scan rather than fail-open."""
    scanner = LocalHeuristicScanner()
    with pytest.raises(ThreatDetectedError) as exc_info:
        await scanner.scan(fixtures_dir / "corrupt_with_js_openaction.pdf")

    assert "auto-trigger" in exc_info.value.verdict
