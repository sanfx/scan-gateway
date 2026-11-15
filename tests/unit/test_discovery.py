"""Unit tests for discover_scanner_plugins() -- both via a monkeypatched
entry_points() (fast, no real package installed) and against the real,
installed tests/fixtures/plugins package (proves genuine distribution-
based discovery, not just the monkeypatched path)."""

from importlib.metadata import EntryPoint, entry_points

import pytest

from scan_gateway.discovery import ENTRY_POINT_GROUP, discover_scanner_plugins

_fake_plugin_installed = any(ep.name == "fake" for ep in entry_points(group=ENTRY_POINT_GROUP))


def test_loads_a_valid_entry_point(monkeypatch):
    ep = EntryPoint(
        name="dummy",
        value="tests.unit.test_discovery:_DummyScannerFactory",
        group=ENTRY_POINT_GROUP,
    )
    monkeypatch.setattr(
        "scan_gateway.discovery.entry_points",
        lambda group: [ep] if group == ENTRY_POINT_GROUP else [],
    )

    discovered = discover_scanner_plugins()

    assert len(discovered) == 1
    assert discovered[0].name == "dummy-scanner"


def test_skips_an_entry_point_that_fails_to_load(monkeypatch):
    broken = EntryPoint(
        name="broken", value="nonexistent.module:DoesNotExist", group=ENTRY_POINT_GROUP
    )
    good = EntryPoint(
        name="dummy",
        value="tests.unit.test_discovery:_DummyScannerFactory",
        group=ENTRY_POINT_GROUP,
    )
    monkeypatch.setattr(
        "scan_gateway.discovery.entry_points",
        lambda group: [broken, good] if group == ENTRY_POINT_GROUP else [],
    )

    discovered = discover_scanner_plugins()

    assert len(discovered) == 1
    assert discovered[0].name == "dummy-scanner"


@pytest.mark.skipif(
    not _fake_plugin_installed,
    reason="tests/fixtures/plugins not installed -- run `pip install -e tests/fixtures/plugins`",
)
def test_discovers_a_real_installed_plugin_package():
    # Requires `pip install -e tests/fixtures/plugins` (see README's dev
    # setup) -- proves discovery against an actually-installed
    # distribution's entry-point metadata, not just a monkeypatched one.
    discovered = discover_scanner_plugins()
    names = [s.name for s in discovered]
    assert "fake" in names


class _DummyScanner:
    name = "dummy-scanner"

    async def scan(self, path):
        return None


def _DummyScannerFactory():
    return _DummyScanner()
