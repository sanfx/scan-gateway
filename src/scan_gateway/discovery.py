"""importlib.metadata-based discovery for third-party scan-gateway plugins."""

import logging
from importlib.metadata import entry_points

from scan_gateway.protocol import Scanner

ENTRY_POINT_GROUP = "scan_gateway.scanners"

logger = logging.getLogger(__name__)


def discover_scanner_plugins() -> list[Scanner]:
    """Load every Scanner registered under the "scan_gateway.scanners" entry-point
    group. Each entry point must resolve to a zero-argument callable (a class
    with no required constructor args, or a factory function) returning a
    Scanner instance -- any config it needs (host, API key, etc) is the
    plugin's own responsibility to read, e.g. from its own environment
    variables. A plugin that fails to import or instantiate is logged and
    skipped, not fatal -- one broken third-party plugin shouldn't take down
    every scan."""
    discovered: list[Scanner] = []
    for ep in entry_points(group=ENTRY_POINT_GROUP):
        try:
            factory = ep.load()
            scanner = factory()
        except Exception:
            logger.exception("scan-gateway plugin %r (%s) failed to load, skipping", ep.name, ep.value)
            continue
        discovered.append(scanner)
    return discovered
