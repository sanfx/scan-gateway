"""Built-in, always-available fallback scanner: YARA pattern matching plus a
PDF-structural auto-trigger check. No network/daemon dependency -- this is
what ScanGateway falls back to when no configured scanner could complete a
scan (none configured, or all unreachable). Narrower coverage than a real
scanner plugin, not a replacement -- see README.
"""

import logging
from pathlib import Path

import pikepdf
import yara

from scan_gateway.exceptions import ThreatDetectedError

logger = logging.getLogger(__name__)

_RULES_PATH = Path(__file__).parent / "rules" / "suspicious_pdf.yar"
_rules = yara.compile(filepath=str(_RULES_PATH))

# /Launch (launch an external program) is rare enough in legitimate PDFs to
# flag on its own -- deliberately left as a standalone raw-byte check, not
# part of the structural check below, and not implicated in the false
# positives that check used to produce (see _SCRIPT_KEYWORDS below).
_LAUNCH_KEYWORD = b"/Launch"

# Fallback-only raw-byte keyword search (pdfid-style). Used only when the
# structural check below can't parse the file at all (e.g. a corrupt or
# encrypted PDF) -- a parse failure shouldn't silently skip this check
# entirely. A raw-byte match on these short tokens is prone to coincidental
# hits inside compressed binary image/font stream data with no relation to
# real PDF syntax, which is exactly why the structural check exists.
_SCRIPT_KEYWORDS = (b"/JavaScript", b"/JS")
_AUTOTRIGGER_KEYWORDS = (b"/OpenAction", b"/AA")


def _is_script_action(obj: object) -> bool:
    """True if `obj` is a genuine `<< /S /JavaScript /JS (...) >>` action
    dictionary -- not just a PDF object that happens to contain the bytes
    "/JS" somewhere (e.g. inside compressed image/font stream data, which a
    raw-byte search can't tell apart from real PDF syntax)."""
    return isinstance(obj, pikepdf.Dictionary) and obj.get("/S") == pikepdf.Name("/JavaScript")


def _is_action(obj: object) -> bool:
    """True if `obj` is any action dictionary (has an `/S` subtype key) --
    used to tell a genuine auto-trigger action apart from, e.g., an
    `/OpenAction` that's actually just a destination array like
    `[page /XYZ null null 0]` ("open to this page/zoom"), which every major
    PDF exporter (Word, LibreOffice, etc.) writes and which runs no code."""
    return isinstance(obj, pikepdf.Dictionary) and "/S" in obj


def _has_reachable_autotrigger_action(pdf: pikepdf.Pdf) -> bool:
    """True if the Catalog's /OpenAction, the Catalog's /AA, or any page's
    /AA resolves to a genuine action dictionary. Deliberately does not walk
    into annotations' own /AA -- out of scope for this check, same as
    before."""
    catalog = pdf.Root
    open_action = catalog.get("/OpenAction")
    if open_action is not None and _is_action(open_action):
        return True

    for aa in (catalog.get("/AA"), *(page.get("/AA") for page in pdf.pages)):
        if isinstance(aa, pikepdf.Dictionary) and any(_is_action(v) for v in aa.values()):
            return True

    return False


def _has_script_object(pdf: pikepdf.Pdf) -> bool:
    """True if any object anywhere in the file is a genuine script action --
    not necessarily the same object an auto-trigger points at (matches this
    check's original, deliberately broad intent: "script capability
    combined with something that auto-triggers it", not full correlation).
    Walking `pdf.objects` also transparently decompresses object streams,
    closing a gap the old raw-byte scan had (content hidden inside a
    compressed object stream could evade it)."""
    return any(_is_script_action(obj) for obj in pdf.objects)


def _structural_script_paired_with_autotrigger(path: Path) -> bool | None:
    """Returns the real answer if the file could be parsed, or None if it
    couldn't be opened at all -- the caller falls back to the raw-byte
    check in that case."""
    try:
        with pikepdf.open(path) as pdf:
            return _has_script_object(pdf) and _has_reachable_autotrigger_action(pdf)
    except pikepdf.PikepdfError:
        logger.warning(
            "local-heuristic: couldn't structurally parse %s, falling back to raw-byte check", path
        )
        return None


class LocalHeuristicScanner:
    name = "local-heuristic"

    async def scan(self, path: Path) -> None:
        """Check `path` against the bundled YARA rules and keyword heuristics.

        Args:
            path: Filesystem path of the file to scan.

        Returns:
            None if nothing matches.

        Raises:
            ThreatDetectedError: If a YARA rule matches, a `/Launch` action
                is present, or a script action is paired with a reachable
                auto-trigger action.
        """
        data = path.read_bytes()

        matches = _rules.match(data=data)
        if matches:
            rule_names = ", ".join(m.rule for m in matches)
            raise ThreatDetectedError(self.name, f"YARA: {rule_names}")

        if _LAUNCH_KEYWORD in data:
            raise ThreatDetectedError(self.name, "/Launch action present")

        paired = _structural_script_paired_with_autotrigger(path)
        if paired is None:
            has_script = any(k in data for k in _SCRIPT_KEYWORDS)
            has_autotrigger = any(k in data for k in _AUTOTRIGGER_KEYWORDS)
            paired = has_script and has_autotrigger

        if paired:
            raise ThreatDetectedError(self.name, "script action paired with an auto-trigger action")
