"""Built-in, always-available fallback scanner: YARA pattern matching plus a
lightweight PDF-structural keyword check. No network/daemon dependency --
this is what ScanGateway falls back to when no configured scanner could
complete a scan (none configured, or all unreachable). Narrower coverage
than a real scanner plugin, not a replacement -- see README.
"""

from pathlib import Path

import yara

from scan_gateway.exceptions import ThreatDetectedError

_RULES_PATH = Path(__file__).parent / "rules" / "suspicious_pdf.yar"
_rules = yara.compile(filepath=str(_RULES_PATH))

# Raw-byte keyword search (pdfid-style), not a full object-graph walk --
# content hidden inside a compressed object stream can evade this.
# Deliberately scoped to the one pattern a pure keyword check can
# meaningfully flag: script capability combined with something that
# auto-triggers it without a click ("runs code on open"), not just
# "contains any PDF action/script feature". /Launch (launch an external
# program) is rare enough in legitimate PDFs to flag on its own.
_SCRIPT_KEYWORDS = (b"/JavaScript", b"/JS")
_AUTOTRIGGER_KEYWORDS = (b"/OpenAction", b"/AA")
_LAUNCH_KEYWORD = b"/Launch"


class LocalHeuristicScanner:
    name = "local-heuristic"

    async def scan(self, path: Path) -> None:
        data = path.read_bytes()

        matches = _rules.match(data=data)
        if matches:
            rule_names = ", ".join(m.rule for m in matches)
            raise ThreatDetectedError(self.name, f"YARA: {rule_names}")

        if _LAUNCH_KEYWORD in data:
            raise ThreatDetectedError(self.name, "/Launch action present")

        has_script = any(k in data for k in _SCRIPT_KEYWORDS)
        has_autotrigger = any(k in data for k in _AUTOTRIGGER_KEYWORDS)
        if has_script and has_autotrigger:
            raise ThreatDetectedError(self.name, "script action paired with an auto-trigger action")
