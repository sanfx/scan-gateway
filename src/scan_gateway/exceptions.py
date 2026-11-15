"""Exception hierarchy raised by scan-gateway and its scanners.

Convention: `Scanner.scan(path)` returns None when clean, raises
ThreatDetectedError when something flags it, and raises
ScannerUnavailableError when the scanner couldn't complete the scan for
operational reasons (unreachable, timed out, malformed response) --
distinct from "flagged" so ScanGateway knows to try the next scanner /
fall back, rather than rejecting the file.
"""


class ScanGatewayError(Exception):
    """Base class for every exception this package raises."""


class ThreatDetectedError(ScanGatewayError):
    """Raised when a scanner positively flags a file.

    `scanner_name` (that scanner's `.name`) and `verdict` (its own
    description of what it found) are both exposed so a consuming app can
    log/debug which plugin flagged something without knowing scan-gateway's
    internals."""

    def __init__(self, scanner_name: str, verdict: str):
        """Initialize with the flagging scanner's name and its verdict.

        Args:
            scanner_name: The flagging Scanner's `.name`.
            verdict: That scanner's own description of what it found.

        Returns:
            None.
        """
        self.scanner_name = scanner_name
        self.verdict = verdict
        super().__init__(f"{scanner_name} flagged: {verdict}")


class ScannerUnavailableError(ScanGatewayError):
    """Raised by a Scanner when it can't complete a scan for operational
    reasons (connection refused, timeout, unparseable response, etc).
    Caught internally by ScanGateway to try the next scanner / fall back --
    not expected to reach the consuming app directly."""

    def __init__(self, scanner_name: str, reason: str):
        """Initialize with the unavailable scanner's name and why.

        Args:
            scanner_name: The unavailable Scanner's `.name`.
            reason: A human-readable description of why the scan couldn't
                be completed (e.g. a connection error or timeout message).

        Returns:
            None.
        """
        self.scanner_name = scanner_name
        self.reason = reason
        super().__init__(f"{scanner_name} unavailable: {reason}")
