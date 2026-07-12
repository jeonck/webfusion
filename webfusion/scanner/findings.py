"""Finding model and severity ordering shared by all checks."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Higher = more severe; used for --fail-on thresholds and sorting.
_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def rank(sev: Severity) -> int:
    return _ORDER[sev]


@dataclass
class Finding:
    id: str  # stable check id, e.g. "missing-csp"
    name: str
    severity: Severity
    confidence: str  # "high" | "medium" | "low"
    url: str
    evidence: str = ""
    description: str = ""
    remediation: str = ""
    cwe: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


# SARIF only has error/warning/note — map severities onto it.
def sarif_level(sev: Severity) -> str:
    if sev in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if sev is Severity.MEDIUM:
        return "warning"
    return "note"
