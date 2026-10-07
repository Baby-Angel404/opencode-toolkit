"""Multi-language security auditing.

Scans Python, JavaScript, TypeScript and Go for practical, exploitable risk
classes. Python is analysed through its AST (so ``eval(user_input)`` is caught
structurally, not by string matching); the remaining languages use
token-aware pattern rules tuned to avoid the false positives that make plain
regex scanners unusable.

Findings never contain secret values -- see :mod:`opencode_toolkit.core.redact`.
"""

from __future__ import annotations

from opencode_toolkit.security_audit.engine import AuditEngine, scan_path
from opencode_toolkit.security_audit.models import (
    SEVERITY_ORDER,
    Confidence,
    Finding,
    ScanResult,
    Severity,
)

__all__ = [
    "SEVERITY_ORDER",
    "AuditEngine",
    "Confidence",
    "Finding",
    "ScanResult",
    "Severity",
    "scan_path",
]
