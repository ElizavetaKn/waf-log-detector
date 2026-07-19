from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from urllib.parse import unquote_plus


@dataclass(frozen=True)
class Detection:
    rule_id: str
    category: str
    severity: str
    request: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


RULES: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
    (
        "WAF_SQLI_001",
        "sql_injection",
        "high",
        re.compile(r"(?i)(\bunion\b\s+\bselect\b|\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|sleep\s*\()"),
    ),
    (
        "WAF_XSS_001",
        "xss",
        "high",
        re.compile(r"(?i)(<\s*script\b|javascript\s*:|onerror\s*=|onload\s*=)"),
    ),
    (
        "WAF_TRAVERSAL_001",
        "path_traversal",
        "high",
        re.compile(r"(?i)(\.\./|\.\.\\|/etc/passwd|windows/system32)"),
    ),
    (
        "WAF_CMDI_001",
        "command_injection",
        "critical",
        re.compile(r"(?i)(;\s*(cat|whoami|id|uname)\b|\|\s*(cat|whoami|id|uname)\b)"),
    ),
)


def inspect_request(request: str) -> list[Detection]:
    normalized = unquote_plus(request)
    detections: list[Detection] = []
    for rule_id, category, severity, pattern in RULES:
        if pattern.search(normalized):
            detections.append(
                Detection(
                    rule_id=rule_id,
                    category=category,
                    severity=severity,
                    request=request,
                )
            )
    return detections
