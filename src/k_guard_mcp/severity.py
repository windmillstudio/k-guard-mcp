from __future__ import annotations

SEVERITIES = ("critical", "high", "medium", "low", "info")
CONFIDENCES = ("high", "medium", "low")
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def validate_severity(value: str) -> str:
    if value not in SEVERITIES:
        raise ValueError(f"Invalid severity {value!r}; expected one of {SEVERITIES}")
    return value


def validate_confidence(value: str) -> str:
    if value not in CONFIDENCES:
        raise ValueError(f"Invalid confidence {value!r}; expected one of {CONFIDENCES}")
    return value


def severity_rank(value: str) -> int:
    return SEVERITY_RANK[validate_severity(value)]

