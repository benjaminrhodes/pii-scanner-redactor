"""PII detection module."""

import re
from dataclasses import dataclass
from enum import Enum
from typing import List


class PIIType(Enum):
    SSN = "ssn"
    EMAIL = "email"
    PHONE = "phone"
    ADDRESS = "address"


@dataclass
class PIIDetection:
    pii_type: PIIType
    value: str
    start: int
    end: int


SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b")
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
PHONE_PATTERN = re.compile(r"\b(?:\d{3}-)?\d{3}-\d{4}\b|\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
ADDRESS_PATTERN = re.compile(
    r"\b\d+\s+[A-Za-z]+(?:\s+[A-Za-z]+)*\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct|Circle|Cir)[,.\s]+[A-Za-z]+[,.\s]+[A-Z]{2}\s+\d{5}(?:-\d{4})?\b",
    re.IGNORECASE,
)


def detect_pii(text: str) -> List[PIIDetection]:
    """Detect PII in text."""
    results = []

    for match in SSN_PATTERN.finditer(text):
        results.append(
            PIIDetection(
                pii_type=PIIType.SSN, value=match.group(), start=match.start(), end=match.end()
            )
        )

    for match in EMAIL_PATTERN.finditer(text):
        results.append(
            PIIDetection(
                pii_type=PIIType.EMAIL, value=match.group(), start=match.start(), end=match.end()
            )
        )

    for match in PHONE_PATTERN.finditer(text):
        value = match.group()
        if not EMAIL_PATTERN.match(value):
            results.append(
                PIIDetection(
                    pii_type=PIIType.PHONE, value=value, start=match.start(), end=match.end()
                )
            )

    for match in ADDRESS_PATTERN.finditer(text):
        results.append(
            PIIDetection(
                pii_type=PIIType.ADDRESS, value=match.group(), start=match.start(), end=match.end()
            )
        )

    return results
