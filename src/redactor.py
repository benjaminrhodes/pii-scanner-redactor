"""PII redaction module."""


from src.detector import PIIType, detect_pii


def redact_text(text: str) -> str:
    """Redact all PII from text."""
    detections = detect_pii(text)
    detections.sort(key=lambda x: x.start, reverse=True)

    result = text
    for detection in detections:
        replacement = f"[{detection.pii_type.name}]"
        result = result[: detection.start] + replacement + result[detection.end :]

    return result


def redact_pii(text: str, pii_type: PIIType) -> str:
    """Redact specific PII type from text."""
    detections = [d for d in detect_pii(text) if d.pii_type == pii_type]
    detections.sort(key=lambda x: x.start, reverse=True)

    result = text
    for detection in detections:
        replacement = f"[{detection.pii_type.name}]"
        result = result[: detection.start] + replacement + result[detection.end :]

    return result
