"""Tests for PII scanner and redactor."""

from src.detector import detect_pii, PIIType
from src.redactor import redact_text, redact_pii


class TestPIIType:
    """Test PII type enum."""

    def test_pii_type_has_ssn(self):
        assert hasattr(PIIType, "SSN")

    def test_pii_type_has_email(self):
        assert hasattr(PIIType, "EMAIL")

    def test_pii_type_has_phone(self):
        assert hasattr(PIIType, "PHONE")

    def test_pii_type_has_address(self):
        assert hasattr(PIIType, "ADDRESS")


class TestDetectPII:
    """Test PII detection."""

    def test_detect_ssn(self):
        text = "My SSN is 123-45-6789"
        results = detect_pii(text)
        pii_types = [p.pii_type for p in results]
        assert PIIType.SSN in pii_types

    def test_detect_ssn_without_dashes(self):
        text = "My SSN is 123456789"
        results = detect_pii(text)
        pii_types = [p.pii_type for p in results]
        assert PIIType.SSN in pii_types

    def test_detect_email(self):
        text = "Contact me at john@example.com"
        results = detect_pii(text)
        pii_types = [p.pii_type for p in results]
        assert PIIType.EMAIL in pii_types

    def test_detect_phone(self):
        text = "Call me at 555-123-4567"
        results = detect_pii(text)
        pii_types = [p.pii_type for p in results]
        assert PIIType.PHONE in pii_types

    def test_detect_phone_with_parentheses(self):
        text = "Call (555) 123-4567"
        results = detect_pii(text)
        pii_types = [p.pii_type for p in results]
        assert PIIType.PHONE in pii_types

    def test_detect_us_address(self):
        text = "I live at 123 Main Street, Springfield, IL 62701"
        results = detect_pii(text)
        pii_types = [p.pii_type for p in results]
        assert PIIType.ADDRESS in pii_types

    def test_no_pii_found(self):
        text = "This is just plain text"
        results = detect_pii(text)
        assert len(results) == 0

    def test_detect_multiple_pii(self):
        text = "Contact john@example.com or call 555-123-4567"
        results = detect_pii(text)
        pii_types = [p.pii_type for p in results]
        assert PIIType.EMAIL in pii_types
        assert PIIType.PHONE in pii_types


class TestRedactText:
    """Test text redaction."""

    def test_redact_ssn(self):
        text = "My SSN is 123-45-6789"
        result = redact_text(text)
        assert "123-45-6789" not in result
        assert "[SSN]" in result

    def test_redact_email(self):
        text = "Contact john@example.com"
        result = redact_text(text)
        assert "john@example.com" not in result
        assert "[EMAIL]" in result

    def test_redact_phone(self):
        text = "Call 555-123-4567"
        result = redact_text(text)
        assert "555-123-4567" not in result
        assert "[PHONE]" in result

    def test_redact_address(self):
        text = "I live at 123 Main Street, Springfield, IL 62701"
        result = redact_text(text)
        assert "123 Main Street" not in result
        assert "[ADDRESS]" in result

    def test_redact_multiple_pii(self):
        text = "Contact john@example.com or call 555-123-4567"
        result = redact_text(text)
        assert "john@example.com" not in result
        assert "555-123-4567" not in result
        assert "[EMAIL]" in result
        assert "[PHONE]" in result


class TestRedactPII:
    """Test redact_pii function."""

    def test_redact_specific_pii_type(self):
        text = "SSN: 123-45-6789, Email: john@example.com"
        result = redact_pii(text, PIIType.SSN)
        assert "123-45-6789" not in result
        assert "john@example.com" in result

    def test_redact_preserves_other_text(self):
        text = "Hello world, my SSN is 123-45-6789"
        result = redact_text(text)
        assert "Hello world, my SSN is" in result
