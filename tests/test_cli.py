"""Tests for CLI interface."""

from src.cli import main, scan_file, redact_file


class TestCLI:
    """Test CLI commands."""

    def test_main_returns_zero(self):
        assert main([]) == 0

    def test_scan_file_detects_pii(self, tmp_path):
        test_file = tmp_path / "test.txt"
        test_file.write_text("Contact john@example.com")

        result = scan_file(str(test_file))
        assert "EMAIL" in result
        assert "john@example.com" in result

    def test_redact_file_redacts_pii(self, tmp_path):
        test_file = tmp_path / "test.txt"
        test_file.write_text("Contact john@example.com")

        result = redact_file(str(test_file))
        assert "john@example.com" not in result
        assert "[EMAIL]" in result

    def test_scan_file_no_pii(self, tmp_path):
        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello world")

        result = scan_file(str(test_file))
        assert "No PII detected" in result
