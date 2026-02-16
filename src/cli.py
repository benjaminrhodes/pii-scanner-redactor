"""CLI interface."""

import argparse
import sys
from pathlib import Path
from typing import Optional

from src.detector import detect_pii
from src.redactor import redact_text


def scan_file(filepath: str) -> str:
    """Scan a file for PII."""
    path = Path(filepath)
    if not path.exists():
        return f"Error: File {filepath} not found"

    content = path.read_text()
    detections = detect_pii(content)

    if not detections:
        return f"{filepath}: No PII detected"

    lines = [f"{filepath}:"]
    for detection in detections:
        lines.append(f"  {detection.pii_type.name}: {detection.value} (position {detection.start})")

    return "\n".join(lines)


def redact_file(filepath: str) -> str:
    """Redact PII from a file."""
    path = Path(filepath)
    if not path.exists():
        return f"Error: File {filepath} not found"

    content = path.read_text()
    redacted = redact_text(content)

    return redacted


def main(argv: Optional[list] = None) -> int:
    """Main CLI entry point."""
    if argv is None:
        argv = []
    parser = argparse.ArgumentParser(
        description="PII Scanner and Redactor - Detect and redact PII from text files"
    )
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    scan_parser = subparsers.add_parser("scan", help="Scan file for PII")
    scan_parser.add_argument("file", help="File to scan")

    redact_parser = subparsers.add_parser("redact", help="Redact PII from file")
    redact_parser.add_argument("file", help="File to redact")
    redact_parser.add_argument("-o", "--output", help="Output file (default: stdout)")

    args = parser.parse_args(argv)

    if args.command == "scan":
        result = scan_file(args.file)
        print(result)
    elif args.command == "redact":
        result = redact_file(args.file)
        if args.output:
            Path(args.output).write_text(result)
            print(f"Redacted content written to {args.output}")
        else:
            print(result)
    else:
        parser.print_help()

    return 0


if __name__ == "__main__":
    sys.exit(main())
