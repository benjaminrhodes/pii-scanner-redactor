# PII Scanner/Redactor

Detect and redact common personally identifiable information in text files.

This project is a defensive data-protection utility for privacy, DLP, and incident-response workflows. It scans text for common PII patterns, reports findings, and can produce a redacted copy for safer sharing or review.

## Why This Matters

Large organizations need to know where sensitive data appears before they can protect it. Even small scripts can reduce risk when they make sensitive data visible, mask it consistently, and keep analysts from spreading raw PII during triage.

## Security Signals

- **Domain:** Data protection, privacy engineering, DLP support
- **Risk:** Accidental exposure of SSNs, emails, phone numbers, and addresses
- **Framework mapping:** NIST CSF Identify/Protect, privacy-by-design practices, data-minimization workflows
- **Portfolio signal:** I can build simple, testable controls that help teams discover and reduce sensitive-data exposure

## Features

- Detects common PII types:
  - Social Security numbers
  - Email addresses
  - US phone numbers
  - US-style street addresses
- Redacts findings with type markers such as `[SSN]` and `[EMAIL]`.
- Provides scan and redact CLI commands.
- Includes unit tests for detection, redaction, and CLI behavior.
- Uses synthetic examples only.

## Quickstart

```bash
git clone https://github.com/benjaminrhodes/pii-scanner-redactor.git
cd pii-scanner-redactor
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

Create a synthetic sample:

```bash
cat > sample.txt <<'EOF'
Customer Jane Doe can be reached at jane@example.com or 555-123-4567.
Synthetic SSN for testing: 123-45-6789.
EOF
```

Scan for PII:

```bash
python -m src.cli scan sample.txt
```

Example output:

```text
sample.txt:
  SSN: 123-45-6789 (position 96)
  EMAIL: jane@example.com (position 36)
  PHONE: 555-123-4567 (position 56)
```

Redact PII:

```bash
python -m src.cli redact sample.txt -o redacted.txt
cat redacted.txt
```

Example output:

```text
Customer Jane Doe can be reached at [EMAIL] or [PHONE].
Synthetic SSN for testing: [SSN].
```

## Use Cases and Explainer

- [Example use cases](docs/use-cases.md): log sharing, pre-commit data hygiene, and incident-triage sanitization.
- [60-second explainer script](docs/explainer-script.md): a ready-to-record script, shot list, and LinkedIn caption.

## Testing

```bash
pytest tests/ -v
ruff check .
```

## Limitations

- This is pattern-based detection; it is not a full enterprise DLP engine.
- False positives and false negatives are possible, especially with unusual formatting or international data.
- Address detection is intentionally conservative and focused on US-style examples.
- Do not run portfolio demos on real customer, employee, patient, or payment data.

## Roadmap

- Add JSON output for easier pipeline/SIEM integration.
- Add configurable allowlists and ignore patterns.
- Add confidence scoring and finding counts by PII type.
- Add support for additional regional identifiers.

## Security

See [SECURITY.md](SECURITY.md). Use synthetic test data only.

## License

MIT
