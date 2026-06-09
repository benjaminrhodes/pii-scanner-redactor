# PII Scanner/Redactor — Example Use Cases

This project demonstrates a lightweight data-protection workflow for finding and masking common PII in text files.

## Use Case 1: Redacting Sensitive Data Before Sharing Logs

**Scenario:** A support or security analyst needs to share a log excerpt with another team.

**Risk:** The file contains customer emails, phone numbers, SSNs, or addresses.

**How this tool helps:**

1. The analyst scans the file for common PII patterns.
2. The tool reports what it found and where.
3. The analyst creates a redacted copy before sharing.

**Security outcome:** Reduces accidental spread of sensitive data during troubleshooting or incident response.

## Use Case 2: Pre-Commit Data Hygiene Check

**Scenario:** A team wants to avoid committing sample files that contain real personal data.

**Risk:** Developers accidentally include customer-like or employee-like records in examples, tests, or fixtures.

**How this tool helps:**

- Scans local files for common PII patterns.
- Produces deterministic redaction markers.
- Encourages synthetic examples in repositories.

**Security outcome:** Supports privacy-by-design and safer secure-SDLC habits.

## Use Case 3: Incident Triage Sanitization

**Scenario:** During an investigation, an analyst needs to include evidence in a ticket or report.

**Risk:** Raw evidence may contain personal data that is not needed for the audience.

**How this tool helps:**

- Preserves the structure of the evidence.
- Replaces sensitive values with labels like `[EMAIL]`, `[PHONE]`, and `[SSN]`.
- Makes reports easier to share with broader response teams.

**Security outcome:** Helps teams communicate findings while minimizing unnecessary sensitive-data exposure.

## Demo Command

```bash
cat > sample.txt <<'EOF'
Customer Jane Doe can be reached at jane@example.com or 555-123-4567.
Synthetic SSN for testing: 123-45-6789.
EOF

python -m src.cli scan sample.txt
python -m src.cli redact sample.txt -o redacted.txt
cat redacted.txt
```

## What To Say In An Interview

> I built this to demonstrate practical privacy engineering. It is not a full enterprise DLP platform, but it shows how I think about reducing exposure: detect sensitive data, preserve useful context, redact what does not need to spread, and document the limitations clearly.
