# PII Scanner/Redactor — 60-Second Explainer Script

## Short Description

PII Scanner/Redactor is a defensive data-protection utility that detects and masks common personal information in text files before those files are shared, committed, or attached to reports.

## 60-Second Video Script

**Hook — 0:00–0:08**

> A lot of data leaks are not dramatic hacks. Sometimes sensitive information just gets copied into the wrong log, ticket, test file, or report.

**Problem — 0:08–0:20**

> Analysts and developers often need to share evidence, but that evidence can contain emails, phone numbers, SSNs, or addresses that the next audience does not actually need to see.

**Solution — 0:20–0:38**

> I built PII Scanner/Redactor as a small data-protection tool. It scans text files for common PII patterns and can produce a redacted version with labels like `[EMAIL]`, `[PHONE]`, and `[SSN]`.

**Demo — 0:38–0:50**

> Here is a synthetic sample. First I scan it and identify the sensitive fields. Then I redact it and preserve the useful context without exposing the raw values.

**Close — 0:50–1:00**

> This is not a full DLP platform. It is a practical portfolio example of how I approach privacy engineering: identify exposure, reduce unnecessary spread, and make the safer path easy for the team.

## Shot List

1. Talking head: “Not all data leaks are dramatic hacks.”
2. Screen recording: show synthetic sample file.
3. Terminal: run scan command.
4. Terminal: run redact command and show output.
5. Talking head: explain privacy/security value.

## Demo Commands

```bash
cat > sample.txt <<'EOF'
Customer Jane Doe can be reached at jane@example.com or 555-123-4567.
Synthetic SSN for testing: 123-45-6789.
EOF

python -m src.cli scan sample.txt
python -m src.cli redact sample.txt -o redacted.txt
cat redacted.txt
```

## LinkedIn Caption

A practical privacy control does not have to start as a giant platform.

I built a small PII Scanner/Redactor that detects common personal information in text files and produces a masked version for safer sharing.

The portfolio point: find exposure, preserve useful context, and reduce unnecessary spread of sensitive data.
