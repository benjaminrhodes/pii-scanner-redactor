# PII Scanner/Redactor

Detect and redact PII in datasets

## Features

- Detect PII types: SSN, email, phone, addresses
- Redact detected PII with placeholder markers
- CLI interface for scanning and redacting files
- Supports multiple text formats

## Installation

```bash
pip install -e .
```

## Usage

### Scan a file for PII

```bash
python -m src.cli scan path/to/file.txt
```

### Redact PII from a file

```bash
python -m src.cli redact path/to/file.txt
```

### Redact and save to output file

```bash
python -m src.cli redact path/to/file.txt -o output.txt
```

## Testing

```bash
pytest tests/ -v
```

## License

MIT
