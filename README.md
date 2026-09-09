# Web Security Audit

Version: 1.0.2

Standalone web security audit engine.

## Installation

```bash
chmod 750 install.sh

./install.sh
```

## Configuration

Create the working configuration:

```bash
cp config/audit-config.example.json \
   audit-config.json
```

Edit:

```text
audit-config.json
```

## Validation

```bash
python3 web-security-audit.py \
  --validate-only \
  -c audit-config.json \
  -p profiles/profile-web-security-external.json
```

## Run

```bash
python3 web-security-audit.py \
  -c audit-config.json \
  -p profiles/profile-web-security-external.json \
  -o reports/audit-output
```

## Documentation

See:

```text
docs/MANUAL.md
docs/CHANGELOG.md
```
