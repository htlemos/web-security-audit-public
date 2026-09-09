#!/usr/bin/env bash

set -euo pipefail

echo
echo "Web Security Audit - Installation"
echo

missing=""

for cmd in python3 curl openssl nmap; do
    command -v "$cmd" >/dev/null 2>&1 || missing="$missing $cmd"
done

command -v testssl.sh >/dev/null 2>&1 \
 || command -v testssl >/dev/null 2>&1 \
 || missing="$missing testssl.sh"

if [ -n "$missing" ]; then
    echo "Missing required commands:$missing"
    exit 1
fi

if ! command -v nikto >/dev/null 2>&1; then
    echo "WARNING: nikto not found."
    echo "Install it or disable it in audit-config.json."
fi

chmod 750 web-security-audit.py

#
# Create working config
#

if [ ! -f audit-config.json ]; then
    cp config/audit-config.example.json audit-config.json
fi

#
# Compile check
#

python3 -m py_compile web-security-audit.py

#
# Validation
#

python3 web-security-audit.py \
    --validate-only \
    -c audit-config.json \
    -p profiles/profile-web-security-external.json

echo
echo "Installation validation successful."
echo