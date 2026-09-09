#!/usr/bin/env bash

set -euo pipefail

#
# Detect version automatically
#

VERSION=$(grep -m1 "^V=" web-security-audit.py | cut -d"'" -f2)

if [ -z "${VERSION}" ]; then
    echo "ERROR: unable to determine version from web-security-audit.py"
    exit 1
fi

RELEASE_NAME="web-security-audit-${VERSION}"

echo
echo "========================================"
echo " Building ${RELEASE_NAME}"
echo "========================================"
echo

#
# Clean previous build
#

rm -rf dist
mkdir -p "dist/${RELEASE_NAME}"

#
# Core files
#

cp web-security-audit.py \
   "dist/${RELEASE_NAME}/"

cp install.sh \
   "dist/${RELEASE_NAME}/"

cp README.md \
   "dist/${RELEASE_NAME}/"

#
# Profiles
#

mkdir -p "dist/${RELEASE_NAME}/profiles"

cp profiles/profile-web-security-external.json \
   "dist/${RELEASE_NAME}/profiles/"

#
# Configuration
#

mkdir -p "dist/${RELEASE_NAME}/config"

cp config/audit-config.example.json \
   "dist/${RELEASE_NAME}/config/"

#
# Documentation
#

mkdir -p "dist/${RELEASE_NAME}/docs"

cp docs/MANUAL.md \
   "dist/${RELEASE_NAME}/docs/"

cp docs/CHANGELOG.md \
   "dist/${RELEASE_NAME}/docs/"

#
# Remove caches
#

find dist -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find dist -type f -name "*.pyc" -delete 2>/dev/null || true

#
# Internal checksums
#

(
    cd "dist/${RELEASE_NAME}"

    find . -type f \
        ! -name SHA256SUMS.txt \
        -exec sha256sum {} \; \
        > SHA256SUMS.txt
)

#
# Create ZIP
#

(
    cd dist

    zip -r \
        "${RELEASE_NAME}.zip" \
        "${RELEASE_NAME}" \
        > /dev/null
)

#
# Archive release permanently
#

mkdir -p releases

cp \
  "dist/${RELEASE_NAME}.zip" \
  releases/


#
# Quick release validation
#

rm -rf /tmp/web-security-audit-test

mkdir -p /tmp/web-security-audit-test

cp \
  "releases/${RELEASE_NAME}.zip" \
  /tmp/web-security-audit-test/

(
    cd /tmp/web-security-audit-test

    unzip -q "${RELEASE_NAME}.zip"

    test -f \
      "${RELEASE_NAME}/web-security-audit.py"

    test -f \
      "${RELEASE_NAME}/profiles/profile-web-security-external.json"

    test -f \
      "${RELEASE_NAME}/config/audit-config.example.json"

    test -f \
      "${RELEASE_NAME}/install.sh"
)

#
# Generate SHA256 INSIDE releases
#

(
    cd releases

    sha256sum \
        "${RELEASE_NAME}.zip" \
        > "${RELEASE_NAME}.zip.sha256"
)

#
# Display results
#

echo
echo "Build artifacts:"
echo

ls -lh "dist/${RELEASE_NAME}.zip"
ls -lh "dist/${RELEASE_NAME}.zip.sha256" 2>/dev/null || true

echo
echo "Release archive:"
echo

ls -lh "releases/${RELEASE_NAME}.zip"
ls -lh "releases/${RELEASE_NAME}.zip.sha256"

echo
echo "Verification:"
echo

(
    cd releases

    sha256sum -c \
        "${RELEASE_NAME}.zip.sha256"
)

echo
echo "Release successfully generated."
echo