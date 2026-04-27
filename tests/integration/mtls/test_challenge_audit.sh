#!/bin/bash
# SPDX-FileCopyrightText: 2026 Haluan Irsad
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -e

echo "Running Challenge Audit Integration Test..."

LOG_FILE="/var/log/vantaqd/audit.log"
URL="https://vantaqd-server:8443/v1/attestation/challenge"
CERT="/certs/govt-verifier-01.crt"
KEY="/certs/govt-verifier-01.key"

# 1. Test: Successful challenge creation audit
echo "Testing success audit..."
curl -s -k --cert "$CERT" --key "$KEY" \
     -X POST "$URL" \
     -H "Content-Type: application/json" \
     -d '{"purpose": "test_audit_success"}' > /dev/null

# Verify log
grep -a "\"result\":\"allowed\"" "$LOG_FILE" | grep "\"reason\":\"ok\"" || {
    echo "FAILED: Success audit log not found or incorrect"
    cat "$LOG_FILE"
    exit 1
}
echo "Success audit verified."

# 2. Test: Denied challenge creation audit (missing purpose)
echo "Testing denial audit (missing purpose)..."
curl -s -k --cert "$CERT" --key "$KEY" \
     -X POST "$URL" \
     -H "Content-Type: application/json" \
     -d '{"something_else": "test"}' > /dev/null

# Verify log
grep -a "\"result\":\"denied\"" "$LOG_FILE" | grep "\"reason\":\"missing_purpose\"" || {
    echo "FAILED: Denial audit log not found or incorrect"
    cat "$LOG_FILE"
    exit 1
}
echo "Denial audit verified."

echo "CHALLENGE AUDIT TEST PASSED"
