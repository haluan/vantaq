#!/bin/bash
# SPDX-FileCopyrightText: 2026 Haluan Irsad
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -e

SERVER_URL="https://vantaqd-server:8443"
CA_CERT="/certs/device-ca.crt"
URL="$SERVER_URL/v1/attestation/challenge"

echo "Testing Unauthorized Challenge Requests..."

# 1. Missing client cert
echo "  Testing missing client cert..."
CODE=$(curl -s -o /dev/null -w "%{http_code}" --cacert "$CA_CERT" -X POST -d '{"purpose":"test"}' "$URL" || echo "failed")
if [ "$CODE" == "401" ] || [[ "$CODE" == *"failed"* ]] || [ "$CODE" == "000" ]; then
    echo "  PASS: missing cert rejected (code: $CODE)"
else
    echo "  FAIL: missing cert was not rejected (code: $CODE)"
    exit 1
fi

# 2. Untrusted client cert
echo "  Testing untrusted client cert..."
CODE=$(curl -s -o /dev/null -w "%{http_code}" --cacert "$CA_CERT" \
    --cert "/certs/untrusted-verifier.crt" --key "/certs/untrusted-verifier.key" \
    -X POST -d '{"purpose":"test"}' "$URL" || echo "failed")
if [[ "$CODE" == *"failed"* ]] || [ "$CODE" == "000" ]; then
    echo "  PASS: untrusted cert rejected at TLS level"
else
    echo "  FAIL: untrusted cert was not rejected (code: $CODE)"
    exit 1
fi

# 3. Unknown verifier cert (valid CA but unknown identity)
echo "  Testing unknown verifier identity..."
RESP=$(curl -s -w "\n%{http_code}" --cacert "$CA_CERT" \
    --cert "/certs/unknown-verifier-99.crt" --key "/certs/unknown-verifier-99.key" \
    -X POST -d '{"purpose":"test"}' "$URL" || true)

HTTP_CODE=$(echo "$RESP" | tail -n 1)
BODY=$(echo "$RESP" | head -n -1)

if [ "$HTTP_CODE" -eq 403 ]; then
    echo "  PASS: unknown verifier rejected with 403"
else
    echo "  FAIL: unknown verifier returned $HTTP_CODE instead of 403"
    exit 1
fi

if echo "$BODY" | grep -q "\"challenge_id\"" || echo "$BODY" | grep -q "\"nonce\""; then
    echo "  FAIL: response contained challenge data"
    echo "  Response: $BODY"
    exit 1
fi
echo "  PASS: no challenge data in failure response"

echo "PASS: Unauthorized Challenge Requests correctly rejected"
