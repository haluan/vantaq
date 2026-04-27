#!/bin/bash
# SPDX-FileCopyrightText: 2026 Haluan Irsad
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -e

SERVER_URL="https://vantaqd-server:8443"
CA_CERT="/certs/device-ca.crt"
CLIENT_CERT="/certs/govt-verifier-01.crt"
CLIENT_KEY="/certs/govt-verifier-01.key"

echo "Testing Challenge Verifier Binding..."

# 1. Attempt to spoof verifier_id in body
echo "  Attempting to spoof verifier_id in body..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --cacert "$CA_CERT" --cert "$CLIENT_CERT" --key "$CLIENT_KEY" \
    -X POST -d '{"purpose":"remote_attestation","verifier_id":"rogue-verifier"}' \
    "$SERVER_URL/v1/attestation/challenge")

if [ "$HTTP_CODE" -eq 400 ]; then
    echo "  SUCCESS: Server rejected spoofed verifier_id with 400."
else
    echo "  FAILURE: Server returned $HTTP_CODE instead of 400 for spoofed verifier_id."
    exit 1
fi

# 2. Verify response uses identity from certificate
echo "  Checking identity binding from certificate..."
RESPONSE=$(curl -s -f --cacert "$CA_CERT" --cert "$CLIENT_CERT" --key "$CLIENT_KEY" \
    -X POST -d '{"purpose":"remote_attestation"}' \
    "$SERVER_URL/v1/attestation/challenge")

# Cert is for govt-verifier-01, response must match even if we didn't specify it
if echo "$RESPONSE" | grep -q "\"verifier_id\":\"govt-verifier-01\""; then
    echo "  SUCCESS: Response correctly bound to certificate identity."
else
    echo "  FAILURE: Response verifier_id did not match certificate identity."
    echo "  Response: $RESPONSE"
    exit 1
fi

echo "PASS: Challenge Verifier Binding"
