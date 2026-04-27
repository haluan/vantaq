#!/bin/bash
# SPDX-FileCopyrightText: 2026 Haluan Irsad
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -e

SERVER_URL="https://vantaqd-server:8443"
CA_CERT="/certs/device-ca.crt"
# Use admin-verifier to have a fresh capacity bucket (other tests use govt-verifier-01)
CLIENT_CERT="/certs/admin-verifier.crt"
CLIENT_KEY="/certs/admin-verifier.key"

echo "Testing Challenge Expiry and Capacity Recovery (using admin-verifier)..."

# 1. Verify TTL reporting
echo "  Verifying TTL reporting..."
RESP=$(curl -s -f --cacert "$CA_CERT" --cert "$CLIENT_CERT" --key "$CLIENT_KEY" \
    -X POST -d '{"purpose":"remote_attestation", "requested_ttl_seconds": 1}' \
    "$SERVER_URL/v1/attestation/challenge")

TTL=$(echo "$RESP" | grep -o '"expires_in_seconds":[0-9]*' | cut -d: -f2)
if [ "$TTL" != "1" ]; then
    echo "FAILED: Expected TTL 1, got $TTL"
    echo "Response: $RESP"
    exit 1
fi
echo "  SUCCESS: TTL 1 correctly reported."

# 2. Test Capacity Recovery via Expiry
# Note: vantaqd.yaml is configured with max_per_verifier: 10
echo "  Testing capacity recovery (max_per_verifier: 10)..."

# Already created 1 above. Request 9 more with 1s TTL.
echo "  - Requesting 9 more challenges (1s TTL)..."
for i in {2..10}; do
    curl -s -f --cacert "$CA_CERT" --cert "$CLIENT_CERT" --key "$CLIENT_KEY" \
        -X POST -d '{"purpose":"remote_attestation", "requested_ttl_seconds": 1}' \
        "$SERVER_URL/v1/attestation/challenge" > /dev/null
done
echo "  - Capacity reached (10 challenges created for admin-verifier)."

# Challenge 11 (should fail immediately)
echo "  - Requesting Challenge 11 (should fail due to capacity)..."
CODE=$(curl -s -o /dev/null -w "%{http_code}" --cacert "$CA_CERT" --cert "$CLIENT_CERT" --key "$CLIENT_KEY" \
    -X POST -d '{"purpose":"remote_attestation"}' \
    "$SERVER_URL/v1/attestation/challenge" || true)

if [ "$CODE" != "500" ]; then
    echo "FAILED: Expected 500 for capacity limit, got $CODE"
    exit 1
fi
echo "  - SUCCESS: Challenge 11 rejected as expected."

# Wait for expiry
echo "  - Waiting 2 seconds for challenges to expire..."
sleep 2

# Challenge 11 again (should succeed now)
echo "  - Requesting Challenge 11 again (should succeed after expiry cleanup)..."
RESP11=$(curl -s -f --cacert "$CA_CERT" --cert "$CLIENT_CERT" --key "$CLIENT_KEY" \
    -X POST -d '{"purpose":"remote_attestation"}' \
    "$SERVER_URL/v1/attestation/challenge")

CHID11=$(echo "$RESP11" | grep -o '"challenge_id":"[^"]*"' | cut -d'"' -f4)
if [ -z "$CHID11" ]; then
    echo "FAILED: Challenge 11 failed after wait"
    echo "Response: $RESP11"
    exit 1
fi
echo "  - SUCCESS: Challenge 11 created after expiry cleanup ($CHID11)."

echo "PASS: Challenge expiry and capacity recovery verified."
