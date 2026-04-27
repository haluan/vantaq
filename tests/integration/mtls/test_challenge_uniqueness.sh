#!/bin/bash
# SPDX-FileCopyrightText: 2026 Haluan Irsad
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -e

SERVER_URL="https://vantaqd-server:8443"
CA_CERT="/certs/device-ca.crt"
CLIENT_CERT="/certs/govt-verifier-01.crt"
CLIENT_KEY="/certs/govt-verifier-01.key"

echo "Testing Challenge Uniqueness..."

# 1. Request first challenge
echo "  Requesting first challenge..."
RESP1=$(curl -s -f --cacert "$CA_CERT" --cert "$CLIENT_CERT" --key "$CLIENT_KEY" \
    -X POST -d '{"purpose":"remote_attestation"}' \
    "$SERVER_URL/v1/attestation/challenge")

CHID1=$(echo "$RESP1" | grep -o '"challenge_id":"[^"]*"' | cut -d'"' -f4)
NONCE1=$(echo "$RESP1" | grep -o '"nonce":"[^"]*"' | cut -d'"' -f4)

if [ -z "$CHID1" ] || [ -z "$NONCE1" ]; then
    echo "FAILED: Could not parse first challenge response"
    echo "Response: $RESP1"
    exit 1
fi

echo "  Challenge 1: $CHID1 (nonce: $NONCE1)"

# 2. Request second challenge
echo "  Requesting second challenge..."
RESP2=$(curl -s -f --cacert "$CA_CERT" --cert "$CLIENT_CERT" --key "$CLIENT_KEY" \
    -X POST -d '{"purpose":"remote_attestation"}' \
    "$SERVER_URL/v1/attestation/challenge")

CHID2=$(echo "$RESP2" | grep -o '"challenge_id":"[^"]*"' | cut -d'"' -f4)
NONCE2=$(echo "$RESP2" | grep -o '"nonce":"[^"]*"' | cut -d'"' -f4)

if [ -z "$CHID2" ] || [ -z "$NONCE2" ]; then
    echo "FAILED: Could not parse second challenge response"
    echo "Response: $RESP2"
    exit 1
fi

echo "  Challenge 2: $CHID2 (nonce: $NONCE2)"

# 3. Assert uniqueness
if [ "$CHID1" == "$CHID2" ]; then
    echo "FAILED: Challenge IDs are not unique ($CHID1)"
    exit 1
fi

if [ "$NONCE1" == "$NONCE2" ]; then
    echo "FAILED: Nonces are not unique ($NONCE1)"
    exit 1
fi

echo "PASS: Challenges are unique"
