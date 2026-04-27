#!/bin/bash
# SPDX-FileCopyrightText: 2026 Haluan Irsad
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -e

SERVER_URL="https://vantaqd-server:8443"
CA_CERT="/certs/device-ca.crt"
CLIENT_CERT="/certs/govt-verifier-01.crt"
CLIENT_KEY="/certs/govt-verifier-01.key"

echo "Testing POST /v1/attestation/challenge..."

# 1. Successful challenge creation
echo "  Requesting challenge..."
RESPONSE=$(curl -s -f --cacert "$CA_CERT" --cert "$CLIENT_CERT" --key "$CLIENT_KEY" \
    -X POST -d '{"purpose":"remote_attestation"}' \
    "$SERVER_URL/v1/attestation/challenge")

echo "$RESPONSE" | grep -q "\"challenge_id\":"
echo "$RESPONSE" | grep -q "\"nonce\":"
echo "$RESPONSE" | grep -q "\"verifier_id\":\"govt-verifier-01\""
echo "$RESPONSE" | grep -q "\"purpose\":\"remote_attestation\""
echo "$RESPONSE" | grep -q "\"expires_in_seconds\":30"

echo "PASS: POST /v1/attestation/challenge"
