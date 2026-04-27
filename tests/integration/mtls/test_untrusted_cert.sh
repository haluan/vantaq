#!/bin/bash
# SPDX-FileCopyrightText: 2026 Haluan Irsad
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -e

SERVER_URL="https://vantaqd-server:8443"
CA_CERT="/certs/device-ca.crt"
CLIENT_CERT="/certs/untrusted-verifier.crt"
CLIENT_KEY="/certs/untrusted-verifier.key"

echo "Testing untrusted client cert..."

# Curl should return non-zero exit code due to TLS failure if it verifies the server,
# but the server should reject the client cert.
# If curl fails to handshake, that's what we expect.
if curl -s --cacert "$CA_CERT" --cert "$CLIENT_CERT" --key "$CLIENT_KEY" "$SERVER_URL/v1/health" 2>&1 | grep -q "alert certificate unknown"; then
    echo "PASS: untrusted cert rejected by server"
elif ! curl -s --cacert "$CA_CERT" --cert "$CLIENT_CERT" --key "$CLIENT_KEY" "$SERVER_URL/v1/health" > /dev/null 2>&1; then
    echo "PASS: untrusted cert rejected (connection failed)"
else
    echo "FAIL: untrusted cert was accepted"
    exit 1
fi
