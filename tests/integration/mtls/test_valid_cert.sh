#!/bin/bash
# SPDX-FileCopyrightText: 2026 Haluan Irsad
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -e

SERVER_URL="https://vantaqd-server:8443"
CA_CERT="/certs/device-ca.crt"
CLIENT_CERT="/certs/govt-verifier-01.crt"
CLIENT_KEY="/certs/govt-verifier-01.key"

echo "Testing valid verifier cert..."

# 1. Health check
echo "  Checking /v1/health..."
curl -s -f --cacert "$CA_CERT" --cert "$CLIENT_CERT" --key "$CLIENT_KEY" "$SERVER_URL/v1/health" > /dev/null

# 2. Identity API
echo "  Checking /v1/device/identity..."
curl -s -f --cacert "$CA_CERT" --cert "$CLIENT_CERT" --key "$CLIENT_KEY" "$SERVER_URL/v1/device/identity" | grep -q "test-device-01"

# 3. Capabilities API
echo "  Checking /v1/device/capabilities..."
curl -s -f --cacert "$CA_CERT" --cert "$CLIENT_CERT" --key "$CLIENT_KEY" "$SERVER_URL/v1/device/capabilities" | grep -q "supported_claims"

# 4. Metadata API (Self)
echo "  Checking /v1/security/verifiers/govt-verifier-01..."
curl -s -f --cacert "$CA_CERT" --cert "$CLIENT_CERT" --key "$CLIENT_KEY" "$SERVER_URL/v1/security/verifiers/govt-verifier-01" | grep -q "govt-verifier-01"

echo "PASS: valid verifier cert"
