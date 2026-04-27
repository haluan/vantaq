#!/bin/bash
# SPDX-FileCopyrightText: 2026 Haluan Irsad
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -e

SERVER_URL="https://vantaqd-server:8443"
CA_CERT="/certs/device-ca.crt"
CLIENT_CERT="/certs/unknown-verifier-99.crt"
CLIENT_KEY="/certs/unknown-verifier-99.key"

echo "Testing unknown verifier ID cert..."

CODE=$(curl -s -o /dev/null -w "%{http_code}" --cacert "$CA_CERT" --cert "$CLIENT_CERT" --key "$CLIENT_KEY" "$SERVER_URL/v1/health")

if [ "$CODE" == "403" ]; then
    echo "PASS: unknown verifier rejected with 403"
else
    echo "FAIL: unknown verifier returned $CODE (expected 403)"
    exit 1
fi
