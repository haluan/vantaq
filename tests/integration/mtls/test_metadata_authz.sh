#!/bin/bash
# SPDX-FileCopyrightText: 2026 Haluan Irsad
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -e

SERVER_URL="https://vantaqd-server:8443"
CA_CERT="/certs/device-ca.crt"
GOVT_CERT="/certs/govt-verifier-01.crt"
GOVT_KEY="/certs/govt-verifier-01.key"
ADMIN_CERT="/certs/admin-verifier.crt"
ADMIN_KEY="/certs/admin-verifier.key"

echo "Testing Verifier Metadata Authorization..."

# 1. Verifier can query itself
echo "  govt-verifier-01 querying itself..."
curl -s -f --cacert "$CA_CERT" --cert "$GOVT_CERT" --key "$GOVT_KEY" "$SERVER_URL/v1/security/verifiers/govt-verifier-01" > /dev/null

# 2. Verifier cannot query another
echo "  govt-verifier-01 querying admin-verifier (should fail 403)..."
CODE=$(curl -s -o /dev/null -w "%{http_code}" --cacert "$CA_CERT" --cert "$GOVT_CERT" --key "$GOVT_KEY" "$SERVER_URL/v1/security/verifiers/admin-verifier")
if [ "$CODE" != "403" ]; then
    echo "FAIL: govt-verifier-01 could query admin-verifier (code: $CODE)"
    exit 1
fi

# 3. Admin can query any verifier
echo "  admin-verifier querying govt-verifier-01..."
curl -s -f --cacert "$CA_CERT" --cert "$ADMIN_CERT" --key "$ADMIN_KEY" "$SERVER_URL/v1/security/verifiers/govt-verifier-01" > /dev/null

echo "PASS: Verifier Metadata Authorization"
