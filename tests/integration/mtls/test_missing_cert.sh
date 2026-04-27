#!/bin/bash
# SPDX-FileCopyrightText: 2026 Haluan Irsad
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -e

SERVER_URL="https://vantaqd-server:8443"
CA_CERT="/certs/device-ca.crt"

echo "Testing missing client cert..."

# Should fail with 401 or TLS error depending on server configuration
# In our case, we set require_client_cert: true, so it might fail at TLS level or return 401
# Let's check for non-2xx response.
CODE=$(curl -s -o /dev/null -w "%{http_code}" --cacert "$CA_CERT" "$SERVER_URL/v1/health" || echo "failed")

if [ "$CODE" == "401" ] || [[ "$CODE" == *"failed"* ]] || [ "$CODE" == "000" ]; then
    echo "PASS: missing client cert rejected (code: $CODE)"
else
    echo "FAIL: missing client cert was not rejected (code: $CODE)"
    exit 1
fi
