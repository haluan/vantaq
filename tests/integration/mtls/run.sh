#!/bin/bash
# SPDX-FileCopyrightText: 2026 Haluan Irsad
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -e

echo "Starting mTLS Integration Test Suite..."

# Function to wait for server
wait_for_server() {
    echo "Waiting for vantaqd-server:8443..."
    for i in $(seq 1 30); do
        if curl -v -k --cert "/certs/govt-verifier-01.crt" --key "/certs/govt-verifier-01.key" "https://vantaqd-server:8443/v1/health"; then
            echo "Server is up!"
            return 0
        fi
        CODE=$(curl -k -s -o /dev/null -w "%{http_code}" --cert "/certs/govt-verifier-01.crt" --key "/certs/govt-verifier-01.key" "https://vantaqd-server:8443/v1/health" || true)
        echo "Attempt $i: code $CODE"
        sleep 1
    done
    echo "Timeout waiting for server"
    return 1
}

wait_for_server

# Run test cases
./test_valid_cert.sh
./test_missing_cert.sh
./test_untrusted_cert.sh
./test_unknown_verifier.sh
./test_metadata_authz.sh
./test_post_challenge.sh

echo ""
echo "ALL MTLS INTEGRATION TESTS PASSED!"
