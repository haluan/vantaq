#!/usr/bin/env sh
# SPDX-FileCopyrightText: 2026 Haluan Irsad
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -eu

MAX_ATTEMPTS="${MAX_ATTEMPTS:-30}"
SLEEP_SECONDS="${SLEEP_SECONDS:-1}"
BASE_URL="${BASE_URL:-https://device-1:8443}"
CERT_DIR="${CERT_DIR:-/certs}"
CA_CERT="${CA_CERT:-${CERT_DIR}/device-ca.crt}"

# Verifier 1 (Govt)
V1_CERT="${CERT_DIR}/govt-verifier-01.crt"
V1_KEY="${CERT_DIR}/govt-verifier-01.key"

# Verifier 2 (Admin)
V2_CERT="${CERT_DIR}/admin-verifier.crt"
V2_KEY="${CERT_DIR}/admin-verifier.key"

COMPOSE_CMD="${COMPOSE_CMD:-}"

if [ -z "${COMPOSE_CMD}" ]; then
  if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
  elif docker-compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
  else
    echo "test-evidence-binding: FAIL docker compose command not found"
    exit 1
  fi
fi

# Helper function to perform authenticated POST
auth_post() {
  path="$1"
  data="$2"
  cert="$3"
  key="$4"
  # Use allowed-verifier service from root docker-compose
  sh -c "${COMPOSE_CMD} run --rm allowed-verifier -sS -i \
    --cacert \"${CA_CERT}\" \
    --cert \"${cert}\" \
    --key \"${key}\" \
    -X POST -d '${data}' \
    \"${BASE_URL}${path}\""
}

echo "test-evidence-binding: waiting for ${BASE_URL}/v1/health"
attempt=1
while [ "${attempt}" -le "${MAX_ATTEMPTS}" ]; do
  if auth_post "/v1/health" "" "${V1_CERT}" "${V1_KEY}" | grep -Eq '^HTTP/[0-9.]+ 200 '; then
    echo "test-evidence-binding: server ready"
    break
  fi
  attempt=$((attempt + 1))
  sleep "${SLEEP_SECONDS}"
done

if [ "${attempt}" -gt "${MAX_ATTEMPTS}" ]; then
  echo "test-evidence-binding: FAIL timeout"
  exit 1
fi

# 1. Get Challenge using Verifier 1
echo "test-evidence-binding: Verifier 1 obtaining challenge"
ch_out="$(auth_post "/v1/attestation/challenge" '{"purpose":"test"}' "${V1_CERT}" "${V1_KEY}")"
if ! echo "${ch_out}" | grep -Eq '^HTTP/[0-9.]+ 201 '; then
  echo "test-evidence-binding: FAIL challenge creation failed"
  echo "${ch_out}"
  exit 1
fi

challenge_id="$(echo "${ch_out}" | grep -o '"challenge_id":"[^"]*' | cut -d'"' -f4)"
nonce="$(echo "${ch_out}" | grep -o '"nonce":"[^"]*' | cut -d'"' -f4)"

# 2. Attempt to consume challenge using Verifier 2 (Mismatch)
echo "test-evidence-binding: Verifier 2 attempting to consume Verifier 1's challenge"
out_rogue="$(auth_post "/v1/attestation/evidence" "{\"challenge_id\":\"${challenge_id}\",\"nonce\":\"${nonce}\"}" "${V2_CERT}" "${V2_KEY}")"
if ! echo "${out_rogue}" | grep -Eq '^HTTP/[0-9.]+ 403 '; then
  echo "test-evidence-binding: FAIL expected 403 Forbidden for verifier mismatch"
  echo "${out_rogue}"
  exit 1
fi
echo "test-evidence-binding: PASS 403 Forbidden for verifier mismatch"

# 3. Consume challenge using Verifier 1 (Success)
echo "test-evidence-binding: Verifier 1 consuming its own challenge"
out_valid="$(auth_post "/v1/attestation/evidence" "{\"challenge_id\":\"${challenge_id}\",\"nonce\":\"${nonce}\"}" "${V1_CERT}" "${V1_KEY}")"
if ! echo "${out_valid}" | grep -Eq '^HTTP/[0-9.]+ 200 '; then
  echo "test-evidence-binding: FAIL expected 200 OK for valid verifier"
  echo "${out_valid}"
  exit 1
fi

# 4. Verify verifier_id is in response and correct
if ! echo "${out_valid}" | grep -q '"verifier_id":"govt-verifier-01"'; then
  echo "test-evidence-binding: FAIL response missing correct verifier_id"
  echo "${out_valid}"
  exit 1
fi
echo "test-evidence-binding: PASS valid verifier binding in response"

echo "test-evidence-binding: ALL TESTS PASSED"
