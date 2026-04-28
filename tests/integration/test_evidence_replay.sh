#!/usr/bin/env sh
# SPDX-FileCopyrightText: 2026 Haluan Irsad
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -eu

MAX_ATTEMPTS="${MAX_ATTEMPTS:-30}"
SLEEP_SECONDS="${SLEEP_SECONDS:-1}"
BASE_URL="${BASE_URL:-https://device-1:8443}"
CERT_DIR="${CERT_DIR:-/certs}"
CA_CERT="${CA_CERT:-${CERT_DIR}/device-ca.crt}"
VALID_CERT="${VALID_CERT:-${CERT_DIR}/govt-verifier-01.crt}"
VALID_KEY="${VALID_KEY:-${CERT_DIR}/govt-verifier-01.key}"
COMPOSE_CMD="${COMPOSE_CMD:-}"

if [ -z "${COMPOSE_CMD}" ]; then
  if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
  elif docker-compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
  else
    echo "test-evidence-replay: FAIL docker compose command not found"
    exit 1
  fi
fi

# Helper function to perform authenticated POST
auth_post() {
  path="$1"
  data="$2"
  sh -c "${COMPOSE_CMD} run --rm allowed-verifier -sS -i \
    --cacert \"${CA_CERT}\" \
    --cert \"${VALID_CERT}\" \
    --key \"${VALID_KEY}\" \
    -X POST -d '${data}' \
    \"${BASE_URL}${path}\""
}

echo "test-evidence-replay: waiting for ${BASE_URL}/v1/health"
attempt=1
while [ "${attempt}" -le "${MAX_ATTEMPTS}" ]; do
  if auth_post "/v1/health" "" | grep -Eq '^HTTP/[0-9.]+ 200 '; then
    echo "test-evidence-replay: server ready"
    break
  fi
  attempt=$((attempt + 1))
  sleep "${SLEEP_SECONDS}"
done

if [ "${attempt}" -gt "${MAX_ATTEMPTS}" ]; then
  echo "test-evidence-replay: FAIL timeout"
  exit 1
fi

# 1. Get Challenge
echo "test-evidence-replay: obtaining challenge"
ch_out="$(auth_post "/v1/attestation/challenge" '{"purpose":"test"}')"
if ! echo "${ch_out}" | grep -Eq '^HTTP/[0-9.]+ 201 '; then
  echo "test-evidence-replay: FAIL challenge creation failed"
  echo "${ch_out}"
  exit 1
fi

challenge_id="$(echo "${ch_out}" | grep -o '"challenge_id":"[^"]*' | cut -d'"' -f4)"
nonce="$(echo "${ch_out}" | grep -o '"nonce":"[^"]*' | cut -d'"' -f4)"

# 2. Test First Use (Success)
echo "test-evidence-replay: testing first use"
out_first="$(auth_post "/v1/attestation/evidence" "{\"challenge_id\":\"${challenge_id}\",\"nonce\":\"${nonce}\"}")"
if ! echo "${out_first}" | grep -Eq '^HTTP/[0-9.]+ 200 '; then
  echo "test-evidence-replay: FAIL expected 200 for first use"
  echo "${out_first}"
  exit 1
fi

# 3. Test Second Use (Replay)
echo "test-evidence-replay: testing second use (replay attack)"
out_second="$(auth_post "/v1/attestation/evidence" "{\"challenge_id\":\"${challenge_id}\",\"nonce\":\"${nonce}\"}")"
if ! echo "${out_second}" | grep -Eq '^HTTP/[0-9.]+ 409 '; then
  echo "test-evidence-replay: FAIL expected 409 for replay attack"
  echo "${out_second}"
  exit 1
fi
echo "test-evidence-replay: PASS 409 for replay attack"

echo "test-evidence-replay: ALL TESTS PASSED"
