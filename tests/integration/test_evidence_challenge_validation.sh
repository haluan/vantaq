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
    echo "test-evidence-validation: FAIL docker compose command not found"
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

echo "test-evidence-validation: waiting for ${BASE_URL}/v1/health"
attempt=1
while [ "${attempt}" -le "${MAX_ATTEMPTS}" ]; do
  if auth_post "/v1/health" "" | grep -Eq '^HTTP/[0-9.]+ 200 '; then
    echo "test-evidence-validation: server ready"
    break
  fi
  echo "test-evidence-validation: attempt ${attempt}/${MAX_ATTEMPTS} not ready"
  attempt=$((attempt + 1))
  sleep "${SLEEP_SECONDS}"
done

if [ "${attempt}" -gt "${MAX_ATTEMPTS}" ]; then
  echo "test-evidence-validation: FAIL timeout"
  exit 1
fi

# 1. Get Challenge
echo "test-evidence-validation: obtaining challenge"
ch_out="$(auth_post "/v1/attestation/challenge" '{"purpose":"test"}')"
if ! echo "${ch_out}" | grep -Eq '^HTTP/[0-9.]+ 201 '; then
  echo "test-evidence-validation: FAIL challenge creation failed"
  echo "${ch_out}"
  exit 1
fi

challenge_id="$(echo "${ch_out}" | grep -o '"challenge_id":"[^"]*' | cut -d'"' -f4)"
nonce="$(echo "${ch_out}" | grep -o '"nonce":"[^"]*' | cut -d'"' -f4)"
echo "test-evidence-validation: got challenge_id=${challenge_id} nonce=${nonce}"

# 2. Test 404 (Unknown Challenge ID)
echo "test-evidence-validation: testing 404 (unknown challenge)"
out_404="$(auth_post "/v1/attestation/evidence" "{\"challenge_id\":\"non-existent\",\"nonce\":\"${nonce}\"}")"
if ! echo "${out_404}" | grep -Eq '^HTTP/[0-9.]+ 404 '; then
  echo "test-evidence-validation: FAIL expected 404 for unknown challenge"
  echo "${out_404}"
  exit 1
fi
echo "test-evidence-validation: PASS 404 for unknown challenge"

# 3. Test 409 (Nonce Mismatch)
echo "test-evidence-validation: testing 409 (nonce mismatch)"
out_409="$(auth_post "/v1/attestation/evidence" "{\"challenge_id\":\"${challenge_id}\",\"nonce\":\"badnonce\"}")"
if ! echo "${out_409}" | grep -Eq '^HTTP/[0-9.]+ 409 '; then
  echo "test-evidence-validation: FAIL expected 409 for nonce mismatch"
  echo "${out_409}"
  exit 1
fi
echo "test-evidence-validation: PASS 409 for nonce mismatch"

# 4. Test 400 (Missing field)
echo "test-evidence-validation: testing 400 (missing field)"
out_400="$(auth_post "/v1/attestation/evidence" "{\"nonce\":\"${nonce}\"}")"
if ! echo "${out_400}" | grep -Eq '^HTTP/[0-9.]+ 400 '; then
  echo "test-evidence-validation: FAIL expected 400 for missing challenge_id"
  echo "${out_400}"
  exit 1
fi
echo "test-evidence-validation: PASS 400 for missing field"

# 5. Test Success
echo "test-evidence-validation: testing success"
out_200="$(auth_post "/v1/attestation/evidence" "{\"challenge_id\":\"${challenge_id}\",\"nonce\":\"${nonce}\"}")"
if ! echo "${out_200}" | grep -Eq '^HTTP/[0-9.]+ 200 '; then
  echo "test-evidence-validation: FAIL expected 200 for valid evidence request"
  echo "${out_200}"
  exit 1
fi
if ! echo "${out_200}" | grep -q '"evidence_id":'; then
  echo "test-evidence-validation: FAIL response missing evidence_id"
  echo "${out_200}"
  exit 1
fi
echo "test-evidence-validation: PASS valid evidence creation"

echo "test-evidence-validation: ALL TESTS PASSED"
