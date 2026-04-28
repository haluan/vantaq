#!/usr/bin/env sh
# SPDX-FileCopyrightText: 2026 Haluan Irsad
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
#
# Integration test: verify_evidence CLI against a live device.
# Run from repo root. Requires docker-compose and bin/verify_evidence.

set -eu

MAX_ATTEMPTS="${MAX_ATTEMPTS:-30}"
SLEEP_SECONDS="${SLEEP_SECONDS:-1}"
ENSURE_DEVICE="${ENSURE_DEVICE:-1}"
DEVICE_READY_SLEEP_SECONDS="${DEVICE_READY_SLEEP_SECONDS:-3}"
BASE_URL="${BASE_URL:-https://device-1:8443}"
CERT_DIR="${CERT_DIR:-/certs}"
CA_CERT="${CA_CERT:-${CERT_DIR}/device-ca.crt}"
V1_CERT="${CERT_DIR}/govt-verifier-01.crt"
V1_KEY="${CERT_DIR}/govt-verifier-01.key"

COMPOSE_CMD="${COMPOSE_CMD:-}"

if [ -z "${COMPOSE_CMD}" ]; then
  if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
  elif docker-compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
  else
    echo "test-verifier-cli: FAIL docker compose command not found"
    exit 1
  fi
fi

print_device_logs() {
  echo "test-verifier-cli: recent device-1 logs"
  ${COMPOSE_CMD} logs --tail=80 device-1 || true
}

device_is_running() {
  container_id="$(${COMPOSE_CMD} ps -q device-1 2>/dev/null || true)"
  if [ -z "${container_id}" ]; then
    return 1
  fi
  if command -v docker >/dev/null 2>&1; then
    running="$(docker inspect -f '{{.State.Running}}' "${container_id}" 2>/dev/null || echo false)"
    if [ "${running}" != "true" ]; then
      return 1
    fi
  fi
  return 0
}

if [ "${ENSURE_DEVICE}" = "1" ]; then
  echo "test-verifier-cli: ensuring device-1 is recreated on current daemon"
  ${COMPOSE_CMD} up --build -d --force-recreate device-1
  if [ "${DEVICE_READY_SLEEP_SECONDS}" -gt 0 ] 2>/dev/null; then
    sleep "${DEVICE_READY_SLEEP_SECONDS}"
  fi
  if ! device_is_running; then
    echo "test-verifier-cli: FAIL device-1 failed to stay running after recreate"
    print_device_logs
    exit 1
  fi
elif [ "${ENSURE_DEVICE}" = "0" ]; then
  if ! device_is_running; then
    echo "test-verifier-cli: FAIL device-1 is not running in current compose daemon context"
    echo "test-verifier-cli: hint run build/up/test on the same daemon (same DOCKER_HOST)"
    echo "test-verifier-cli: hint use '${COMPOSE_CMD} up --build -d --force-recreate device-1' instead of restart"
    print_device_logs
    exit 1
  fi
else
  echo "test-verifier-cli: FAIL ENSURE_DEVICE must be 0 or 1"
  exit 1
fi

# Helper: POST via the allowed-verifier service (static IP 10.50.10.20 — on allowed subnet).
# The curlimages/curl image has curl as its entrypoint, so args are passed directly.
auth_post() {
  path="$1"
  data="$2"
  ${COMPOSE_CMD} run --rm allowed-verifier \
    -sS -i \
    --cacert "${CA_CERT}" \
    --cert "${V1_CERT}" \
    --key "${V1_KEY}" \
    -X POST -d "${data}" \
    "${BASE_URL}${path}"
}

echo "test-verifier-cli: waiting for ${BASE_URL}/v1/health"
attempt=1
while [ "${attempt}" -le "${MAX_ATTEMPTS}" ]; do
  # curlimages/curl entrypoint is curl; no explicit 'curl' needed.
  if ${COMPOSE_CMD} run --rm allowed-verifier \
      -sS --cacert "${CA_CERT}" \
      --cert "${V1_CERT}" --key "${V1_KEY}" \
      "${BASE_URL}/v1/health" | grep -q '"status":"ok"'; then
    echo "test-verifier-cli: server ready"
    break
  fi
  echo "test-verifier-cli: attempt ${attempt} failed, retrying in ${SLEEP_SECONDS}s..."
  sleep "${SLEEP_SECONDS}"
  attempt=$((attempt + 1))
done

if [ "${attempt}" -gt "${MAX_ATTEMPTS}" ]; then
  echo "test-verifier-cli: FAIL ${BASE_URL} timed out"
  exit 1
fi

echo "test-verifier-cli: obtaining challenge"
CH_RESP=$(auth_post "/v1/attestation/challenge" '{"purpose":"remote_attestation","requested_ttl_seconds":60}')
if ! echo "${CH_RESP}" | grep -Eq '^HTTP/[0-9.]+ 201 '; then
  echo "test-verifier-cli: FAIL challenge creation failed"
  echo "${CH_RESP}"
  exit 1
fi
CH_ID=$(echo "${CH_RESP}" | grep -o '"challenge_id":"[^"]*' | cut -d'"' -f4)
NONCE=$(echo "${CH_RESP}" | grep -o '"nonce":"[^"]*' | cut -d'"' -f4)

if [ -z "${CH_ID}" ] || [ -z "${NONCE}" ]; then
  echo "test-verifier-cli: FAIL failed to obtain challenge"
  echo "${CH_RESP}"
  exit 1
fi

echo "test-verifier-cli: obtaining evidence"
EV_RESP=$(auth_post "/v1/attestation/evidence" "{\"challenge_id\":\"${CH_ID}\",\"nonce\":\"${NONCE}\"}")
# Strip HTTP headers — take everything from the first '{'.
echo "${EV_RESP}" | sed -n '/{/,$p' > evidence.json

if ! grep -q '"evidence_id"' evidence.json; then
  echo "test-verifier-cli: FAIL evidence response malformed"
  echo "${EV_RESP}"
  exit 1
fi

echo "test-verifier-cli: fetching device public key"
${COMPOSE_CMD} cp device-1:/etc/vantaqd/certs/device-server.crt device-server.crt

# SCENARIO 1 — Valid evidence / correct key
echo "test-verifier-cli: SCENARIO 1 - Valid Evidence"
bin/verify_evidence evidence.json device-server.crt
echo "test-verifier-cli: PASS SCENARIO 1"

# SCENARIO 2 — Tampered nonce
echo "test-verifier-cli: SCENARIO 2 - Tampered Nonce"
sed 's/"nonce":"[^"]*"/"nonce":"TAMPERED_NONCE_999"/' evidence.json > evidence_tampered_nonce.json
if bin/verify_evidence evidence_tampered_nonce.json device-server.crt 2>/dev/null; then
  echo "test-verifier-cli: FAIL - accepted tampered nonce"
  exit 1
fi
echo "test-verifier-cli: PASS SCENARIO 2"

# SCENARIO 3 — Tampered claims
echo "test-verifier-cli: SCENARIO 3 - Tampered Claims"
sed 's/"claims":{[^}]*}/"claims":{"malicious":"payload"}/' evidence.json > evidence_tampered_claims.json
if bin/verify_evidence evidence_tampered_claims.json device-server.crt 2>/dev/null; then
  echo "test-verifier-cli: FAIL - accepted tampered claims"
  exit 1
fi
echo "test-verifier-cli: PASS SCENARIO 3"

# SCENARIO 4 — Wrong public key (use verifier CA cert instead of device cert)
echo "test-verifier-cli: SCENARIO 4 - Wrong Public Key"
${COMPOSE_CMD} cp device-1:/etc/vantaqd/certs/device-ca.crt device-ca.crt
if bin/verify_evidence evidence.json device-ca.crt 2>/dev/null; then
  echo "test-verifier-cli: FAIL - accepted wrong public key"
  exit 1
fi
echo "test-verifier-cli: PASS SCENARIO 4"

# Cleanup
rm -f evidence.json evidence_tampered_nonce.json evidence_tampered_claims.json device-server.crt device-ca.crt

echo "test-verifier-cli: ALL SCENARIOS PASSED"
