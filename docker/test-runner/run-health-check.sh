#!/bin/sh
# SPDX-FileCopyrightText: 2026 Haluan Irsad
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -eu

BASE_URL="${BASE_URL:-https://device-1:8443}"
HEALTH_URL="${HEALTH_URL:-${BASE_URL}/v1/health}"
IDENTITY_URL="${IDENTITY_URL:-${BASE_URL}/v1/device/identity}"
CAPABILITIES_URL="${CAPABILITIES_URL:-${BASE_URL}/v1/device/capabilities}"
CERT_DIR="${CERT_DIR:-/certs}"
CA_CERT="${CA_CERT:-${CERT_DIR}/device-ca.crt}"
CLIENT_CERT="${CLIENT_CERT:-${CERT_DIR}/govt-verifier-01.crt}"
CLIENT_KEY="${CLIENT_KEY:-${CERT_DIR}/govt-verifier-01.key}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-30}"
SLEEP_SECONDS="${SLEEP_SECONDS:-1}"

attempt=1
tmp_body="$(mktemp)"
trap 'rm -f "$tmp_body"' EXIT

request_json_or_fail() {
  url="$1"
  expected_pattern="$2"
  label="$3"

  http_code="$(curl -sS -o "$tmp_body" -w '%{http_code}' \
    --cacert "$CA_CERT" \
    --cert "$CLIENT_CERT" \
    --key "$CLIENT_KEY" \
    "$url" || true)"
  if [ "$http_code" != "200" ]; then
    echo "health-check: FAIL ${label} returned http=${http_code}"
    cat "$tmp_body"
    exit 1
  fi

  if ! grep -Eq "$expected_pattern" "$tmp_body"; then
    echo "health-check: FAIL ${label} payload assertion"
    cat "$tmp_body"
    exit 1
  fi

  echo "health-check: PASS ${label}"
}

echo "health-check: waiting for ${HEALTH_URL}"

while [ "$attempt" -le "$MAX_ATTEMPTS" ]; do
  http_code="$(curl -sS -o "$tmp_body" -w '%{http_code}' \
    --cacert "$CA_CERT" \
    --cert "$CLIENT_CERT" \
    --key "$CLIENT_KEY" \
    "$HEALTH_URL" || true)"

  if [ "$http_code" = "200" ]; then
    if grep -Eq '"status"[[:space:]]*:[[:space:]]*"ok"' "$tmp_body"; then
      echo "health-check: PASS health"
      request_json_or_fail "$IDENTITY_URL" \
        '"device_id"[[:space:]]*:[[:space:]]*"edge-gw-001"' \
        "identity"
      request_json_or_fail "$CAPABILITIES_URL" \
        '"supported_claims"[[:space:]]*:[[:space:]]*\[[^]]*"device_identity"' \
        "capabilities"
      echo "health-check: PASS all endpoint checks"
      exit 0
    fi

    echo "health-check: FAIL (status=200 but JSON status!=ok)"
    cat "$tmp_body"
    exit 1
  fi

  echo "health-check: attempt ${attempt}/${MAX_ATTEMPTS} not ready (http=${http_code})"
  attempt=$((attempt + 1))
  sleep "$SLEEP_SECONDS"
done

echo "health-check: FAIL timeout waiting for ${HEALTH_URL}"
exit 1
