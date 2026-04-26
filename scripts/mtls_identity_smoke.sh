#!/usr/bin/env sh
# SPDX-FileCopyrightText: 2026 Haluan Irsad
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -eu

MAX_ATTEMPTS="${MAX_ATTEMPTS:-30}"
SLEEP_SECONDS="${SLEEP_SECONDS:-1}"
IDENTITY_URL="${IDENTITY_URL:-https://device-1:8443/v1/device/identity}"
CERT_DIR="${CERT_DIR:-/certs}"
CA_CERT="${CA_CERT:-${CERT_DIR}/device-ca.crt}"
VALID_CERT="${VALID_CERT:-${CERT_DIR}/govt-verifier-01.crt}"
VALID_KEY="${VALID_KEY:-${CERT_DIR}/govt-verifier-01.key}"
UNTRUSTED_CERT="${UNTRUSTED_CERT:-${CERT_DIR}/govt-verifier-01-untrusted.crt}"
UNTRUSTED_KEY="${UNTRUSTED_KEY:-${CERT_DIR}/govt-verifier-01-untrusted.key}"
COMPOSE_CMD="${COMPOSE_CMD:-}"

if [ -z "${COMPOSE_CMD}" ]; then
  if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
  elif docker-compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
  else
    echo "mtls-identity-smoke: FAIL docker compose command not found"
    exit 1
  fi
fi

attempt=1
tmp_missing="$(mktemp)"
tmp_untrusted="$(mktemp)"
trap 'rm -f "${tmp_missing}" "${tmp_untrusted}"' EXIT

echo "mtls-identity-smoke: waiting for ${IDENTITY_URL}"

while [ "${attempt}" -le "${MAX_ATTEMPTS}" ]; do
  out="$(
    sh -c "${COMPOSE_CMD} run --rm allowed-verifier -sS -i \
      --cacert \"${CA_CERT}\" \
      --cert \"${VALID_CERT}\" \
      --key \"${VALID_KEY}\" \
      \"${IDENTITY_URL}\"" 2>&1 || true
  )"
  status_line="$(printf '%s\n' "${out}" | awk 'NR==1 {print}')"

  if printf '%s\n' "${out}" | grep -Eq '^HTTP/[0-9.]+ 200 '; then
    if ! printf '%s\n' "${out}" | grep -Eq '"device_id"[[:space:]]*:[[:space:]]*"edge-gw-001"'; then
      echo "mtls-identity-smoke: FAIL valid mTLS returned malformed identity body"
      printf '%s\n' "${out}"
      exit 1
    fi
    if ! printf '%s\n' "${out}" | grep -Eq '"model"[[:space:]]*:[[:space:]]*"edge-gateway-v1"'; then
      echo "mtls-identity-smoke: FAIL valid mTLS missing model field"
      printf '%s\n' "${out}"
      exit 1
    fi
    if ! printf '%s\n' "${out}" | grep -Eq '"serial_number"[[:space:]]*:[[:space:]]*"SN-001"'; then
      echo "mtls-identity-smoke: FAIL valid mTLS missing serial_number field"
      printf '%s\n' "${out}"
      exit 1
    fi
    if ! printf '%s\n' "${out}" | grep -Eq '"manufacturer"[[:space:]]*:[[:space:]]*"ExampleCorp"'; then
      echo "mtls-identity-smoke: FAIL valid mTLS missing manufacturer field"
      printf '%s\n' "${out}"
      exit 1
    fi
    if ! printf '%s\n' "${out}" | grep -Eq '"firmware_version"[[:space:]]*:[[:space:]]*"0.1.0-demo"'; then
      echo "mtls-identity-smoke: FAIL valid mTLS missing firmware_version field"
      printf '%s\n' "${out}"
      exit 1
    fi

    echo "mtls-identity-smoke: PASS valid client certificate ${status_line}"
    break
  fi

  echo "mtls-identity-smoke: attempt ${attempt}/${MAX_ATTEMPTS} not ready (${status_line})"
  attempt=$((attempt + 1))
  sleep "${SLEEP_SECONDS}"
done

if [ "${attempt}" -gt "${MAX_ATTEMPTS}" ]; then
  echo "mtls-identity-smoke: FAIL timeout waiting for valid mTLS 200"
  exit 1
fi

if sh -c "${COMPOSE_CMD} run --rm allowed-verifier -sS -i \
  --cacert \"${CA_CERT}\" \
  \"${IDENTITY_URL}\"" >"${tmp_missing}" 2>&1; then
  echo "mtls-identity-smoke: FAIL missing client cert unexpectedly succeeded"
  cat "${tmp_missing}"
  exit 1
fi
if grep -Eq '^HTTP/[0-9.]+ 200 ' "${tmp_missing}"; then
  echo "mtls-identity-smoke: FAIL missing client cert leaked HTTP 200 response"
  cat "${tmp_missing}"
  exit 1
fi
if grep -Eq '"device_id"[[:space:]]*:[[:space:]]*"edge-gw-001"' "${tmp_missing}"; then
  echo "mtls-identity-smoke: FAIL missing client cert leaked identity body"
  cat "${tmp_missing}"
  exit 1
fi
echo "mtls-identity-smoke: PASS missing client certificate rejected at handshake"

if sh -c "${COMPOSE_CMD} run --rm allowed-verifier -sS -i \
  --cacert \"${CA_CERT}\" \
  --cert \"${UNTRUSTED_CERT}\" \
  --key \"${UNTRUSTED_KEY}\" \
  \"${IDENTITY_URL}\"" >"${tmp_untrusted}" 2>&1; then
  echo "mtls-identity-smoke: FAIL untrusted client cert unexpectedly succeeded"
  cat "${tmp_untrusted}"
  exit 1
fi
if grep -Eq '^HTTP/[0-9.]+ 200 ' "${tmp_untrusted}"; then
  echo "mtls-identity-smoke: FAIL untrusted client cert leaked HTTP 200 response"
  cat "${tmp_untrusted}"
  exit 1
fi
if grep -Eq '"device_id"[[:space:]]*:[[:space:]]*"edge-gw-001"' "${tmp_untrusted}"; then
  echo "mtls-identity-smoke: FAIL untrusted client cert leaked identity body"
  cat "${tmp_untrusted}"
  exit 1
fi
echo "mtls-identity-smoke: PASS untrusted client certificate rejected at handshake"
