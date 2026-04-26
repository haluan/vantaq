#!/usr/bin/env sh
# SPDX-FileCopyrightText: 2026 Haluan Irsad
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -eu

MAX_ATTEMPTS="${MAX_ATTEMPTS:-30}"
SLEEP_SECONDS="${SLEEP_SECONDS:-1}"
HEALTH_URL="${HEALTH_URL:-https://device-1:8443/v1/health}"
CERT_DIR="${CERT_DIR:-/certs}"
CA_CERT="${CA_CERT:-${CERT_DIR}/device-ca.crt}"
CLIENT_CERT="${CLIENT_CERT:-${CERT_DIR}/govt-verifier-01.crt}"
CLIENT_KEY="${CLIENT_KEY:-${CERT_DIR}/govt-verifier-01.key}"
COMPOSE_CMD="${COMPOSE_CMD:-}"

if [ -z "${COMPOSE_CMD}" ]; then
  if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
  elif docker-compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
  else
    echo "denied-subnet-health: FAIL docker compose command not found"
    exit 1
  fi
fi

attempt=1

echo "denied-subnet-health: waiting for ${HEALTH_URL}"

while [ "${attempt}" -le "${MAX_ATTEMPTS}" ]; do
  out="$(
    sh -c "${COMPOSE_CMD} run --rm rogue-verifier -sS -i \
      --cacert \"${CA_CERT}\" \
      --cert \"${CLIENT_CERT}\" \
      --key \"${CLIENT_KEY}\" \
      \"${HEALTH_URL}\"" 2>&1 || true
  )"
  status_line="$(printf '%s\n' "${out}" | awk 'NR==1 {print}')"

  if printf '%s\n' "${out}" | grep -Eq '^HTTP/[0-9.]+ 403 '; then
    if printf '%s\n' "${out}" | grep -q 'SUBNET_NOT_ALLOWED'; then
      echo "denied-subnet-health: PASS ${status_line}"
      exit 0
    fi

    echo "denied-subnet-health: FAIL missing SUBNET_NOT_ALLOWED marker"
    printf '%s\n' "${out}"
    exit 1
  fi

  echo "denied-subnet-health: attempt ${attempt}/${MAX_ATTEMPTS} not ready (${status_line})"
  attempt=$((attempt + 1))
  sleep "${SLEEP_SECONDS}"
done

echo "denied-subnet-health: FAIL timeout waiting for 403 from ${HEALTH_URL}"
exit 1
