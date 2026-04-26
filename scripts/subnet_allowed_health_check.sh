#!/usr/bin/env sh
# SPDX-FileCopyrightText: 2026 Haluan Irsad
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -eu

MAX_ATTEMPTS="${MAX_ATTEMPTS:-30}"
SLEEP_SECONDS="${SLEEP_SECONDS:-1}"
HEALTH_URL="${HEALTH_URL:-http://device-1:8080/v1/health}"
COMPOSE_CMD="${COMPOSE_CMD:-}"

if [ -z "${COMPOSE_CMD}" ]; then
  if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
  elif docker-compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
  else
    echo "allowed-subnet-health: FAIL docker compose command not found"
    exit 1
  fi
fi

attempt=1

echo "allowed-subnet-health: waiting for ${HEALTH_URL}"

while [ "${attempt}" -le "${MAX_ATTEMPTS}" ]; do
  out="$(sh -c "${COMPOSE_CMD} run --rm allowed-verifier -sS -i \"${HEALTH_URL}\"" 2>&1 || true)"
  status_line="$(printf '%s\n' "${out}" | awk 'NR==1 {print}')"

  if printf '%s\n' "${out}" | grep -Eq '^HTTP/[0-9.]+ 200 '; then
    if printf '%s\n' "${out}" | grep -Eq '"status"[[:space:]]*:[[:space:]]*"ok"'; then
      echo "allowed-subnet-health: PASS ${status_line}"
      exit 0
    fi

    echo "allowed-subnet-health: FAIL status marker missing"
    printf '%s\n' "${out}"
    exit 1
  fi

  echo "allowed-subnet-health: attempt ${attempt}/${MAX_ATTEMPTS} not ready (${status_line})"
  attempt=$((attempt + 1))
  sleep "${SLEEP_SECONDS}"
done

echo "allowed-subnet-health: FAIL timeout waiting for 200 OK from ${HEALTH_URL}"
exit 1
