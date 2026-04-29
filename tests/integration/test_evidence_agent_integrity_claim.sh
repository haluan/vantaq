#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Haluan Irsad
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -euo pipefail

BASE_URL="${BASE_URL:-https://127.0.0.1:8443}"
CERT_PATH="${CERT_PATH:-config/certs/govt-verifier-01.crt}"
KEY_PATH="${KEY_PATH:-config/certs/govt-verifier-01.key}"
PUB_KEY_PATH="${PUB_KEY_PATH:-config/certs/device-server.crt}"

auth_post() {
  local path="$1"
  local payload="$2"
  curl -sS -k --cert "${CERT_PATH}" --key "${KEY_PATH}" \
    -H "Content-Type: application/json" \
    -X POST "${BASE_URL}${path}" -d "${payload}"
}

auth_post_status() {
  local path="$1"
  local payload="$2"
  curl -sS -k -o /tmp/vantaq_t08_resp.json -w "%{http_code}" \
    --cert "${CERT_PATH}" --key "${KEY_PATH}" \
    -H "Content-Type: application/json" \
    -X POST "${BASE_URL}${path}" -d "${payload}"
}

extract_json_field() {
  local key="$1"
  sed -n "s/.*\"${key}\":\"\([^\"]*\)\".*/\1/p"
}

echo "test-evidence-agent-integrity-claim: requesting challenge"
CH_RESP="$(auth_post "/v1/attestation/challenge" '{"purpose":"remote_attestation"}')"
CH_ID="$(echo "${CH_RESP}" | extract_json_field "challenge_id" | head -n1)"
NONCE="$(echo "${CH_RESP}" | extract_json_field "nonce" | head -n1)"

if [[ -z "${CH_ID}" || -z "${NONCE}" ]]; then
  echo "test-evidence-agent-integrity-claim: FAIL unable to parse challenge response"
  echo "${CH_RESP}"
  exit 1
fi

echo "test-evidence-agent-integrity-claim: requesting evidence with agent_integrity"
EV_RESP="$(auth_post "/v1/attestation/evidence" "{\"challenge_id\":\"${CH_ID}\",\"nonce\":\"${NONCE}\",\"claims\":[\"agent_integrity\"]}")"
if ! echo "${EV_RESP}" | grep -q '"agent_integrity":"sha256:'; then
  echo "test-evidence-agent-integrity-claim: FAIL agent_integrity missing from response"
  echo "${EV_RESP}"
  exit 1
fi

echo "${EV_RESP}" > /tmp/vantaq_t08_evidence.json
if [[ -x "./bin/verify_evidence" ]]; then
  ./bin/verify_evidence /tmp/vantaq_t08_evidence.json "${PUB_KEY_PATH}" >/dev/null
fi

echo "test-evidence-agent-integrity-claim: requesting challenge for no-claim path"
CH_RESP="$(auth_post "/v1/attestation/challenge" '{"purpose":"remote_attestation"}')"
CH_ID="$(echo "${CH_RESP}" | extract_json_field "challenge_id" | head -n1)"
NONCE="$(echo "${CH_RESP}" | extract_json_field "nonce" | head -n1)"

EV_RESP="$(auth_post "/v1/attestation/evidence" "{\"challenge_id\":\"${CH_ID}\",\"nonce\":\"${NONCE}\"}")"
if echo "${EV_RESP}" | grep -q '"agent_integrity":"sha256:'; then
  echo "test-evidence-agent-integrity-claim: FAIL agent_integrity appeared when not requested"
  echo "${EV_RESP}"
  exit 1
fi

echo "test-evidence-agent-integrity-claim: probing missing source behavior"
CH_RESP="$(auth_post "/v1/attestation/challenge" '{"purpose":"remote_attestation"}')"
CH_ID="$(echo "${CH_RESP}" | extract_json_field "challenge_id" | head -n1)"
NONCE="$(echo "${CH_RESP}" | extract_json_field "nonce" | head -n1)"
STATUS="$(auth_post_status "/v1/attestation/evidence" "{\"challenge_id\":\"${CH_ID}\",\"nonce\":\"${NONCE}\",\"claims\":[\"agent_integrity\"]}")"
if [[ "${STATUS}" == "404" ]]; then
  if ! grep -q "MEASUREMENT_SOURCE_NOT_FOUND" /tmp/vantaq_t08_resp.json; then
    echo "test-evidence-agent-integrity-claim: FAIL expected MEASUREMENT_SOURCE_NOT_FOUND"
    cat /tmp/vantaq_t08_resp.json
    exit 1
  fi
  echo "test-evidence-agent-integrity-claim: PASS missing source mapped to 404"
fi

rm -f /tmp/vantaq_t08_evidence.json /tmp/vantaq_t08_resp.json
echo "test-evidence-agent-integrity-claim: PASS"
