#!/usr/bin/env sh
# SPDX-FileCopyrightText: 2026 Haluan Irsad
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -eu

umask 077

if ! command -v openssl >/dev/null 2>&1; then
  echo "dev-pki: FAIL openssl command not found" >&2
  exit 1
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/../.." && pwd)"
CERT_DIR="${CERT_DIR:-${REPO_ROOT}/config/certs}"

mkdir -p "${CERT_DIR}"

KNOWN_FILES="
device-ca.crt
device-ca.key
verifier-ca.crt
verifier-ca.key
untrusted-verifier-ca.crt
untrusted-verifier-ca.key
device-server.crt
device-server.key
govt-verifier-01.crt
govt-verifier-01.key
govt-verifier-01-untrusted.crt
govt-verifier-01-untrusted.key
"

for filename in ${KNOWN_FILES}; do
  rm -f "${CERT_DIR}/${filename}"
done

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/vantaqd-dev-pki.XXXXXX")"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT INT TERM

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 -days 3650 -nodes \
  -subj "/CN=vantaqd-dev-device-ca" \
  -keyout "${CERT_DIR}/device-ca.key" \
  -out "${CERT_DIR}/device-ca.crt"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 -days 3650 -nodes \
  -subj "/CN=vantaqd-dev-verifier-ca" \
  -keyout "${CERT_DIR}/verifier-ca.key" \
  -out "${CERT_DIR}/verifier-ca.crt"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 -days 3650 -nodes \
  -subj "/CN=vantaqd-dev-untrusted-verifier-ca" \
  -keyout "${CERT_DIR}/untrusted-verifier-ca.key" \
  -out "${CERT_DIR}/untrusted-verifier-ca.crt"

openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -subj "/CN=device-1.vantaqd.local" \
  -keyout "${CERT_DIR}/device-server.key" \
  -out "${TMP_DIR}/device-server.csr"

cat > "${TMP_DIR}/device-server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:device-1,DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -sha256 -days 825 \
  -in "${TMP_DIR}/device-server.csr" \
  -CA "${CERT_DIR}/device-ca.crt" \
  -CAkey "${CERT_DIR}/device-ca.key" \
  -set_serial 1001 \
  -out "${CERT_DIR}/device-server.crt" \
  -extfile "${TMP_DIR}/device-server.ext"

openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -subj "/CN=govt-verifier-01" \
  -keyout "${CERT_DIR}/govt-verifier-01.key" \
  -out "${TMP_DIR}/govt-verifier-01.csr"

cat > "${TMP_DIR}/verifier-client.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=URI:spiffe://vantaqd/verifier/govt-verifier-01
EOF

openssl x509 -req -sha256 -days 825 \
  -in "${TMP_DIR}/govt-verifier-01.csr" \
  -CA "${CERT_DIR}/verifier-ca.crt" \
  -CAkey "${CERT_DIR}/verifier-ca.key" \
  -set_serial 2001 \
  -out "${CERT_DIR}/govt-verifier-01.crt" \
  -extfile "${TMP_DIR}/verifier-client.ext"

openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -subj "/CN=govt-verifier-01" \
  -keyout "${CERT_DIR}/govt-verifier-01-untrusted.key" \
  -out "${TMP_DIR}/govt-verifier-01-untrusted.csr"

openssl x509 -req -sha256 -days 825 \
  -in "${TMP_DIR}/govt-verifier-01-untrusted.csr" \
  -CA "${CERT_DIR}/untrusted-verifier-ca.crt" \
  -CAkey "${CERT_DIR}/untrusted-verifier-ca.key" \
  -set_serial 3001 \
  -out "${CERT_DIR}/govt-verifier-01-untrusted.crt" \
  -extfile "${TMP_DIR}/verifier-client.ext"

chmod 600 \
  "${CERT_DIR}/device-ca.key" \
  "${CERT_DIR}/verifier-ca.key" \
  "${CERT_DIR}/untrusted-verifier-ca.key" \
  "${CERT_DIR}/device-server.key" \
  "${CERT_DIR}/govt-verifier-01.key" \
  "${CERT_DIR}/govt-verifier-01-untrusted.key"

chmod 644 \
  "${CERT_DIR}/device-ca.crt" \
  "${CERT_DIR}/verifier-ca.crt" \
  "${CERT_DIR}/untrusted-verifier-ca.crt" \
  "${CERT_DIR}/device-server.crt" \
  "${CERT_DIR}/govt-verifier-01.crt" \
  "${CERT_DIR}/govt-verifier-01-untrusted.crt"

echo "dev-pki: generated certificates in ${CERT_DIR}"
