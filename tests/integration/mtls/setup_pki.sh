#!/usr/bin/env sh
# SPDX-FileCopyrightText: 2026 Haluan Irsad
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -eu

CERT_DIR="$1"
mkdir -p "${CERT_DIR}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

# 1. Root CAs
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
  -subj "/CN=vantaq-test-device-ca" \
  -keyout "${CERT_DIR}/device-ca.key" \
  -out "${CERT_DIR}/device-ca.crt"

openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
  -subj "/CN=vantaq-test-verifier-ca" \
  -keyout "${CERT_DIR}/verifier-ca.key" \
  -out "${CERT_DIR}/verifier-ca.crt"

openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
  -subj "/CN=vantaq-test-untrusted-ca" \
  -keyout "${CERT_DIR}/untrusted-ca.key" \
  -out "${CERT_DIR}/untrusted-ca.crt"

# 2. Server Cert
openssl req -new -newkey rsa:2048 -nodes \
  -subj "/CN=vantaqd-server" \
  -keyout "${CERT_DIR}/device-server.key" \
  -out "${TMP_DIR}/device-server.csr"

cat > "${TMP_DIR}/device-server.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:vantaqd-server,DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -sha256 -days 365 \
  -in "${TMP_DIR}/device-server.csr" \
  -CA "${CERT_DIR}/device-ca.crt" \
  -CAkey "${CERT_DIR}/device-ca.key" \
  -set_serial 1 \
  -out "${CERT_DIR}/device-server.crt" \
  -extfile "${TMP_DIR}/device-server.ext"

# 3. Client Certs
gen_client() {
    name="$1"
    id="$2"
    ca_name="${3:-verifier}"
    
    openssl req -new -newkey rsa:2048 -nodes \
      -subj "/CN=${name}" \
      -keyout "${CERT_DIR}/${name}.key" \
      -out "${TMP_DIR}/${name}.csr"

    cat > "${TMP_DIR}/${name}.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectAltName=URI:spiffe://vantaqd/verifier/${id}
EOF

    openssl x509 -req -sha256 -days 365 \
      -in "${TMP_DIR}/${name}.csr" \
      -CA "${CERT_DIR}/${ca_name}-ca.crt" \
      -CAkey "${CERT_DIR}/${ca_name}-ca.key" \
      -set_serial $(date +%s%N | cut -c1-9) \
      -out "${CERT_DIR}/${name}.crt" \
      -extfile "${TMP_DIR}/${name}.ext"
}

gen_client "govt-verifier-01" "govt-verifier-01"
gen_client "admin-verifier" "admin-verifier"
gen_client "untrusted-verifier" "govt-verifier-01" "untrusted"
gen_client "unknown-verifier-99" "unknown-verifier-99"

echo "PKI setup complete in ${CERT_DIR}"
