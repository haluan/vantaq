# syntax=docker/dockerfile:1

FROM debian:bookworm-slim AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential make cmake git libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY include ./include
COPY src ./src
COPY cmake ./cmake
COPY CMakeLists.txt ./CMakeLists.txt
COPY Makefile ./Makefile

RUN make build

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/vantaqd \
    && cat > /etc/vantaqd/vantaqd.yaml <<'YAML'
server:
  listen_address: 0.0.0.0
  listen_port: 8443
  version: 0.1.0
  tls:
    enabled: true
    server_cert_path: /etc/vantaqd/certs/device-server.crt
    server_key_path: /etc/vantaqd/certs/device-server.key
    trusted_client_ca_path: /etc/vantaqd/certs/verifier-ca.crt
    require_client_cert: true

verifiers:
  - verifier_id: govt-verifier-01
    cert_subject_cn: govt-verifier-01
    cert_san_uri: spiffe://vantaqd/verifier/govt-verifier-01
    status: active
    roles:
      - verifier
    allowed_apis:
      - GET /v1/health
      - GET /v1/device/identity
      - GET /v1/device/capabilities
      - GET /v1/security/verifiers/{verifier_id}

device_identity:
  device_id: edge-gw-001
  model: edge-gateway-v1
  serial_number: SN-001
  manufacturer: ExampleCorp
  firmware_version: 0.1.0-demo

capabilities:
  supported_claims:
    - device_identity
  signature_algorithms: []
  evidence_formats: []
  challenge_modes: []
  storage_modes: []

network_access:
  allowed_subnets: []
  dev_allow_all_networks: true

audit:
  max_bytes: 65536
  path: /var/lib/vantaqd/audit.log
YAML

COPY --from=builder /workspace/bin/vantaqd /usr/local/bin/vantaqd

EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/vantaqd"]
CMD []
