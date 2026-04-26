# syntax=docker/dockerfile:1

FROM debian:bookworm-slim AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential make cmake git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY include ./include
COPY src ./src
COPY cmake ./cmake
COPY CMakeLists.txt ./CMakeLists.txt
COPY Makefile ./Makefile

RUN make build

FROM debian:bookworm-slim AS runtime

RUN mkdir -p /etc/vantaqd \
    && cat > /etc/vantaqd/vantaqd.yaml <<'YAML'
service:
  listen_host: 0.0.0.0
  listen_port: 8080
  version: 0.1.0

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
YAML

COPY --from=builder /workspace/bin/vantaqd /usr/local/bin/vantaqd

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/vantaqd"]
CMD []
