# Vantaq Runbook

## Prerequisites

- C toolchain + CMake + Make
- Docker + Docker Compose

## Run `vantaqd` Locally

1. Build:

```bash
make build
```

2. Run with default config path:

```bash
./bin/vantaqd
```

3. Run with explicit config path:

```bash
./bin/vantaqd --config ./config/device-1/vantaqd.yaml
```

4. Check version:

```bash
./bin/vantaqd --version
```

## Run `vantaqd` in Docker Compose

1. Start device:

```bash
docker compose up --build -d device-1
```

2. Verify endpoints from verifier container:

```bash
docker compose run --rm verifier-cli http://device-1:8080/v1/health
docker compose run --rm verifier-cli http://device-1:8080/v1/device/identity
docker compose run --rm verifier-cli http://device-1:8080/v1/device/capabilities
```

3. Stop environment:

```bash
docker compose down
```

## Run Integration Tests

### Local C Test Suite

```bash
make test
```

### Compose Test-Runner Integration Checks

1. Start device:

```bash
docker compose up --build -d device-1
```

2. Run integration checks:

```bash
docker compose build test-runner
docker compose run --rm test-runner
```

3. Stop environment:

```bash
docker compose down
```

### Verifier CLI Evidence Integration

Run `tests/integration/test_verifier_cli_verify_evidence.sh` with a single daemon context for all steps.
Do not mix `docker-compose` steps on one daemon with script execution on another daemon.
Use container recreation instead of `restart` when picking up new image builds.

1. Docker daemon flow:

```bash
docker-compose up --build -d --force-recreate device-1
ENSURE_DEVICE=0 ./tests/integration/test_verifier_cli_verify_evidence.sh
```

2. Podman socket flow (apply the same `DOCKER_HOST` to all steps):

```bash
export DOCKER_HOST=unix:///var/folders/yw/c4ymmzxs23j3ww74wqpw9txm0000gn/T/podman/podman-machine-default-api.sock
docker-compose up --build -d --force-recreate device-1
ENSURE_DEVICE=0 ./tests/integration/test_verifier_cli_verify_evidence.sh
```

3. Optional script-managed lifecycle:

```bash
ENSURE_DEVICE=1 DEVICE_READY_SLEEP_SECONDS=3 ./tests/integration/test_verifier_cli_verify_evidence.sh
```

### Allowed-Subnet Health Check (T09)

#### Via Local Make (Host Network)

1. Run the canonical host command:

```bash
make integration-test-subnet-allowed
```

2. Expected result:

```text
PASS (HTTP 200 and health payload contains status=ok)
```

#### Via Docker Compose (Allowed Network)

1. Ensure the environment is up:

```bash
docker compose up -d device-1
```

2. Run curl from the `allowed-verifier` container:

```bash
docker compose run --rm allowed-verifier http://10.50.10.10:8080/v1/health
```

3. Expected result:

```text
PASS (HTTP 200)
```

### Denied-Subnet Health Check (T10)

#### Via Local Make (Host Network)

1. Run the canonical host command:

```bash
make integration-test-subnet-denied
```

2. Expected result:

```text
PASS (HTTP 403 and error payload contains SUBNET_NOT_ALLOWED)
```

#### Via Docker Compose (Denied Network)

1. Ensure the environment is up:

```bash
docker compose up -d device-1
```

2. Run curl from the `rogue-verifier` container:

```bash
docker compose run --rm rogue-verifier http://10.60.10.10:8080/v1/health
```

3. Expected result:

```text
FAIL/DENIED (HTTP 403)
```

### mTLS Integration Tests

This suite validates mTLS enforcement, verifier allowlisting, and Metadata API authorization.

1. Run the automated suite:

```bash
make test-mtls
```

#### Manual Execution via Docker Compose

If you need to debug the mTLS environment:

1. Generate the test certificates:

```bash
./tests/integration/mtls/setup_pki.sh ./tests/integration/mtls/certs
```

2. Start the environment:

```bash
docker compose -f tests/integration/mtls/docker-compose.yml up --build
```

3. Run the tests:

```bash
docker compose -f tests/integration/mtls/docker-compose.yml run --rm test-runner
```

4. Clean up:

```bash
docker compose -f tests/integration/mtls/docker-compose.yml down
rm -rf tests/integration/mtls/certs
```

2. Behavior:
   - Automatically generates test PKI certificates.
   - Spins up `vantaqd` and a `test-runner` in Docker.
   - Validates:
     - Successful access with valid verifier cert.
     - Rejection of missing/untrusted certificates.
     - Rejection of unknown Verifier IDs (403).
     - Role-based access to Verifier Metadata API.
     - Attestation Challenge API (creation, audit, binding, uniqueness, and expiry).

### Verifier Metadata API

Retrieve metadata for a specific verifier.

**Endpoint**: `GET /v1/security/verifiers/{verifier_id}`

**Authorization**:
- Verifiers can query their own metadata.
- Users with `owner-admin` role (configurable) can query any verifier.

**Example Request (using curl with mTLS)**:

```bash
curl --cacert ca.crt --cert verifier.crt --key verifier.key \
     https://localhost:8443/v1/security/verifiers/govt-verifier-01
```

### Attestation Challenge API

Request a new cryptographic challenge for remote attestation.

**Endpoint**: `POST /v1/attestation/challenge`

**Authorization**:
- Requires a valid mTLS certificate from an allowlisted verifier.
- The verifier must have permission to call `POST /v1/attestation/challenge` (or have `*` permissions).
- Identity is automatically bound from the certificate; the server rejects spoofed `verifier_id` in the request body.

**Example Request (using curl with mTLS)**:

```bash
curl --cacert ca.crt --cert verifier.crt --key verifier.key \
     -X POST -H "Content-Type: application/json" \
     -d '{"purpose": "remote_attestation", "requested_ttl_seconds": 60}' \
     https://localhost:8443/v1/attestation/challenge
```

**Example via Docker Compose**:

```bash
docker compose run --rm allowed-verifier \
  curl -s --cacert /certs/device-ca.crt \
       --cert /certs/govt-verifier-01.crt \
       --key /certs/govt-verifier-01.key \
       -X POST -H "Content-Type: application/json" \
       -d '{"purpose": "remote_attestation"}' \
       https://device-1:8443/v1/attestation/challenge
```

**Configuration (`vantaqd.yaml`)**:

```yaml
challenge:
  ttl_seconds: 30       # Default TTL if not specified by client
  max_global: 1000      # Global capacity limit for pending challenges
  max_per_verifier: 100 # Per-verifier capacity limit
```

**Audit Logs**:
Challenge creation attempts (success and failure) are logged to the audit log with `verifier_id` and `request_id` correlation.
