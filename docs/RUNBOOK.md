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
docker compose run --rm allowed-verifier \
  --cacert /certs/device-ca.crt \
  --cert /certs/govt-verifier-01.crt \
  --key /certs/govt-verifier-01.key \
  https://device-1:8443/v1/health
docker compose run --rm allowed-verifier \
  --cacert /certs/device-ca.crt \
  --cert /certs/govt-verifier-01.crt \
  --key /certs/govt-verifier-01.key \
  https://device-1:8443/v1/device/identity
docker compose run --rm allowed-verifier \
  --cacert /certs/device-ca.crt \
  --cert /certs/govt-verifier-01.crt \
  --key /certs/govt-verifier-01.key \
  https://device-1:8443/v1/device/capabilities
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

### Allowed-Subnet Health Check

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
docker compose run --rm allowed-verifier \
  -sS -i \
  --cacert /certs/device-ca.crt \
  --cert /certs/govt-verifier-01.crt \
  --key /certs/govt-verifier-01.key \
  https://device-1:8443/v1/health
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
docker compose run --rm rogue-verifier \
  -sS -i \
  --cacert /certs/device-ca.crt \
  --cert /certs/govt-verifier-01.crt \
  --key /certs/govt-verifier-01.key \
  https://device-1:8443/v1/health
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

2. Optional smoke targets from `Makefile`:

```bash
make integration-test-mtls
make integration-test-mtls-identity
make integration-test-mtls-capabilities
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

5. Behavior:
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
  -sS --cacert /certs/device-ca.crt \
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

### Attestation Evidence API

Create signed attestation evidence bound to a previously issued challenge.

**Endpoint**: `POST /v1/attestation/evidence`

**Authorization**:
- Requires a valid mTLS certificate from an allowlisted verifier.
- The verifier must have permission to call `POST /v1/attestation/evidence` (or have `*` permissions).
- The challenge must belong to the authenticated verifier and be valid at request time.

**Request Body**:
- `challenge_id` (required): Challenge ID returned by `POST /v1/attestation/challenge`.
- `nonce` (required): Nonce returned with the challenge.
- `claims` (required): Non-empty string array of requested claims.

Supported claim names:
- `device_identity`
- `firmware_hash`
- `config_hash`
- `agent_integrity`
- `boot_state`

Notes:
- Claim names are validated against supported claim names and `capabilities.supported_claims` in `vantaqd.yaml`.
- Measurement-backed claims (`firmware_hash`, `config_hash`, `agent_integrity`, `boot_state`) require valid `measurement` paths in `vantaqd.yaml`.

**Example Request (using curl with mTLS)**:

```bash
curl --cacert ca.crt --cert verifier.crt --key verifier.key \
     -X POST -H "Content-Type: application/json" \
     -d '{"challenge_id":"<challenge-id>","nonce":"<nonce>","claims":["device_identity","firmware_hash"]}' \
     https://localhost:8443/v1/attestation/evidence
```

**Example via Docker Compose**:

```bash
docker compose run --rm allowed-verifier \
  -sS --cacert /certs/device-ca.crt \
  --cert /certs/govt-verifier-01.crt \
  --key /certs/govt-verifier-01.key \
  -X POST -H "Content-Type: application/json" \
  -d '{"challenge_id":"<challenge-id>","nonce":"<nonce>","claims":["device_identity"]}' \
  https://device-1:8443/v1/attestation/evidence
```

**Response Fields**:
Successful responses include:
- `evidence_id`
- `device_id`
- `verifier_id`
- `challenge_id`
- `nonce`
- `purpose`
- `timestamp`
- `claims`
- `signature_algorithm`
- `signature`

**Common `error.code` Values**:
- `challenge_not_found` (404)
- `challenge_expired` (409)
- `challenge_already_used` (409)
- `nonce_mismatch` (409)
- `verifier_mismatch` (403)
- `invalid_claims` (400)
- `unsupported_claim` (400)
- `claim_not_allowed` (403)
- `measurement_source_not_found` (404)
- `measurement_parse_failed` (400)

**Audit Logs**:
Evidence creation attempts (success and failure) are written to the audit log with `verifier_id` and `request_id` correlation.

### Latest Evidence API

Retrieve the latest evidence previously generated for the authenticated verifier.

**Endpoint**: `GET /v1/attestation/evidence/latest`

Compatibility note: `GET /v1/attestation/latest-evidence` is also accepted.

**Authorization**:
- Requires a valid mTLS certificate from an allowlisted verifier.
- The verifier must have permission to call `GET /v1/attestation/latest-evidence` (or have `*` permissions).
- Responses are scoped to the authenticated verifier identity.

**Behavior**:
- Returns the same JSON shape as `POST /v1/attestation/evidence`.
- Returns `404` when no evidence has been stored yet for that verifier.

**Example via Docker Compose**:

```bash
docker compose run --rm allowed-verifier \
  -sS --cacert /certs/device-ca.crt \
  --cert /certs/govt-verifier-01.crt \
  --key /certs/govt-verifier-01.key \
  https://device-1:8443/v1/attestation/evidence/latest
```

**Configuration (`vantaqd.yaml`)**:

```yaml
verifiers:
  - verifier_id: govt-verifier-01
    allowed_apis:
      - POST /v1/attestation/evidence
      - GET /v1/attestation/evidence/latest
```

### Evidence by ID API

Retrieve one stored evidence document by its evidence ID for the authenticated verifier.

**Endpoint**: `GET /v1/attestation/evidence/{evidence_id}`

**Authorization**:
- Requires a valid mTLS certificate from an allowlisted verifier.
- The verifier must have permission to call `GET /v1/attestation/evidence/{evidence_id}` (or have `*` permissions).
- Responses are scoped to the authenticated verifier identity; evidence owned by another verifier is not returned.

**Path Rules**:
- `evidence_id` must be non-empty and within the server max length.
- Path traversal and encoded traversal patterns are rejected (`/`, `%`, `..` in the path segment).

**Behavior**:
- Returns `200` with the same evidence JSON shape as `POST /v1/attestation/evidence` when found.
- Returns `404` when the evidence ID does not exist for that verifier.
- Returns `400` for invalid `evidence_id` path format.

**Example via Docker Compose**:

```bash
docker compose run --rm allowed-verifier \
  -sS --cacert /certs/device-ca.crt \
  --cert /certs/govt-verifier-01.crt \
  --key /certs/govt-verifier-01.key \
  https://device-1:8443/v1/attestation/evidence/<evidence-id>
```

### Verifier CLI Signature Verification

Use `bin/verify_evidence` to verify evidence signatures off-device.

1. Build binaries:

```bash
make build
```

2. Verify evidence:

```bash
./bin/verify_evidence <evidence.json> <device-public-key-or-cert.pem>
```

References:
- `tools/verifier-cli/README.md`
- `tests/integration/test_verifier_cli_verify_evidence.sh`
