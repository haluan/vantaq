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
