CMAKE ?= cmake
CTEST ?= ctest
CMAKE_BUILD_DIR ?= build/cmake
COMPOSE ?= $(shell if docker compose version >/dev/null 2>&1; then echo "docker compose"; elif docker-compose version >/dev/null 2>&1; then echo "docker-compose"; else echo "docker compose"; fi)

.PHONY: all cmake-configure build test clean format dev-certs docker-device-build integration-test-subnet-allowed integration-test-subnet-denied integration-test-mtls

all: build

cmake-configure:
	$(CMAKE) -S . -B $(CMAKE_BUILD_DIR) -DVANTAQ_BUILD_TESTS=OFF

build: cmake-configure
	$(CMAKE) --build $(CMAKE_BUILD_DIR)

test:
	$(CMAKE) -S . -B $(CMAKE_BUILD_DIR) -DVANTAQ_BUILD_TESTS=ON
	$(CMAKE) --build $(CMAKE_BUILD_DIR)
	$(CTEST) --test-dir $(CMAKE_BUILD_DIR) --output-on-failure

clean:
	rm -rf $(CMAKE_BUILD_DIR) build/obj build/tests bin

format:
	@echo "Formatting C source files..."
	@find src tests -name "*.c" -o -name "*.h" | xargs clang-format -i

dev-certs:
	./scripts/dev-pki/generate-dev-certs.sh

docker-device-build:
	docker build -f docker/device/Dockerfile -t vantaqd-device:local .

integration-test-subnet-allowed:
	$(COMPOSE) up --build -d device-1
	./scripts/subnet_allowed_health_check.sh

integration-test-subnet-denied:
	$(COMPOSE) up --build -d device-1
	./scripts/subnet_denied_health_check.sh

integration-test-mtls:
	$(COMPOSE) up --build -d device-1
	./scripts/mtls_transport_smoke.sh
