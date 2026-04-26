CMAKE ?= cmake
CTEST ?= ctest
CMAKE_BUILD_DIR ?= build/cmake

.PHONY: all cmake-configure build test clean format docker-device-build

all: build

cmake-configure:
	$(CMAKE) -S . -B $(CMAKE_BUILD_DIR)

build: cmake-configure
	$(CMAKE) --build $(CMAKE_BUILD_DIR)

test: build
	$(CTEST) --test-dir $(CMAKE_BUILD_DIR) --output-on-failure

clean:
	rm -rf $(CMAKE_BUILD_DIR) build/obj build/tests bin

format:
	@echo "Formatting C source files..."
	@find src tests -name "*.c" -o -name "*.h" | xargs clang-format -i

docker-device-build:
	docker build -f docker/device/Dockerfile -t vantaqd-device:local .
