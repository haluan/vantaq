CC ?= cc
CSTD ?= -std=c17
WARN ?= -Wall -Wextra -Wpedantic
OPT ?= -O2
CPPFLAGS += -Iinclude
CFLAGS ?= $(CSTD) $(WARN) $(OPT)

TARGET := bin/vantaqd
OBJ_DIR := build/obj
TEST_DIR := build/tests

APP_SRCS := \
	src/application/app.c \
	src/domain/version.c \
	src/infrastructure/stdio_io.c

MAIN_SRC := src/main.c
APP_OBJS := $(APP_SRCS:src/%.c=$(OBJ_DIR)/%.o)
MAIN_OBJ := $(MAIN_SRC:src/%.c=$(OBJ_DIR)/%.o)

UNIT_TEST_BIN := $(TEST_DIR)/unit/test_app_version
INTEG_TEST_BIN := $(TEST_DIR)/integration/test_cli_smoke

CMOCKA_CFLAGS := $(shell pkg-config --cflags cmocka 2>/dev/null)
CMOCKA_LIBS := $(shell pkg-config --libs cmocka 2>/dev/null || printf '%s' '-lcmocka')

.PHONY: all format build clean test docker-device-build

all: build

format:
	@echo "Formatting C source files..."
	@find src tests -name "*.c" -o -name "*.h" | xargs clang-format -i

build: $(TARGET)

$(TARGET): $(MAIN_OBJ) $(APP_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(MAIN_OBJ) $(APP_OBJS) -o $@

$(OBJ_DIR)/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(UNIT_TEST_BIN): tests/unit/test_app_version.c src/application/app.c src/domain/version.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CMOCKA_CFLAGS) $^ $(CMOCKA_LIBS) -o $@

$(INTEG_TEST_BIN): tests/integration/test_cli_smoke.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CMOCKA_CFLAGS) $^ $(CMOCKA_LIBS) -o $@

test: build $(UNIT_TEST_BIN) $(INTEG_TEST_BIN)
	./$(UNIT_TEST_BIN)
	./$(INTEG_TEST_BIN)

clean:
	rm -rf build bin

docker-device-build:
	docker build -f docker/device/Dockerfile -t vantaqd-device:local .
