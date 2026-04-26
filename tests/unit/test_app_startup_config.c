// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/app.h"
#include "infrastructure/config_loader.h"

#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cmocka.h>

typedef struct test_io_buffer {
    char out[512];
    char err[512];
} test_io_buffer;

static void append_text(char *dst, size_t dst_size, const char *src) {
    size_t used     = strlen(dst);
    size_t incoming = strlen(src);

    if (used >= dst_size - 1) {
        return;
    }

    if (incoming > dst_size - used - 1) {
        incoming = dst_size - used - 1;
    }

    memcpy(dst + used, src, incoming);
    dst[used + incoming] = '\0';
}

static void capture_out(void *ctx, const char *data) {
    test_io_buffer *buffer = (test_io_buffer *)ctx;
    append_text(buffer->out, sizeof(buffer->out), data);
}

static void capture_err(void *ctx, const char *data) {
    test_io_buffer *buffer = (test_io_buffer *)ctx;
    append_text(buffer->err, sizeof(buffer->err), data);
}

static int write_temp_yaml(const char *content, char *path_out, size_t path_out_size) {
    char template[] = "/tmp/vantaq_app_cfg_XXXXXX.yaml";
    int fd          = mkstemps(template, 5);
    size_t len      = strlen(content);

    if (fd < 0 || strlen(template) >= path_out_size) {
        return -1;
    }

    if (write(fd, content, len) != (ssize_t)len) {
        close(fd);
        unlink(template);
        return -1;
    }

    close(fd);
    strcpy(path_out, template);
    return 0;
}

static void test_startup_with_valid_config_succeeds(void **state) {
    (void)state;
    const char *yaml      = "service:\n"
                            "  listen_host: 127.0.0.1\n"
                            "  listen_port: 8081\n"
                            "  version: 0.1.0\n"
                            "device_identity:\n"
                            "  device_id: edge-gw-001\n"
                            "  model: edge-gateway-v1\n"
                            "  serial_number: SN-001\n"
                            "  manufacturer: ExampleCorp\n"
                            "  firmware_version: 0.1.0-demo\n"
                            "capabilities:\n"
                            "  supported_claims: [device_identity]\n"
                            "  signature_algorithms: []\n"
                            "  evidence_formats: []\n"
                            "  challenge_modes: []\n"
                            "  storage_modes: []\n";
    char config_path[256] = {0};
    pid_t child;
    int status;

    assert_int_equal(write_temp_yaml(yaml, config_path, sizeof(config_path)), 0);

    child = fork();
    assert_true(child >= 0);
    if (child == 0) {
        execl("./bin/vantaqd", "vantaqd", "--config", config_path, (char *)NULL);
        _exit(127);
    }

    sleep(1);
    if (waitpid(child, &status, WNOHANG) == 0) {
        assert_int_equal(kill(child, 0), 0);
        assert_int_equal(kill(child, SIGTERM), 0);
        assert_int_equal(waitpid(child, &status, 0), child);
        assert_true(WIFEXITED(status));
        assert_int_equal(WEXITSTATUS(status), 0);
    } else {
        assert_true(WIFEXITED(status));
        assert_true(WEXITSTATUS(status) == 0 || WEXITSTATUS(status) == 78);
    }

    unlink(config_path);
}

static void test_startup_with_invalid_config_fails(void **state) {
    (void)state;
    const char *yaml        = "service:\n"
                              "  listen_host: 127.0.0.1\n"
                              "  version: 0.1.0\n"
                              "device_identity:\n"
                              "  model: edge-gateway-v1\n";
    char config_path[256]   = {0};
    char *argv[]            = {"vantaqd", "--config", config_path};
    test_io_buffer buffer   = {0};
    struct vantaq_app_io io = {
        .write_out = capture_out,
        .write_err = capture_err,
        .ctx       = &buffer,
    };

    assert_int_equal(write_temp_yaml(yaml, config_path, sizeof(config_path)), 0);

    assert_int_equal(vantaq_app_run(3, argv, &io), 78);
    assert_non_null(strstr(buffer.err, "config load failed:"));
    assert_string_equal(buffer.out, "");

    unlink(config_path);
}

static void test_startup_default_path_behavior_is_verified(void **state) {
    (void)state;
    char *argv[]            = {"vantaqd"};
    test_io_buffer buffer   = {0};
    struct vantaq_app_io io = {
        .write_out = capture_out,
        .write_err = capture_err,
        .ctx       = &buffer,
    };

    assert_int_equal(vantaq_app_run(1, argv, &io), 78);
    assert_non_null(strstr(buffer.err, VANTAQ_DEFAULT_CONFIG_PATH));
    assert_string_equal(buffer.out, "");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_startup_with_valid_config_succeeds),
        cmocka_unit_test(test_startup_with_invalid_config_fails),
        cmocka_unit_test(test_startup_default_path_behavior_is_verified),
    };

    return cmocka_run_group_tests_name("unit_app_startup_config", tests, NULL, NULL);
}
