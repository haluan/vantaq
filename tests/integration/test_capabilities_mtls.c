// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

// clang-format off
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>
// clang-format on
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// Suite Pattern: Struct to hold test state
struct CapabilitiesTestSuite {
    int port;
    char cfg_path[256];
    pid_t child_pid;
};

// Assert Pattern: Direct s.xxx() style macros
#define s_assert_int_equal(s, a, b) assert_int_equal(a, b)
#define s_assert_non_null(s, a) assert_non_null(a)
#define s_assert_null(s, a) assert_null(a)
#define s_assert_true(s, a) assert_true(a)

// Forward declarations of helpers usually found in test_cli_smoke.c
// In a real scenario, these would be in a shared test library.
extern int reserve_ephemeral_port(void);
extern int write_temp_yaml(int port, const char *allowed_subnets, const char *dev_allow_all,
                           char *path_out, size_t path_out_size);
extern int wait_for_server_ready(int port, int timeout_ms);
extern int request_status_and_body(int port, const char *request, int *status_out, char *body_out,
                                   size_t body_out_size);

static int suite_setup(void **state) {
    struct CapabilitiesTestSuite *s = malloc(sizeof(struct CapabilitiesTestSuite));
    if (!s)
        return -1;

    s->port = reserve_ephemeral_port();
    if (s->port <= 0) {
        free(s);
        return -1;
    }

    if (write_temp_yaml(s->port, "127.0.0.1/32", "false", s->cfg_path, sizeof(s->cfg_path)) != 0) {
        free(s);
        return -1;
    }

    s->child_pid = fork();
    if (s->child_pid < 0) {
        free(s);
        return -1;
    }

    if (s->child_pid == 0) {
        execl("./bin/vantaqd", "vantaqd", "--config", s->cfg_path, (char *)NULL);
        _exit(127);
    }

    if (wait_for_server_ready(s->port, 4000) != 0) {
        kill(s->child_pid, SIGTERM);
        waitpid(s->child_pid, NULL, 0);
        unlink(s->cfg_path);
        free(s);
        return -1;
    }

    *state = s;
    return 0;
}

static int suite_teardown(void **state) {
    struct CapabilitiesTestSuite *s = *state;
    if (s) {
        kill(s->child_pid, SIGTERM);
        waitpid(s->child_pid, NULL, 0);
        unlink(s->cfg_path);
        free(s);
    }
    return 0;
}

static void test_capabilities_requires_mtls(void **state) {
    struct CapabilitiesTestSuite *s = *state;
    int status;
    char body[1024];

    int rc = request_status_and_body(
        s->port, "GET /v1/device/capabilities HTTP/1.1\r\nHost: localhost\r\n\r\n", &status, body,
        sizeof(body));

    s_assert_int_equal(s, rc, 0);
    s_assert_int_equal(s, status, 401);
    s_assert_non_null(s, strstr(body, "\"code\":\"MTLS_REQUIRED\""));
    s_assert_null(s, strstr(body, "\"supported_claims\""));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_capabilities_requires_mtls, suite_setup,
                                        suite_teardown),
    };

    return cmocka_run_group_tests_name("capabilities_mtls_suite", tests, NULL, NULL);
}
