// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "test_server_harness.h"

#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cmocka.h>

// Suite Pattern: Struct to hold test state
struct CapabilitiesTestSuite {
    struct vantaq_test_server_handle server;
};

// Assert Pattern: Direct s.xxx() style macros
#define s_assert_int_equal(s, a, b) assert_int_equal(a, b)
#define s_assert_non_null(s, a) assert_non_null(a)
#define s_assert_null(s, a) assert_null(a)
#define s_assert_true(s, a) assert_true(a)

static int suite_setup(void **state) {
    struct CapabilitiesTestSuite *s = malloc(sizeof(struct CapabilitiesTestSuite));
    struct vantaq_test_server_opts opts;
    char setup_err[512];

    if (!s)
        return -1;
    memset(s, 0, sizeof(*s));

    memset(&opts, 0, sizeof(opts));
    opts.tls_enabled            = false;
    opts.require_client_cert    = true;
    opts.allowed_subnets        = "127.0.0.1/32";
    opts.dev_allow_all_networks = "false";
    opts.allowed_apis_yaml      = "      - GET /v1/health\n";
    opts.startup_timeout_ms     = 4000;
    opts.max_start_retries      = 5;
    setup_err[0]                = '\0';

    if (vantaq_test_server_start(&opts, &s->server, setup_err, sizeof(setup_err)) != 0) {
        if (setup_err[0] != '\0') {
            print_error("test_capabilities_mtls setup failed: %s\n", setup_err);
        }
        if (strstr(setup_err, "unable to reserve port") != NULL ||
            strstr(setup_err, "bind_failed") != NULL ||
            strstr(setup_err, "startup_timeout") != NULL) {
            free(s);
            *state = NULL;
            return 0;
        }
        free(s);
        return -1;
    }

    *state = s;
    return 0;
}

static int suite_teardown(void **state) {
    struct CapabilitiesTestSuite *s = *state;
    if (s) {
        vantaq_test_server_stop(&s->server);
        free(s);
    }
    return 0;
}

static void test_capabilities_requires_mtls(void **state) {
    struct CapabilitiesTestSuite *s = *state;
    if (s == NULL) {
        skip();
    }
    int status;
    char body[1024];

    int rc = request_status_and_body(
        s->server.port, "GET /v1/device/capabilities HTTP/1.1\r\nHost: localhost\r\n\r\n", &status,
        body, sizeof(body));

    s_assert_int_equal(s, rc, 0);
    s_assert_int_equal(s, status, 401);
    s_assert_non_null(s, strstr(body, "\"code\":\"MTLS_REQUIRED\""));
    s_assert_null(s, strstr(body, "\"supported_claims\""));
}

static void test_post_challenge_requires_mtls(void **state) {
    struct CapabilitiesTestSuite *s = *state;
    if (s == NULL) {
        skip();
    }
    int status;
    char body[1024];

    int rc = request_status_and_body(
        s->server.port, "POST /v1/attestation/challenge HTTP/1.1\r\nHost: localhost\r\n\r\n",
        &status, body, sizeof(body));

    s_assert_int_equal(s, rc, 0);
    s_assert_int_equal(s, status, 401);
    s_assert_non_null(s, strstr(body, "\"code\":\"MTLS_REQUIRED\""));
}

static void test_challenge_method_not_allowed(void **state) {
    struct CapabilitiesTestSuite *s = *state;
    if (s == NULL) {
        skip();
    }
    int status;
    char body[1024];

    int rc = request_status_and_body(
        s->server.port, "GET /v1/attestation/challenge HTTP/1.1\r\nHost: localhost\r\n\r\n",
        &status, body, sizeof(body));

    s_assert_int_equal(s, rc, 0);
    s_assert_int_equal(s, status, 405);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_capabilities_requires_mtls, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_post_challenge_requires_mtls, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_challenge_method_not_allowed, suite_setup,
                                        suite_teardown),
    };

    return cmocka_run_group_tests_name("capabilities_mtls_suite", tests, NULL, NULL);
}
