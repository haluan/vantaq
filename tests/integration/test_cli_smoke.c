// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/memory/zero_struct.h"
#include "test_server_harness.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <cmocka.h>

static int read_text_file(const char *path, char *out, size_t out_size) {
    FILE *file;
    size_t n;

    if (path == NULL || out == NULL || out_size == 0) {
        return -1;
    }

    file = fopen(path, "rb");
    if (file == NULL) {
        return -1;
    }

    n      = fread(out, 1, out_size - 1, file);
    out[n] = '\0';
    fclose(file);
    return 0;
}

static int request_status_code(int port, const char *request) {
    int sock;
    struct sockaddr_in addr;
    char response[512];
    ssize_t n;
    int status = -1;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }

    VANTAQ_ZERO_STRUCT(addr);
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock);
        return -1;
    }

    if (write(sock, request, strlen(request)) < 0) {
        close(sock);
        return -1;
    }

    n = read(sock, response, sizeof(response) - 1);
    close(sock);
    if (n <= 0) {
        return -1;
    }

    response[n] = '\0';
    if (sscanf(response, "HTTP/1.1 %d", &status) != 1) {
        return -1;
    }

    return status;
}

static void test_server_bootstrap_health_404_405_and_graceful_shutdown(void **state) {
    (void)state;
    struct vantaq_test_server_opts opts;
    struct vantaq_test_server_handle server;
    char setup_err[512];
    int health_status;
    char health_body[512];
    int identity_status;
    char identity_body[512];
    int capabilities_status;
    char capabilities_body[768];

    VANTAQ_ZERO_STRUCT(opts);
    VANTAQ_ZERO_STRUCT(server);
    opts.tls_enabled            = false;
    opts.require_client_cert    = true;
    opts.include_challenge      = false;
    opts.allowed_subnets        = "127.0.0.1/32";
    opts.dev_allow_all_networks = "false";
    opts.allowed_apis_yaml      = "      - GET /v1/health\n";
    opts.startup_timeout_ms     = 4000;
    opts.max_start_retries      = 5;
    setup_err[0]                = '\0';

    if (vantaq_test_server_start(&opts, &server, setup_err, sizeof(setup_err)) != 0) {
        if (strstr(setup_err, "unable to reserve port") != NULL ||
            strstr(setup_err, "bind_failed") != NULL ||
            strstr(setup_err, "startup_timeout") != NULL) {
            skip();
        }
        fail_msg("test_cli_smoke setup failed: %s", setup_err[0] != '\0' ? setup_err : "unknown");
    }

    assert_int_equal(
        request_status_code(server.port, "GET /unknown HTTP/1.1\r\nHost: localhost\r\n\r\n"), 404);
    assert_int_equal(
        request_status_code(server.port, "POST /v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n"),
        405);
    assert_int_equal(request_status_code(server.port,
                                         "POST /v1/device/identity HTTP/1.1\r\nHost: localhost\r\n"
                                         "\r\n"),
                     405);
    assert_int_equal(
        request_status_code(server.port,
                            "POST /v1/device/capabilities HTTP/1.1\r\nHost: localhost\r\n\r\n"),
        405);
    assert_int_equal(request_status_and_body(server.port,
                                             "GET /v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n",
                                             &health_status, health_body, sizeof(health_body)),
                     0);
    assert_int_equal(health_status, 401);
    assert_non_null(strstr(health_body, "\"error\""));
    assert_non_null(strstr(health_body, "\"code\":\"MTLS_REQUIRED\""));
    assert_non_null(
        strstr(health_body, "\"message\":\"Valid verifier client certificate is required.\""));
    assert_null(strstr(health_body, "\"status\":\"ok\""));
    assert_null(strstr(health_body, "\"service\":\"vantaqd\""));
    assert_null(strstr(health_body, "\"version\":\"0.1.0\""));
    assert_null(strstr(health_body, "\"uptime_seconds\":"));
    assert_int_equal(request_status_and_body(
                         server.port, "GET /v1/device/identity HTTP/1.1\r\nHost: localhost\r\n\r\n",
                         &identity_status, identity_body, sizeof(identity_body)),
                     0);
    assert_int_equal(identity_status, 401);
    assert_non_null(strstr(identity_body, "\"error\""));
    assert_non_null(strstr(identity_body, "\"code\":\"MTLS_REQUIRED\""));
    assert_non_null(
        strstr(identity_body, "\"message\":\"Valid verifier client certificate is required.\""));
    assert_null(strstr(identity_body, "\"device_id\":"));
    assert_null(strstr(identity_body, "\"model\":"));
    assert_null(strstr(identity_body, "\"serial_number\":"));
    assert_null(strstr(identity_body, "\"manufacturer\":"));
    assert_null(strstr(identity_body, "\"firmware_version\":"));
    assert_int_equal(
        request_status_and_body(server.port,
                                "GET /v1/device/capabilities HTTP/1.1\r\nHost: localhost\r\n\r\n",
                                &capabilities_status, capabilities_body, sizeof(capabilities_body)),
        0);
    assert_int_equal(capabilities_status, 401);
    assert_non_null(strstr(capabilities_body, "\"error\""));
    assert_non_null(strstr(capabilities_body, "\"code\":\"MTLS_REQUIRED\""));
    assert_non_null(strstr(capabilities_body,
                           "\"message\":\"Valid verifier client certificate is required.\""));
    assert_null(strstr(capabilities_body, "\"supported_claims\":"));

    vantaq_test_server_stop(&server);
}

static void test_health_denied_for_disallowed_subnet(void **state) {
    (void)state;
    struct vantaq_test_server_opts opts;
    struct vantaq_test_server_handle server;
    char setup_err[512];
    char audit_text[2048];
    int health_status;
    char health_body[512];
    int identity_status;
    char identity_body[512];

    VANTAQ_ZERO_STRUCT(opts);
    VANTAQ_ZERO_STRUCT(server);
    opts.tls_enabled            = false;
    opts.require_client_cert    = true;
    opts.include_challenge      = false;
    opts.allowed_subnets        = "10.50.10.0/24";
    opts.dev_allow_all_networks = "false";
    opts.allowed_apis_yaml      = "      - GET /v1/health\n";
    opts.startup_timeout_ms     = 4000;
    opts.max_start_retries      = 5;
    setup_err[0]                = '\0';

    if (vantaq_test_server_start(&opts, &server, setup_err, sizeof(setup_err)) != 0) {
        if (strstr(setup_err, "unable to reserve port") != NULL ||
            strstr(setup_err, "bind_failed") != NULL ||
            strstr(setup_err, "startup_timeout") != NULL) {
            skip();
        }
        fail_msg("test_cli_smoke setup failed: %s", setup_err[0] != '\0' ? setup_err : "unknown");
    }

    assert_int_equal(request_status_and_body(server.port,
                                             "GET /v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n",
                                             &health_status, health_body, sizeof(health_body)),
                     0);
    assert_int_equal(health_status, 403);
    assert_non_null(strstr(health_body, "\"error\""));
    assert_non_null(strstr(health_body, "\"code\":\"SUBNET_NOT_ALLOWED\""));
    assert_non_null(
        strstr(health_body, "\"message\":\"Requester source network is not allowed.\""));
    assert_non_null(strstr(health_body, "\"request_id\":\"req-"));
    assert_null(strstr(health_body, "\"status\":\"ok\""));

    assert_int_equal(request_status_and_body(
                         server.port, "GET /v1/device/identity HTTP/1.1\r\nHost: localhost\r\n\r\n",
                         &identity_status, identity_body, sizeof(identity_body)),
                     0);
    assert_int_equal(identity_status, 403);
    assert_non_null(strstr(identity_body, "\"error\""));
    assert_non_null(strstr(identity_body, "\"code\":\"SUBNET_NOT_ALLOWED\""));
    assert_non_null(
        strstr(identity_body, "\"message\":\"Requester source network is not allowed.\""));
    assert_non_null(strstr(identity_body, "\"request_id\":\"req-"));
    assert_null(strstr(identity_body, "\"device_id\":"));
    assert_null(strstr(identity_body, "\"model\":"));
    assert_null(strstr(identity_body, "\"serial_number\":"));
    assert_null(strstr(identity_body, "\"manufacturer\":"));
    assert_null(strstr(identity_body, "\"firmware_version\":"));

    assert_int_equal(
        request_status_code(server.port, "POST /v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n"),
        405);
    assert_int_equal(request_status_code(server.port,
                                         "POST /v1/device/identity HTTP/1.1\r\nHost: localhost\r\n"
                                         "\r\n"),
                     405);
    assert_int_equal(
        request_status_code(server.port, "GET /unknown HTTP/1.1\r\nHost: localhost\r\n\r\n"), 404);

    assert_int_equal(read_text_file(server.audit_path, audit_text, sizeof(audit_text)), 0);
    assert_non_null(strstr(audit_text, "\"source_ip\":\"127.0.0.1\""));
    assert_non_null(strstr(audit_text, "\"method\":\"GET\""));
    assert_non_null(strstr(audit_text, "\"path\":\"/v1/health\""));
    assert_non_null(strstr(audit_text, "\"result\":\"DENY\""));
    assert_non_null(strstr(audit_text, "\"reason\":\"SUBNET_NOT_ALLOWED\""));
    assert_non_null(strstr(audit_text, "\"request_id\":\"req-"));
    assert_non_null(strstr(audit_text, "\"time\":\""));

    vantaq_test_server_stop(&server);
}

#ifndef DISABLE_TEST_MAIN
int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_server_bootstrap_health_404_405_and_graceful_shutdown),
        cmocka_unit_test(test_health_denied_for_disallowed_subnet),
    };

    return cmocka_run_group_tests_name("integration_http_bootstrap", tests, NULL, NULL);
}
#endif
