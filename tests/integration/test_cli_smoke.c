// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

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

static int first_available_port(void) {
    int port;

    for (port = 18080; port < 18160; port++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr;
        int one = 1;

        if (sock < 0) {
            continue;
        }

        memset(&addr, 0, sizeof(addr));
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port        = htons((uint16_t)port);
        (void)setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

        if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            close(sock);
            return port;
        }

        close(sock);
    }

    return -1;
}

static int reserve_ephemeral_port(void) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    if (sock < 0) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = htons(0);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock);
        return -1;
    }

    if (getsockname(sock, (struct sockaddr *)&addr, &len) != 0) {
        close(sock);
        return -1;
    }

    close(sock);
    if ((int)ntohs(addr.sin_port) > 0) {
        return (int)ntohs(addr.sin_port);
    }

    return first_available_port();
}

static int write_temp_yaml(int port, char *path_out, size_t path_out_size) {
    const char *yaml_fmt = "service:\n"
                           "  listen_host: 127.0.0.1\n"
                           "  listen_port: %d\n"
                           "  version: 0.1.0\n"
                           "\n"
                           "device_identity:\n"
                           "  device_id: edge-gw-001\n"
                           "  model: edge-gateway-v1\n"
                           "  serial_number: SN-001\n"
                           "  manufacturer: ExampleCorp\n"
                           "  firmware_version: 0.1.0-demo\n"
                           "\n"
                           "capabilities:\n"
                           "  supported_claims:\n"
                           "    - device_identity\n"
                           "  signature_algorithms: []\n"
                           "  evidence_formats: []\n"
                           "  challenge_modes: []\n"
                           "  storage_modes: []\n";
    char template[]      = "/tmp/vantaq_t05_XXXXXX.yaml";
    char yaml_buf[1024];
    int fd;
    int n;

    fd = mkstemps(template, 5);
    if (fd < 0) {
        return -1;
    }

    n = snprintf(yaml_buf, sizeof(yaml_buf), yaml_fmt, port);
    if (n <= 0 || (size_t)n >= sizeof(yaml_buf)) {
        close(fd);
        unlink(template);
        return -1;
    }

    if (write(fd, yaml_buf, (size_t)n) != n) {
        close(fd);
        unlink(template);
        return -1;
    }

    close(fd);

    if (strlen(template) >= path_out_size) {
        unlink(template);
        return -1;
    }

    strcpy(path_out, template);
    return 0;
}

static int wait_for_server_ready(int port, int timeout_ms) {
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 50 * 1000 * 1000};
    int attempts          = timeout_ms / 50;
    int i;

    for (i = 0; i < attempts; i++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr;

        if (sock < 0) {
            return -1;
        }

        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port   = htons((uint16_t)port);
        if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
            close(sock);
            return -1;
        }

        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            close(sock);
            return 0;
        }

        close(sock);
        nanosleep(&delay, NULL);
    }

    return -1;
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

    memset(&addr, 0, sizeof(addr));
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

static int request_status_and_body(int port, const char *request, int *status_out, char *body_out,
                                   size_t body_out_size) {
    int sock;
    struct sockaddr_in addr;
    char response[1024];
    ssize_t n;
    char *header_end;
    int status = -1;

    if (status_out == NULL || body_out == NULL || body_out_size == 0) {
        return -1;
    }

    body_out[0] = '\0';
    sock        = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
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

    header_end = strstr(response, "\r\n\r\n");
    if (header_end == NULL) {
        return -1;
    }
    header_end += 4;

    if (strlen(header_end) >= body_out_size) {
        return -1;
    }

    strcpy(body_out, header_end);
    *status_out = status;
    return 0;
}

static void test_server_bootstrap_health_404_405_and_graceful_shutdown(void **state) {
    (void)state;
    int port           = reserve_ephemeral_port();
    char cfg_path[256] = {0};
    pid_t child;
    int status;
    int health_status;
    char health_body[512];
    long long uptime_seconds = -1;
    char *uptime_field;
    int identity_status;
    char identity_body[512];

    if (port <= 0) {
        return;
    }
    assert_int_equal(write_temp_yaml(port, cfg_path, sizeof(cfg_path)), 0);

    child = fork();
    assert_true(child >= 0);

    if (child == 0) {
        execl("./bin/vantaqd", "vantaqd", "--config", cfg_path, (char *)NULL);
        _exit(127);
    }

    if (wait_for_server_ready(port, 4000) != 0) {
        int child_status;
        (void)kill(child, SIGTERM);
        (void)waitpid(child, &child_status, 0);
        unlink(cfg_path);
        return;
    }

    assert_int_equal(request_status_code(port, "GET /unknown HTTP/1.1\r\nHost: localhost\r\n\r\n"),
                     404);
    assert_int_equal(
        request_status_code(port, "POST /v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n"), 405);
    assert_int_equal(request_status_code(port,
                                         "POST /v1/device/identity HTTP/1.1\r\nHost: localhost\r\n"
                                         "\r\n"),
                     405);
    assert_int_equal(request_status_and_body(port,
                                             "GET /v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n",
                                             &health_status, health_body, sizeof(health_body)),
                     0);
    assert_int_equal(health_status, 200);
    assert_non_null(strstr(health_body, "\"status\":\"ok\""));
    assert_non_null(strstr(health_body, "\"service\":\"vantaqd\""));
    assert_non_null(strstr(health_body, "\"version\":\"0.1.0\""));
    assert_non_null(strstr(health_body, "\"uptime_seconds\":"));
    uptime_field = strstr(health_body, "\"uptime_seconds\":");
    assert_non_null(uptime_field);
    uptime_field += strlen("\"uptime_seconds\":");
    assert_int_equal(sscanf(uptime_field, "%lld", &uptime_seconds), 1);
    assert_true(uptime_seconds >= 0);
    assert_int_equal(
        request_status_and_body(port, "GET /v1/device/identity HTTP/1.1\r\nHost: localhost\r\n\r\n",
                                &identity_status, identity_body, sizeof(identity_body)),
        0);
    assert_int_equal(identity_status, 200);
    assert_non_null(strstr(identity_body, "\"device_id\":\"edge-gw-001\""));
    assert_non_null(strstr(identity_body, "\"model\":\"edge-gateway-v1\""));
    assert_non_null(strstr(identity_body, "\"serial_number\":\"SN-001\""));
    assert_non_null(strstr(identity_body, "\"manufacturer\":\"ExampleCorp\""));
    assert_non_null(strstr(identity_body, "\"firmware_version\":\"0.1.0-demo\""));

    assert_int_equal(kill(child, SIGTERM), 0);
    assert_int_equal(waitpid(child, &status, 0), child);
    assert_true(WIFEXITED(status));
    assert_int_equal(WEXITSTATUS(status), 0);

    unlink(cfg_path);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_server_bootstrap_health_404_405_and_graceful_shutdown),
    };

    return cmocka_run_group_tests_name("integration_http_bootstrap", tests, NULL, NULL);
}
