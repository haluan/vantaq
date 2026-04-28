// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/memory/zero_struct.h"

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
#include <time.h>
#include <unistd.h>

#include <cmocka.h>

struct ReplayedChallengeTestSuite {
    int port;
    char cfg_path[256];
    char audit_path[256];
    pid_t child_pid;
};

#define s_assert_int_equal(s, a, b) assert_int_equal(a, b)
#define s_assert_non_null(s, a) assert_non_null(a)
#define s_assert_true(s, a) assert_true(a)
#define s_assert_null(s, a) assert_null(a)

// Externs from test_cli_smoke.c
extern int reserve_ephemeral_port(void);
extern int make_temp_audit_path(char *path_out, size_t path_out_size);
extern int wait_for_server_ready(int port, int timeout_ms);

static int write_temp_yaml_mtls(int port, char *path_out, size_t path_out_size) {
    const char *yaml_fmt = "server:\n"
                           "  listen_address: 127.0.0.1\n"
                           "  listen_port: %d\n"
                           "  version: 0.1.0\n"
                           "  tls:\n"
                           "    enabled: true\n"
                           "    server_cert_path: config/certs/device-server.crt\n"
                           "    server_key_path: config/certs/device-server.key\n"
                           "    trusted_client_ca_path: config/certs/verifier-ca.crt\n"
                           "    require_client_cert: true\n"
                           "\n"
                           "verifiers:\n"
                           "  - verifier_id: govt-verifier-01\n"
                           "    cert_subject_cn: govt-verifier-01\n"
                           "    cert_san_uri: spiffe://vantaqd/verifier/govt-verifier-01\n"
                           "    status: active\n"
                           "    roles:\n"
                           "      - verifier\n"
                           "    allowed_apis:\n"
                           "      - POST /v1/attestation/challenge\n"
                           "      - POST /v1/attestation/evidence\n"
                           "\n"
                           "device_identity:\n"
                           "  device_id: edge-gw-001\n"
                           "  model: edge-gateway-v1\n"
                           "  serial_number: SN-001\n"
                           "  manufacturer: ExampleCorp\n"
                           "  firmware_version: 0.1.0-demo\n"
                           "  device_priv_key_path: config/certs/device-server.key\n"
                           "  device_pub_key_path: config/certs/device-server.crt\n"
                           "\n"
                           "capabilities:\n"
                           "  supported_claims:\n"
                           "    - device_identity\n"
                           "  signature_algorithms: []\n"
                           "  evidence_formats: []\n"
                           "  challenge_modes: []\n"
                           "  storage_modes: []\n"
                           "network_access:\n"
                           "  allowed_subnets: [127.0.0.1/32]\n"
                           "  dev_allow_all_networks: false\n"
                           "challenge:\n"
                           "  ttl_seconds: 60\n"
                           "  max_global: 100\n"
                           "  max_per_verifier: 10\n";

    char template[] = "/tmp/vantaq_replay_XXXXXX.yaml";
    char yaml_buf[2048];
    int fd = mkstemps(template, 5);
    if (fd < 0)
        return -1;

    int n = snprintf(yaml_buf, sizeof(yaml_buf), yaml_fmt, port);
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
    strncpy(path_out, template, path_out_size);
    return 0;
}

static int suite_setup(void **state) {
    struct ReplayedChallengeTestSuite *s = malloc(sizeof(struct ReplayedChallengeTestSuite));
    if (!s)
        return -1;

    s->port = reserve_ephemeral_port();
    if (s->port <= 0) {
        free(s);
        return -1;
    }

    if (write_temp_yaml_mtls(s->port, s->cfg_path, sizeof(s->cfg_path)) != 0) {
        free(s);
        return -1;
    }

    if (make_temp_audit_path(s->audit_path, sizeof(s->audit_path)) != 0) {
        unlink(s->cfg_path);
        free(s);
        return -1;
    }

    s->child_pid = fork();
    if (s->child_pid < 0) {
        unlink(s->cfg_path);
        unlink(s->audit_path);
        free(s);
        return -1;
    }

    if (s->child_pid == 0) {
        setenv("VANTAQ_AUDIT_LOG_PATH", s->audit_path, 1);
        execl("./bin/vantaqd", "vantaqd", "--config", s->cfg_path, (char *)NULL);
        _exit(127);
    }

    if (wait_for_server_ready(s->port, 4000) != 0) {
        kill(s->child_pid, SIGTERM);
        waitpid(s->child_pid, NULL, 0);
        unlink(s->cfg_path);
        unlink(s->audit_path);
        free(s);
        return -1;
    }

    *state = s;
    return 0;
}

static int suite_teardown(void **state) {
    struct ReplayedChallengeTestSuite *s = *state;
    if (s) {
        kill(s->child_pid, SIGTERM);
        waitpid(s->child_pid, NULL, 0);
        unlink(s->cfg_path);
        unlink(s->audit_path);
        free(s);
    }
    return 0;
}

static int curl_mtls_post(int port, const char *path, const char *data, char *body_out,
                          size_t body_size) {
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
             "curl -sS -k --cert config/certs/govt-verifier-01.crt --key "
             "config/certs/govt-verifier-01.key "
             "-X POST -d '%s' https://127.0.0.1:%d%s",
             data, port, path);

    FILE *fp = popen(cmd, "r");
    if (!fp)
        return -1;

    size_t n    = fread(body_out, 1, body_size - 1, fp);
    body_out[n] = '\0';
    pclose(fp);
    return 0;
}

static void test_replayed_challenge_rejected(void **state) {
    struct ReplayedChallengeTestSuite *s = *state;
    char body[4096];
    char challenge_id[128];
    char nonce[128];
    char cmd[2048];

    // 1. Get Challenge
    int rc = curl_mtls_post(s->port, "/v1/attestation/challenge",
                            "{\"purpose\":\"remote_attestation\"}", body, sizeof(body));
    s_assert_int_equal(s, rc, 0);
    s_assert_non_null(s, strstr(body, "\"challenge_id\":"));

    char *p = strstr(body, "\"challenge_id\":\"");
    if (p) {
        p += 16;
        char *end = strchr(p, '\"');
        if (end) {
            size_t len = (end - p);
            memcpy(challenge_id, p, len);
            challenge_id[len] = '\0';
        }
    }

    p = strstr(body, "\"nonce\":\"");
    if (p) {
        p += 9;
        char *end = strchr(p, '\"');
        if (end) {
            size_t len = (end - p);
            memcpy(nonce, p, len);
            nonce[len] = '\0';
        }
    }

    s_assert_true(s, strlen(challenge_id) > 0);
    s_assert_true(s, strlen(nonce) > 0);

    // 2. First Evidence Request (Success)
    char evidence_req[512];
    snprintf(evidence_req, sizeof(evidence_req), "{\"challenge_id\":\"%s\",\"nonce\":\"%s\"}",
             challenge_id, nonce);

    rc = curl_mtls_post(s->port, "/v1/attestation/evidence", evidence_req, body, sizeof(body));
    s_assert_int_equal(s, rc, 0);
    s_assert_non_null(s, strstr(body, "\"signature\":"));

    // 3. Second Evidence Request (Replay - Failure)
    // Check status code and body
    snprintf(cmd, sizeof(cmd),
             "curl -sS -k -i --cert config/certs/govt-verifier-01.crt --key "
             "config/certs/govt-verifier-01.key "
             "-X POST -d '%s' https://127.0.0.1:%d/v1/attestation/evidence",
             evidence_req, s->port);

    FILE *fp = popen(cmd, "r");
    if (fp) {
        size_t n = fread(body, 1, sizeof(body) - 1, fp);
        body[n]  = '\0';
        pclose(fp);

        s_assert_non_null(s, strstr(body, "HTTP/1.1 409"));
        s_assert_non_null(s, strstr(body, "\"code\":\"CHALLENGE_ALREADY_USED\""));
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_replayed_challenge_rejected, suite_setup,
                                        suite_teardown),
    };

    return cmocka_run_group_tests_name("integration_replayed_challenge", tests, NULL, NULL);
}
