// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/memory/zero_struct.h"
#include "test_server_harness.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cmocka.h>

struct FirmwareHashChangeSuite {
    struct vantaq_test_server_handle server;
    char firmware_path[256];
};

#define s_assert_int_equal(s, a, b) assert_int_equal(a, b)
#define s_assert_non_null(s, a) assert_non_null(a)
#define s_assert_true(s, a) assert_true(a)

static int write_file(const char *path, const char *content) {
    FILE *fp = fopen(path, "wb");
    if (fp == NULL) {
        return -1;
    }
    if (fwrite(content, 1, strlen(content), fp) != strlen(content)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

static int curl_mtls_post_status_body(int port, const char *path, const char *payload,
                                      int *status_out, char *body_out, size_t body_size) {
    char cmd[4096];
    char status_text[32];
    char body_file[256];
    FILE *status_pipe;
    FILE *body_file_fp;
    size_t n;

    snprintf(body_file, sizeof(body_file), "/tmp/vantaq_fw_change_body_%d.tmp", getpid());
    snprintf(cmd, sizeof(cmd),
             "curl -sS -k --cert config/certs/govt-verifier-01.crt "
             "--key config/certs/govt-verifier-01.key "
             "-o %s -w \"%%{http_code}\" -X POST -d '%s' https://127.0.0.1:%d%s",
             body_file, payload, port, path);

    status_pipe = popen(cmd, "r");
    if (status_pipe == NULL) {
        return -1;
    }
    if (fgets(status_text, sizeof(status_text), status_pipe) == NULL) {
        pclose(status_pipe);
        return -1;
    }
    pclose(status_pipe);
    *status_out = atoi(status_text);

    body_file_fp = fopen(body_file, "rb");
    if (body_file_fp == NULL) {
        return -1;
    }
    n           = fread(body_out, 1, body_size - 1, body_file_fp);
    body_out[n] = '\0';
    fclose(body_file_fp);
    unlink(body_file);

    return 0;
}

static int request_challenge(int port, char *challenge_id, size_t challenge_size, char *nonce,
                             size_t nonce_size) {
    char body[4096];
    int status = 0;
    char *p;
    char *end;

    if (curl_mtls_post_status_body(port, "/v1/attestation/challenge",
                                   "{\"purpose\":\"remote_attestation\"}", &status, body,
                                   sizeof(body)) != 0) {
        return -1;
    }
    if (status != 201) {
        return -1;
    }

    p = strstr(body, "\"challenge_id\":\"");
    if (p == NULL) {
        return -1;
    }
    p += strlen("\"challenge_id\":\"");
    end = strchr(p, '"');
    if (end == NULL || (size_t)(end - p) >= challenge_size) {
        return -1;
    }
    memcpy(challenge_id, p, (size_t)(end - p));
    challenge_id[end - p] = '\0';

    p = strstr(body, "\"nonce\":\"");
    if (p == NULL) {
        return -1;
    }
    p += strlen("\"nonce\":\"");
    end = strchr(p, '"');
    if (end == NULL || (size_t)(end - p) >= nonce_size) {
        return -1;
    }
    memcpy(nonce, p, (size_t)(end - p));
    nonce[end - p] = '\0';
    return 0;
}

static int extract_firmware_hash(const char *body, char *hash_out, size_t hash_out_size) {
    const char *marker = "firmware_hash";
    const char *start;
    const char *end;
    size_t len;

    if (body == NULL || hash_out == NULL || hash_out_size == 0) {
        return -1;
    }

    start = strstr(body, marker);
    if (start == NULL) {
        return -1;
    }
    start += strlen(marker);
    // Skip to the next ':' and then the next quote
    start = strstr(start, "sha256:");
    if (start == NULL) {
        return -1;
    }

    end = start;
    while (*end && *end != '"' && *end != '\\') {
        end++;
    }

    len = (size_t)(end - start);
    if (len == 0 || len >= hash_out_size) {
        return -1;
    }

    memcpy(hash_out, start, len);
    hash_out[len] = '\0';
    return 0;
}

static int verify_evidence_signature(const char *evidence_body, const char *evidence_path) {
    char cmd[512];
    FILE *fp;
    int rc;

    if (evidence_body == NULL || evidence_path == NULL) {
        return -1;
    }

    fp = fopen(evidence_path, "wb");
    if (fp == NULL) {
        return -1;
    }
    fprintf(fp, "%s", evidence_body);
    fclose(fp);

    snprintf(cmd, sizeof(cmd),
             "./bin/verify_evidence %s config/certs/device-server.crt > /dev/null 2>&1",
             evidence_path);
    rc = system(cmd);
    unlink(evidence_path);

    if (rc == -1 || !WIFEXITED(rc) || WEXITSTATUS(rc) != 0) {
        return -1;
    }

    return 0;
}

static int suite_setup(void **state) {
    struct FirmwareHashChangeSuite *s = malloc(sizeof(*s));
    struct vantaq_test_server_opts opts;
    char setup_err[512];

    if (s == NULL) {
        return -1;
    }
    VANTAQ_ZERO_STRUCT(*s);

    snprintf(s->firmware_path, sizeof(s->firmware_path), "/tmp/vantaq_firmware_change_%d.bin",
             getpid());
    if (write_file(s->firmware_path, "firmware-content-seed") != 0) {
        free(s);
        return -1;
    }

    VANTAQ_ZERO_STRUCT(opts);
    opts.tls_enabled               = true;
    opts.require_client_cert       = true;
    opts.include_challenge         = true;
    opts.allowed_subnets           = "127.0.0.1/32";
    opts.dev_allow_all_networks    = "false";
    opts.allowed_apis_yaml         = "      - POST /v1/attestation/challenge\n"
                                     "      - POST /v1/attestation/evidence\n";
    opts.supported_claims_yaml     = "    - device_identity\n"
                                     "    - firmware_hash\n";
    opts.measurement_firmware_path = s->firmware_path;
    opts.startup_timeout_ms        = 4000;
    opts.max_start_retries         = 5;
    setup_err[0]                   = '\0';

    if (vantaq_test_server_start(&opts, &s->server, setup_err, sizeof(setup_err)) != 0) {
        if (setup_err[0] != '\0') {
            print_error("test_firmware_hash_change setup failed: %s\n", setup_err);
        }
        if (strstr(setup_err, "unable to reserve port") != NULL ||
            strstr(setup_err, "bind_failed") != NULL ||
            strstr(setup_err, "startup_timeout") != NULL) {
            unlink(s->firmware_path);
            free(s);
            *state = NULL;
            return 0;
        }
        unlink(s->firmware_path);
        free(s);
        return -1;
    }

    *state = s;
    return 0;
}

static int suite_teardown(void **state) {
    struct FirmwareHashChangeSuite *s = *state;
    if (s != NULL) {
        vantaq_test_server_stop(&s->server);
        unlink(s->firmware_path);
        free(s);
    }
    return 0;
}

static void test_firmware_hash_changes_after_firmware_file_update(void **state) {
    struct FirmwareHashChangeSuite *s = *state;
    char challenge_id[128];
    char nonce[128];
    char req[768];
    char body_a[4096];
    char body_b[4096];
    char hash_a[256];
    char hash_b[256];
    char evidence_path_a[256];
    char evidence_path_b[256];
    int status = 0;

    if (s == NULL) {
        skip();
    }

    s_assert_int_equal(s, write_file(s->firmware_path, "firmware-content-v1"), 0);
    s_assert_int_equal(
        s,
        request_challenge(s->server.port, challenge_id, sizeof(challenge_id), nonce, sizeof(nonce)),
        0);

    snprintf(req, sizeof(req),
             "{\"challenge_id\":\"%s\",\"nonce\":\"%s\",\"claims\":[\"firmware_hash\"]}",
             challenge_id, nonce);
    s_assert_int_equal(s,
                       curl_mtls_post_status_body(s->server.port, "/v1/attestation/evidence", req,
                                                  &status, body_a, sizeof(body_a)),
                       0);
    s_assert_int_equal(s, status, 200);
    s_assert_int_equal(s, extract_firmware_hash(body_a, hash_a, sizeof(hash_a)), 0);
    s_assert_true(s, strncmp(hash_a, "sha256:", 7) == 0);

    snprintf(evidence_path_a, sizeof(evidence_path_a), "/tmp/vantaq_fw_change_evidence_a_%d.json",
             getpid());
    s_assert_int_equal(s, verify_evidence_signature(body_a, evidence_path_a), 0);

    s_assert_int_equal(s, write_file(s->firmware_path, "firmware-content-v2"), 0);
    s_assert_int_equal(
        s,
        request_challenge(s->server.port, challenge_id, sizeof(challenge_id), nonce, sizeof(nonce)),
        0);

    snprintf(req, sizeof(req),
             "{\"challenge_id\":\"%s\",\"nonce\":\"%s\",\"claims\":[\"firmware_hash\"]}",
             challenge_id, nonce);
    s_assert_int_equal(s,
                       curl_mtls_post_status_body(s->server.port, "/v1/attestation/evidence", req,
                                                  &status, body_b, sizeof(body_b)),
                       0);
    s_assert_int_equal(s, status, 200);
    s_assert_int_equal(s, extract_firmware_hash(body_b, hash_b, sizeof(hash_b)), 0);
    s_assert_true(s, strncmp(hash_b, "sha256:", 7) == 0);

    snprintf(evidence_path_b, sizeof(evidence_path_b), "/tmp/vantaq_fw_change_evidence_b_%d.json",
             getpid());
    s_assert_int_equal(s, verify_evidence_signature(body_b, evidence_path_b), 0);

    s_assert_true(s, strcmp(hash_a, hash_b) != 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_firmware_hash_changes_after_firmware_file_update,
                                        suite_setup, suite_teardown),
    };

    return cmocka_run_group_tests_name("integration_firmware_hash_change", tests, NULL, NULL);
}
