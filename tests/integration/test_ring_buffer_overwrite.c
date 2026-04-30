// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "domain/measurement/supported_claims.h"
#include "infrastructure/memory/zero_struct.h"
#include "test_server_harness.h"

#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cmocka.h>

struct RingBufferOverwriteSuite {
    char temp_dir[256];
};

#define s_assert_int_equal(s, a, b) assert_int_equal(a, b)
#define s_assert_non_null(s, a) assert_non_null(a)
#define s_assert_true(s, a) assert_true(a)
#define s_assert_string_equal(s, a, b) assert_string_equal(a, b)

static int make_temp_dir(char *out, size_t out_size) {
    char templ[] = "/tmp/vantaq_t14_XXXXXX";
    char *dir;

    dir = mkdtemp(templ);
    if (dir == NULL) {
        return -1;
    }
    if (strlen(dir) >= out_size) {
        return -1;
    }

    memcpy(out, dir, strlen(dir) + 1U);
    return 0;
}

static int make_temp_file_path(const char *dir, const char *prefix, const char *suffix, char *out,
                               size_t out_size) {
    char templ[512];
    int fd;
    size_t suffix_len;

    if (dir == NULL || prefix == NULL || suffix == NULL || out == NULL || out_size == 0) {
        return -1;
    }

    suffix_len = strlen(suffix);
    if (snprintf(templ, sizeof(templ), "%s/%s_XXXXXX%s", dir, prefix, suffix) <= 0) {
        return -1;
    }

    fd = mkstemps(templ, (int)suffix_len);
    if (fd < 0) {
        return -1;
    }
    close(fd);

    if (strlen(templ) >= out_size) {
        unlink(templ);
        return -1;
    }

    memcpy(out, templ, strlen(templ) + 1U);
    return 0;
}

static int curl_mtls_request(int port, const char *method, const char *path, const char *payload,
                             int *status_out, char *body_out, size_t body_out_size) {
    char cmd[8192];
    char raw[16384];
    FILE *fp;
    size_t n;
    char *marker;
    char *cursor;

    if (method == NULL || path == NULL || status_out == NULL || body_out == NULL ||
        body_out_size == 0) {
        return -1;
    }

    if (payload != NULL) {
        if (snprintf(cmd, sizeof(cmd),
                     "curl -sS -k --cert config/certs/govt-verifier-01.crt --key "
                     "config/certs/govt-verifier-01.key "
                     "-X %s -H 'Content-Type: application/json' -d '%s' "
                     "https://127.0.0.1:%d%s -w '\\nHTTPSTATUS:%%{http_code}'",
                     method, payload, port, path) <= 0) {
            return -1;
        }
    } else {
        if (snprintf(cmd, sizeof(cmd),
                     "curl -sS -k --cert config/certs/govt-verifier-01.crt --key "
                     "config/certs/govt-verifier-01.key "
                     "-X %s https://127.0.0.1:%d%s -w '\\nHTTPSTATUS:%%{http_code}'",
                     method, port, path) <= 0) {
            return -1;
        }
    }

    fp = popen(cmd, "r");
    if (fp == NULL) {
        return -1;
    }

    n      = fread(raw, 1, sizeof(raw) - 1U, fp);
    raw[n] = '\0';
    (void)pclose(fp);

    marker = NULL;
    cursor = raw;
    while ((cursor = strstr(cursor, "\nHTTPSTATUS:")) != NULL) {
        marker = cursor;
        cursor += 1;
    }

    if (marker == NULL) {
        return -1;
    }

    *status_out = atoi(marker + strlen("\nHTTPSTATUS:"));
    *marker     = '\0';

    if (strlen(raw) >= body_out_size) {
        return -1;
    }

    memcpy(body_out, raw, strlen(raw) + 1U);
    return 0;
}

static int extract_json_string_field(const char *json, const char *field, char *out,
                                     size_t out_size) {
    char needle[128];
    const char *start;
    const char *end;
    size_t len;

    if (json == NULL || field == NULL || out == NULL || out_size == 0) {
        return -1;
    }

    if (snprintf(needle, sizeof(needle), "\"%s\":\"", field) <= 0) {
        return -1;
    }

    start = strstr(json, needle);
    if (start == NULL) {
        return -1;
    }
    start += strlen(needle);

    end = strchr(start, '\"');
    if (end == NULL) {
        return -1;
    }

    len = (size_t)(end - start);
    if (len == 0 || len >= out_size) {
        return -1;
    }

    memcpy(out, start, len);
    out[len] = '\0';
    return 0;
}

static int create_challenge(int port, char *challenge_id, size_t challenge_id_size, char *nonce,
                            size_t nonce_size) {
    int status;
    char body[4096];

    if (curl_mtls_request(port, "POST", "/v1/attestation/challenge",
                          "{\"purpose\":\"remote_attestation\"}", &status, body,
                          sizeof(body)) != 0) {
        return -1;
    }
    if (status != 201) {
        return -1;
    }
    if (extract_json_string_field(body, "challenge_id", challenge_id, challenge_id_size) != 0) {
        return -1;
    }
    if (extract_json_string_field(body, "nonce", nonce, nonce_size) != 0) {
        return -1;
    }

    return 0;
}

static int start_server_with_ring(struct vantaq_test_server_handle *server, const char *ring_path,
                                  char *err, size_t err_len) {
    struct vantaq_test_server_opts opts;

    VANTAQ_ZERO_STRUCT(opts);
    opts.tls_enabled                     = true;
    opts.require_client_cert             = true;
    opts.include_challenge               = true;
    opts.allowed_subnets                 = "127.0.0.1/32";
    opts.dev_allow_all_networks          = "false";
    opts.allowed_apis_yaml               = "      - POST /v1/attestation/challenge\n"
                                           "      - POST /v1/attestation/evidence\n"
                                           "      - GET /v1/attestation/evidence/latest\n"
                                           "      - GET /v1/attestation/evidence/aaaaaaaa\n";
    opts.evidence_store_file_path        = ring_path;
    opts.evidence_store_max_records      = "3";
    opts.evidence_store_max_record_bytes = "8192";
    opts.evidence_store_fsync_on_append  = "true";
    opts.startup_timeout_ms              = 4000;
    opts.max_start_retries               = 5;

    if (vantaq_test_server_start(&opts, server, err, err_len) != 0) {
        if (err != NULL && err[0] != '\0') {
            print_error("test_ring_buffer_overwrite setup failed: %s\n", err);
        }
        return -1;
    }

    return 0;
}

static bool is_transient_startup_failure(const char *err) {
    if (err == NULL) {
        return false;
    }

    return strstr(err, "unable to reserve port") != NULL || strstr(err, "bind_failed") != NULL ||
           strstr(err, "startup_timeout") != NULL;
}

static int verify_payload_signature(const char *temp_dir, const char *prefix,
                                    const char *evidence_json) {
    char evidence_file_path[512];
    char cmd[1024];
    FILE *fp;
    int verify_rc;

    if (temp_dir == NULL || prefix == NULL || evidence_json == NULL) {
        return -1;
    }

    if (make_temp_file_path(temp_dir, prefix, ".json", evidence_file_path,
                            sizeof(evidence_file_path)) != 0) {
        return -1;
    }

    fp = fopen(evidence_file_path, "wb");
    if (fp == NULL) {
        (void)unlink(evidence_file_path);
        return -1;
    }

    if (fwrite(evidence_json, 1, strlen(evidence_json), fp) != strlen(evidence_json)) {
        fclose(fp);
        (void)unlink(evidence_file_path);
        return -1;
    }
    fclose(fp);

    (void)snprintf(cmd, sizeof(cmd),
                   "./bin/verify_evidence %s config/certs/device-server.crt > /dev/null 2>&1",
                   evidence_file_path);
    verify_rc = system(cmd);
    (void)unlink(evidence_file_path);

    if (verify_rc == -1) {
        return -1;
    }

    return WEXITSTATUS(verify_rc) == 0 ? 0 : -1;
}

static int suite_setup(void **state) {
    struct RingBufferOverwriteSuite *s = calloc(1, sizeof(*s));

    if (s == NULL) {
        return -1;
    }

    if (make_temp_dir(s->temp_dir, sizeof(s->temp_dir)) != 0) {
        free(s);
        return -1;
    }

    *state = s;
    return 0;
}

static int suite_teardown(void **state) {
    struct RingBufferOverwriteSuite *s = *state;

    if (s != NULL) {
        if (s->temp_dir[0] != '\0') {
            (void)rmdir(s->temp_dir);
        }
        free(s);
    }

    return 0;
}

static void test_ring_buffer_overwrites_oldest_at_capacity(void **state) {
    struct RingBufferOverwriteSuite *s = *state;
    struct vantaq_test_server_handle server;
    char ring_path[512];
    char setup_err[512];
    char challenge_id[128];
    char nonce[128];
    char request_body[512];
    char response_body[8192];
    char latest_id[128];
    char evidence_ids[4][128];
    char get_path[256];
    struct stat st_before;
    struct stat st_after;
    int status;
    size_t i;

    if (s == NULL) {
        skip();
    }

    VANTAQ_ZERO_STRUCT(server);
    setup_err[0] = '\0';
    VANTAQ_ZERO_STRUCT(st_before);
    VANTAQ_ZERO_STRUCT(st_after);

    s_assert_int_equal(
        s,
        make_temp_file_path(s->temp_dir, "ring_overwrite", ".ring", ring_path, sizeof(ring_path)),
        0);

    if (start_server_with_ring(&server, ring_path, setup_err, sizeof(setup_err)) != 0) {
        if (is_transient_startup_failure(setup_err)) {
            (void)unlink(ring_path);
            skip();
            return;
        }
        fail_msg("server start failed: %s", setup_err);
    }

    s_assert_int_equal(s, stat(ring_path, &st_before), 0);

    for (i = 0U; i < 4U; i++) {
        s_assert_int_equal(
            s,
            create_challenge(server.port, challenge_id, sizeof(challenge_id), nonce, sizeof(nonce)),
            0);

        (void)snprintf(request_body, sizeof(request_body),
                       "{\"challenge_id\":\"%s\",\"nonce\":\"%s\",\"claims\":[\"%s\"]}",
                       challenge_id, nonce, VANTAQ_CLAIM_DEVICE_IDENTITY);

        s_assert_int_equal(s,
                           curl_mtls_request(server.port, "POST", "/v1/attestation/evidence",
                                             request_body, &status, response_body,
                                             sizeof(response_body)),
                           0);
        s_assert_int_equal(s, status, 200);
        s_assert_int_equal(s,
                           extract_json_string_field(response_body, "evidence_id", evidence_ids[i],
                                                     sizeof(evidence_ids[i])),
                           0);
    }

    s_assert_int_equal(s, stat(ring_path, &st_after), 0);
    s_assert_int_equal(s, st_before.st_size, st_after.st_size);

    s_assert_int_equal(s,
                       curl_mtls_request(server.port, "GET", "/v1/attestation/evidence/latest",
                                         NULL, &status, response_body, sizeof(response_body)),
                       0);
    s_assert_int_equal(s, status, 200);
    s_assert_int_equal(
        s, extract_json_string_field(response_body, "evidence_id", latest_id, sizeof(latest_id)),
        0);
    s_assert_string_equal(s, latest_id, evidence_ids[3]);

    (void)snprintf(get_path, sizeof(get_path), "/v1/attestation/evidence/%s", evidence_ids[0]);
    s_assert_int_equal(s,
                       curl_mtls_request(server.port, "GET", get_path, NULL, &status, response_body,
                                         sizeof(response_body)),
                       0);
    s_assert_int_equal(s, status, 404);

    for (i = 1U; i < 4U; i++) {
        (void)snprintf(get_path, sizeof(get_path), "/v1/attestation/evidence/%s", evidence_ids[i]);
        s_assert_int_equal(s,
                           curl_mtls_request(server.port, "GET", get_path, NULL, &status,
                                             response_body, sizeof(response_body)),
                           0);
        s_assert_int_equal(s, status, 200);
        s_assert_int_equal(
            s, verify_payload_signature(s->temp_dir, "overwrite_payload", response_body), 0);
    }

    s_assert_int_equal(
        s, create_challenge(server.port, challenge_id, sizeof(challenge_id), nonce, sizeof(nonce)),
        0);

    vantaq_test_server_stop(&server);
    (void)unlink(ring_path);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_ring_buffer_overwrites_oldest_at_capacity, suite_setup,
                                        suite_teardown),
    };

    return cmocka_run_group_tests_name("integration_ring_buffer_overwrite", tests, NULL, NULL);
}
