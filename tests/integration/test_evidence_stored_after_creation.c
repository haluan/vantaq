// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "domain/measurement/supported_claims.h"
#include "domain/ring_buffer/ring_buffer.h"
#include "evidence_ring_buffer.h"
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
#include <unistd.h>

#include <cmocka.h>

struct EvidenceStoredAfterCreationSuite {
    char temp_dir[256];
};

#define s_assert_int_equal(s, a, b) assert_int_equal(a, b)
#define s_assert_non_null(s, a) assert_non_null(a)
#define s_assert_null(s, a) assert_null(a)
#define s_assert_true(s, a) assert_true(a)

static int make_temp_dir(char *out, size_t out_size) {
    char templ[] = "/tmp/vantaq_t07_XXXXXX";
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

static int write_text_file(const char *path, const char *text) {
    FILE *fp;

    if (path == NULL || text == NULL) {
        return -1;
    }

    fp = fopen(path, "wb");
    if (fp == NULL) {
        return -1;
    }

    if (fwrite(text, 1, strlen(text), fp) != strlen(text)) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
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

    end = strchr(start, '"');
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
                                  const char *max_record_bytes, const char *device_priv_key_path,
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
                                           "      - GET /v1/attestation/latest-evidence\n";
    opts.evidence_store_file_path        = ring_path;
    opts.evidence_store_max_records      = "8";
    opts.evidence_store_max_record_bytes = max_record_bytes != NULL ? max_record_bytes : "8192";
    opts.evidence_store_fsync_on_append  = "true";
    opts.startup_timeout_ms              = 4000;
    opts.max_start_retries               = 5;
    opts.device_priv_key_path            = device_priv_key_path;

    if (vantaq_test_server_start(&opts, server, err, err_len) != 0) {
        if (err != NULL && err[0] != '\0') {
            print_error("test_evidence_stored_after_creation setup failed: %s\n", err);
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

static int suite_setup(void **state) {
    struct EvidenceStoredAfterCreationSuite *s = calloc(1, sizeof(*s));

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
    struct EvidenceStoredAfterCreationSuite *s = *state;

    if (s != NULL) {
        if (s->temp_dir[0] != '\0') {
            (void)rmdir(s->temp_dir);
        }
        free(s);
    }

    return 0;
}

static void test_valid_post_is_persisted_and_readable_by_id(void **state) {
    struct EvidenceStoredAfterCreationSuite *s = *state;
    struct vantaq_test_server_handle server;
    struct vantaq_ring_buffer_config *cfg           = NULL;
    struct vantaq_evidence_ring_buffer *ring        = NULL;
    struct vantaq_ring_buffer_read_result *read_res = NULL;
    const struct vantaq_ring_buffer_record *read_rec;
    char ring_path[512];
    char setup_err[512];
    char challenge_id[128];
    char nonce[128];
    char evidence_req[512];
    char evidence_body[8192];
    char evidence_id[128];
    int status;

    if (s == NULL) {
        skip();
    }

    VANTAQ_ZERO_STRUCT(server);
    setup_err[0] = '\0';

    s_assert_int_equal(
        s, make_temp_file_path(s->temp_dir, "ring_ok", ".ring", ring_path, sizeof(ring_path)), 0);
    if (start_server_with_ring(&server, ring_path, "8192", NULL, setup_err, sizeof(setup_err)) !=
        0) {
        if (is_transient_startup_failure(setup_err)) {
            (void)unlink(ring_path);
            skip();
            return;
        }
        fail_msg("server start failed: %s", setup_err);
    }

    s_assert_int_equal(
        s, create_challenge(server.port, challenge_id, sizeof(challenge_id), nonce, sizeof(nonce)),
        0);

    (void)snprintf(evidence_req, sizeof(evidence_req),
                   "{\"challenge_id\":\"%s\",\"nonce\":\"%s\",\"claims\":[\"%s\"]}", challenge_id,
                   nonce, VANTAQ_CLAIM_DEVICE_IDENTITY);

    s_assert_int_equal(s,
                       curl_mtls_request(server.port, "POST", "/v1/attestation/evidence",
                                         evidence_req, &status, evidence_body,
                                         sizeof(evidence_body)),
                       0);
    s_assert_int_equal(s, status, 200);
    s_assert_non_null(s, strstr(evidence_body, "\"evidence_id\":"));
    s_assert_non_null(s, strstr(evidence_body, "\"signature\":"));
    s_assert_int_equal(
        s,
        extract_json_string_field(evidence_body, "evidence_id", evidence_id, sizeof(evidence_id)),
        0);

    s_assert_int_equal(s, vantaq_ring_buffer_config_create(ring_path, 8U, 8192U, true, &cfg),
                       RING_BUFFER_OK);
    s_assert_int_equal(s, vantaq_evidence_ring_buffer_open(cfg, &ring),
                       VANTAQ_EVIDENCE_RING_OPEN_OK);
    s_assert_int_equal(
        s, vantaq_evidence_ring_buffer_read_by_evidence_id(ring, evidence_id, &read_res),
        VANTAQ_EVIDENCE_RING_READ_OK);
    s_assert_non_null(s, read_res);
    s_assert_int_equal(s, vantaq_ring_buffer_read_result_get_status(read_res), RING_BUFFER_OK);

    read_rec = vantaq_ring_buffer_read_result_get_record(read_res);
    s_assert_non_null(s, read_rec);
    s_assert_non_null(s,
                      strstr(vantaq_ring_buffer_record_get_evidence_json(read_rec), evidence_id));

    vantaq_ring_buffer_read_result_destroy(read_res);
    vantaq_evidence_ring_buffer_destroy(ring);
    vantaq_ring_buffer_config_destroy(cfg);
    vantaq_test_server_stop(&server);
    (void)unlink(ring_path);
}

static void test_signing_failure_returns_500_and_does_not_append(void **state) {
    struct EvidenceStoredAfterCreationSuite *s = *state;
    struct vantaq_test_server_handle server;
    struct vantaq_ring_buffer_config *cfg           = NULL;
    struct vantaq_evidence_ring_buffer *ring        = NULL;
    struct vantaq_ring_buffer_read_result *read_res = NULL;
    char ring_path[512];
    char bad_key_path[512];
    char setup_err[512];
    char challenge_id[128];
    char nonce[128];
    char evidence_req[512];
    char response_body[8192];
    int status;

    if (s == NULL) {
        skip();
    }

    VANTAQ_ZERO_STRUCT(server);
    setup_err[0] = '\0';

    s_assert_int_equal(
        s,
        make_temp_file_path(s->temp_dir, "ring_sign_fail", ".ring", ring_path, sizeof(ring_path)),
        0);
    s_assert_int_equal(
        s, make_temp_file_path(s->temp_dir, "bad_priv", ".pem", bad_key_path, sizeof(bad_key_path)),
        0);
    s_assert_int_equal(s, write_text_file(bad_key_path, "not-a-valid-private-key"), 0);

    if (start_server_with_ring(&server, ring_path, "8192", bad_key_path, setup_err,
                               sizeof(setup_err)) != 0) {
        if (is_transient_startup_failure(setup_err)) {
            (void)unlink(ring_path);
            (void)unlink(bad_key_path);
            skip();
            return;
        }
        fail_msg("server start failed: %s", setup_err);
    }

    s_assert_int_equal(
        s, create_challenge(server.port, challenge_id, sizeof(challenge_id), nonce, sizeof(nonce)),
        0);

    (void)snprintf(evidence_req, sizeof(evidence_req),
                   "{\"challenge_id\":\"%s\",\"nonce\":\"%s\",\"claims\":[\"%s\"]}", challenge_id,
                   nonce, VANTAQ_CLAIM_DEVICE_IDENTITY);

    s_assert_int_equal(s,
                       curl_mtls_request(server.port, "POST", "/v1/attestation/evidence",
                                         evidence_req, &status, response_body,
                                         sizeof(response_body)),
                       0);
    s_assert_int_equal(s, status, 500);
    s_assert_non_null(s, strstr(response_body, "\"signing_failed\""));

    s_assert_int_equal(s, vantaq_ring_buffer_config_create(ring_path, 8U, 8192U, true, &cfg),
                       RING_BUFFER_OK);
    s_assert_int_equal(s, vantaq_evidence_ring_buffer_open(cfg, &ring),
                       VANTAQ_EVIDENCE_RING_OPEN_OK);
    s_assert_int_equal(s, vantaq_evidence_ring_buffer_read_latest(ring, &read_res),
                       VANTAQ_EVIDENCE_RING_READ_OK);
    s_assert_non_null(s, read_res);
    s_assert_int_equal(s, vantaq_ring_buffer_read_result_get_status(read_res),
                       RING_BUFFER_RECORD_NOT_FOUND);

    vantaq_ring_buffer_read_result_destroy(read_res);
    vantaq_evidence_ring_buffer_destroy(ring);
    vantaq_ring_buffer_config_destroy(cfg);
    vantaq_test_server_stop(&server);
    (void)unlink(ring_path);
    (void)unlink(bad_key_path);
}

static void test_small_max_record_bytes_causes_storage_error(void **state) {
    struct EvidenceStoredAfterCreationSuite *s = *state;
    struct vantaq_test_server_handle server;
    char ring_path[512];
    char setup_err[512];
    char challenge_id[128];
    char nonce[128];
    char evidence_req[512];
    char response_body[8192];
    int status;

    if (s == NULL) {
        skip();
    }

    VANTAQ_ZERO_STRUCT(server);
    setup_err[0] = '\0';

    s_assert_int_equal(
        s, make_temp_file_path(s->temp_dir, "ring_small", ".ring", ring_path, sizeof(ring_path)),
        0);
    if (start_server_with_ring(&server, ring_path, "128", NULL, setup_err, sizeof(setup_err)) !=
        0) {
        if (is_transient_startup_failure(setup_err)) {
            (void)unlink(ring_path);
            skip();
            return;
        }
        fail_msg("server start failed: %s", setup_err);
    }

    s_assert_int_equal(
        s, create_challenge(server.port, challenge_id, sizeof(challenge_id), nonce, sizeof(nonce)),
        0);

    (void)snprintf(evidence_req, sizeof(evidence_req),
                   "{\"challenge_id\":\"%s\",\"nonce\":\"%s\",\"claims\":[\"%s\"]}", challenge_id,
                   nonce, VANTAQ_CLAIM_DEVICE_IDENTITY);

    s_assert_int_equal(s,
                       curl_mtls_request(server.port, "POST", "/v1/attestation/evidence",
                                         evidence_req, &status, response_body,
                                         sizeof(response_body)),
                       0);
    s_assert_int_equal(s, status, 500);
    s_assert_non_null(s, strstr(response_body, "\"ring_buffer_write_failed\""));

    vantaq_test_server_stop(&server);
    (void)unlink(ring_path);
}

static void test_success_post_response_schema_unchanged(void **state) {
    struct EvidenceStoredAfterCreationSuite *s = *state;
    struct vantaq_test_server_handle server;
    char ring_path[512];
    char setup_err[512];
    char challenge_id[128];
    char nonce[128];
    char evidence_req[512];
    char evidence_body[8192];
    int status;

    if (s == NULL) {
        skip();
    }

    VANTAQ_ZERO_STRUCT(server);
    setup_err[0] = '\0';

    s_assert_int_equal(
        s, make_temp_file_path(s->temp_dir, "ring_schema", ".ring", ring_path, sizeof(ring_path)),
        0);
    if (start_server_with_ring(&server, ring_path, "8192", NULL, setup_err, sizeof(setup_err)) !=
        0) {
        if (is_transient_startup_failure(setup_err)) {
            (void)unlink(ring_path);
            skip();
            return;
        }
        fail_msg("server start failed: %s", setup_err);
    }

    s_assert_int_equal(
        s, create_challenge(server.port, challenge_id, sizeof(challenge_id), nonce, sizeof(nonce)),
        0);

    (void)snprintf(evidence_req, sizeof(evidence_req),
                   "{\"challenge_id\":\"%s\",\"nonce\":\"%s\",\"claims\":[\"%s\"]}", challenge_id,
                   nonce, VANTAQ_CLAIM_DEVICE_IDENTITY);

    s_assert_int_equal(s,
                       curl_mtls_request(server.port, "POST", "/v1/attestation/evidence",
                                         evidence_req, &status, evidence_body,
                                         sizeof(evidence_body)),
                       0);
    s_assert_int_equal(s, status, 200);

    s_assert_non_null(s, strstr(evidence_body, "\"evidence_id\":"));
    s_assert_non_null(s, strstr(evidence_body, "\"device_id\":"));
    s_assert_non_null(s, strstr(evidence_body, "\"verifier_id\":"));
    s_assert_non_null(s, strstr(evidence_body, "\"challenge_id\":"));
    s_assert_non_null(s, strstr(evidence_body, "\"nonce\":"));
    s_assert_non_null(s, strstr(evidence_body, "\"purpose\":"));
    s_assert_non_null(s, strstr(evidence_body, "\"timestamp\":"));
    s_assert_non_null(s, strstr(evidence_body, "\"claims\":"));
    s_assert_non_null(s, strstr(evidence_body, "\"signature_algorithm\":"));
    s_assert_non_null(s, strstr(evidence_body, "\"signature\":"));

    vantaq_test_server_stop(&server);
    (void)unlink(ring_path);
}

static void test_append_failure_does_not_update_latest_store(void **state) {
    struct EvidenceStoredAfterCreationSuite *s = *state;
    struct vantaq_test_server_handle server;
    char ring_path[512];
    char setup_err[512];
    char challenge_id[128];
    char nonce[128];
    char evidence_req[512];
    char response_body[8192];
    int status;

    if (s == NULL) {
        skip();
    }

    VANTAQ_ZERO_STRUCT(server);
    setup_err[0] = '\0';

    s_assert_int_equal(
        s, make_temp_file_path(s->temp_dir, "ring_latest", ".ring", ring_path, sizeof(ring_path)),
        0);
    if (start_server_with_ring(&server, ring_path, "128", NULL, setup_err, sizeof(setup_err)) !=
        0) {
        if (is_transient_startup_failure(setup_err)) {
            (void)unlink(ring_path);
            skip();
            return;
        }
        fail_msg("server start failed: %s", setup_err);
    }

    s_assert_int_equal(
        s, create_challenge(server.port, challenge_id, sizeof(challenge_id), nonce, sizeof(nonce)),
        0);

    (void)snprintf(evidence_req, sizeof(evidence_req),
                   "{\"challenge_id\":\"%s\",\"nonce\":\"%s\",\"claims\":[\"%s\"]}", challenge_id,
                   nonce, VANTAQ_CLAIM_DEVICE_IDENTITY);

    s_assert_int_equal(s,
                       curl_mtls_request(server.port, "POST", "/v1/attestation/evidence",
                                         evidence_req, &status, response_body,
                                         sizeof(response_body)),
                       0);
    s_assert_int_equal(s, status, 500);
    s_assert_non_null(s, strstr(response_body, "\"ring_buffer_write_failed\""));

    s_assert_int_equal(s,
                       curl_mtls_request(server.port, "GET", "/v1/attestation/latest-evidence",
                                         NULL, &status, response_body, sizeof(response_body)),
                       0);
    s_assert_int_equal(s, status, 404);

    vantaq_test_server_stop(&server);
    (void)unlink(ring_path);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_valid_post_is_persisted_and_readable_by_id,
                                        suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_signing_failure_returns_500_and_does_not_append,
                                        suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_small_max_record_bytes_causes_storage_error,
                                        suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_success_post_response_schema_unchanged, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_append_failure_does_not_update_latest_store,
                                        suite_setup, suite_teardown),
    };

    return cmocka_run_group_tests_name("integration_evidence_stored_after_creation", tests, NULL,
                                       NULL);
}
