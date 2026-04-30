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
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cmocka.h>

struct GetLatestEvidenceApiSuite {
    char temp_dir[256];
};

#define s_assert_int_equal(s, a, b) assert_int_equal(a, b)
#define s_assert_non_null(s, a) assert_non_null(a)
#define s_assert_true(s, a) assert_true(a)

static int make_temp_dir(char *out, size_t out_size) {
    char templ[] = "/tmp/vantaq_t08_XXXXXX";
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
                                           "      - GET /v1/attestation/latest-evidence\n";
    opts.evidence_store_file_path        = ring_path;
    opts.evidence_store_max_records      = "8";
    opts.evidence_store_max_record_bytes = "8192";
    opts.evidence_store_fsync_on_append  = "true";
    opts.startup_timeout_ms              = 4000;
    opts.max_start_retries               = 5;

    if (vantaq_test_server_start(&opts, server, err, err_len) != 0) {
        if (err != NULL && err[0] != '\0') {
            print_error("test_get_latest_evidence_api setup failed: %s\n", err);
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

static int append_record_to_ring(const char *ring_path, const char *evidence_id,
                                 const char *verifier_id, const char *evidence_json,
                                 int64_t issued_at_unix) {
    struct vantaq_ring_buffer_config *cfg             = NULL;
    struct vantaq_evidence_ring_buffer *ring          = NULL;
    struct vantaq_ring_buffer_record *record          = NULL;
    struct vantaq_ring_buffer_append_result *append_r = NULL;
    enum vantaq_evidence_ring_append_status append_s;
    ring_buffer_err_t rb;
    int rc = -1;

    rb = vantaq_ring_buffer_config_create(ring_path, 8U, 8192U, true, &cfg);
    if (rb != RING_BUFFER_OK) {
        goto cleanup;
    }

    if (vantaq_evidence_ring_buffer_open(cfg, &ring) != VANTAQ_EVIDENCE_RING_OPEN_OK) {
        goto cleanup;
    }

    rb = vantaq_ring_buffer_record_create(cfg, 0U, 0U, evidence_id, verifier_id, issued_at_unix,
                                          evidence_json, "sha256:test", "checksum:test", &record);
    if (rb != RING_BUFFER_OK) {
        goto cleanup;
    }

    append_s = vantaq_evidence_ring_buffer_append(ring, record, &append_r);
    if (append_s != VANTAQ_EVIDENCE_RING_APPEND_OK || append_r == NULL ||
        vantaq_ring_buffer_append_result_get_status(append_r) != RING_BUFFER_OK) {
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (append_r != NULL) {
        vantaq_ring_buffer_append_result_destroy(append_r);
    }
    if (record != NULL) {
        vantaq_ring_buffer_record_destroy(record);
    }
    if (ring != NULL) {
        vantaq_evidence_ring_buffer_destroy(ring);
    }
    if (cfg != NULL) {
        vantaq_ring_buffer_config_destroy(cfg);
    }
    return rc;
}

static int suite_setup(void **state) {
    struct GetLatestEvidenceApiSuite *s = calloc(1, sizeof(*s));

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
    struct GetLatestEvidenceApiSuite *s = *state;

    if (s != NULL) {
        if (s->temp_dir[0] != '\0') {
            (void)rmdir(s->temp_dir);
        }
        free(s);
    }

    return 0;
}

static void test_empty_ring_returns_404(void **state) {
    struct GetLatestEvidenceApiSuite *s = *state;
    struct vantaq_test_server_handle server;
    char ring_path[512];
    char setup_err[512];
    int status;
    char body[8192];

    if (s == NULL) {
        skip();
    }

    VANTAQ_ZERO_STRUCT(server);
    setup_err[0] = '\0';

    s_assert_int_equal(
        s, make_temp_file_path(s->temp_dir, "ring_empty", ".ring", ring_path, sizeof(ring_path)),
        0);

    if (start_server_with_ring(&server, ring_path, setup_err, sizeof(setup_err)) != 0) {
        if (is_transient_startup_failure(setup_err)) {
            (void)unlink(ring_path);
            skip();
            return;
        }
        fail_msg("server start failed: %s", setup_err);
    }

    s_assert_int_equal(s,
                       curl_mtls_request(server.port, "GET", "/v1/attestation/evidence/latest",
                                         NULL, &status, body, sizeof(body)),
                       0);
    s_assert_int_equal(s, status, 404);

    vantaq_test_server_stop(&server);
    (void)unlink(ring_path);
}

static void test_post_then_latest_returns_created_evidence(void **state) {
    struct GetLatestEvidenceApiSuite *s = *state;
    struct vantaq_test_server_handle server;
    char ring_path[512];
    char setup_err[512];
    char challenge_id[128];
    char nonce[128];
    char req[512];
    char post_body[8192];
    char get_body[8192];
    char post_evidence_id[128];
    char get_evidence_id[128];
    int status;

    if (s == NULL) {
        skip();
    }

    VANTAQ_ZERO_STRUCT(server);
    setup_err[0] = '\0';

    s_assert_int_equal(
        s, make_temp_file_path(s->temp_dir, "ring_post", ".ring", ring_path, sizeof(ring_path)), 0);

    if (start_server_with_ring(&server, ring_path, setup_err, sizeof(setup_err)) != 0) {
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

    (void)snprintf(req, sizeof(req),
                   "{\"challenge_id\":\"%s\",\"nonce\":\"%s\",\"claims\":[\"%s\"]}", challenge_id,
                   nonce, VANTAQ_CLAIM_DEVICE_IDENTITY);

    s_assert_int_equal(s,
                       curl_mtls_request(server.port, "POST", "/v1/attestation/evidence", req,
                                         &status, post_body, sizeof(post_body)),
                       0);
    s_assert_int_equal(s, status, 200);
    s_assert_int_equal(s,
                       extract_json_string_field(post_body, "evidence_id", post_evidence_id,
                                                 sizeof(post_evidence_id)),
                       0);

    s_assert_int_equal(s,
                       curl_mtls_request(server.port, "GET", "/v1/attestation/evidence/latest",
                                         NULL, &status, get_body, sizeof(get_body)),
                       0);
    s_assert_int_equal(s, status, 200);
    s_assert_int_equal(s,
                       extract_json_string_field(get_body, "evidence_id", get_evidence_id,
                                                 sizeof(get_evidence_id)),
                       0);
    s_assert_int_equal(s, strcmp(post_evidence_id, get_evidence_id), 0);

    vantaq_test_server_stop(&server);
    (void)unlink(ring_path);
}

static void test_latest_signature_integrity_unchanged(void **state) {
    struct GetLatestEvidenceApiSuite *s = *state;
    struct vantaq_test_server_handle server;
    char ring_path[512];
    char setup_err[512];
    char challenge_id[128];
    char nonce[128];
    char req[512];
    char get_body[8192];
    char evidence_file_path[512];
    FILE *fp;
    int status;
    int verify_rc;

    if (s == NULL) {
        skip();
    }

    VANTAQ_ZERO_STRUCT(server);
    setup_err[0] = '\0';

    s_assert_int_equal(
        s, make_temp_file_path(s->temp_dir, "ring_sig", ".ring", ring_path, sizeof(ring_path)), 0);

    if (start_server_with_ring(&server, ring_path, setup_err, sizeof(setup_err)) != 0) {
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

    (void)snprintf(req, sizeof(req),
                   "{\"challenge_id\":\"%s\",\"nonce\":\"%s\",\"claims\":[\"%s\"]}", challenge_id,
                   nonce, VANTAQ_CLAIM_DEVICE_IDENTITY);

    s_assert_int_equal(s,
                       curl_mtls_request(server.port, "POST", "/v1/attestation/evidence", req,
                                         &status, get_body, sizeof(get_body)),
                       0);
    s_assert_int_equal(s, status, 200);

    s_assert_int_equal(s,
                       curl_mtls_request(server.port, "GET", "/v1/attestation/evidence/latest",
                                         NULL, &status, get_body, sizeof(get_body)),
                       0);
    s_assert_int_equal(s, status, 200);

    s_assert_int_equal(s,
                       make_temp_file_path(s->temp_dir, "latest_payload", ".json",
                                           evidence_file_path, sizeof(evidence_file_path)),
                       0);

    fp = fopen(evidence_file_path, "wb");
    s_assert_non_null(s, fp);
    s_assert_int_equal(s, fwrite(get_body, 1, strlen(get_body), fp), (int)strlen(get_body));
    fclose(fp);

    {
        char cmd[1024];
        (void)snprintf(cmd, sizeof(cmd),
                       "./bin/verify_evidence %s config/certs/device-server.crt > /dev/null 2>&1",
                       evidence_file_path);
        verify_rc = system(cmd);
    }
    s_assert_true(s, verify_rc != -1);
    s_assert_int_equal(s, WEXITSTATUS(verify_rc), 0);

    (void)unlink(evidence_file_path);
    vantaq_test_server_stop(&server);
    (void)unlink(ring_path);
}

static void test_visibility_absence_returns_404(void **state) {
    struct GetLatestEvidenceApiSuite *s = *state;
    struct vantaq_test_server_handle server;
    char ring_path[512];
    char setup_err[512];
    char body[8192];
    int status;

    if (s == NULL) {
        skip();
    }

    VANTAQ_ZERO_STRUCT(server);
    setup_err[0] = '\0';

    s_assert_int_equal(
        s, make_temp_file_path(s->temp_dir, "ring_hidden", ".ring", ring_path, sizeof(ring_path)),
        0);

    s_assert_int_equal(
        s,
        append_record_to_ring(
            ring_path, "ev-hidden-1", "other-verifier-01",
            "{\"evidence_id\":\"ev-hidden-1\",\"verifier_id\":\"other-verifier-01\"}", 1770200001),
        0);

    if (start_server_with_ring(&server, ring_path, setup_err, sizeof(setup_err)) != 0) {
        if (is_transient_startup_failure(setup_err)) {
            (void)unlink(ring_path);
            skip();
            return;
        }
        fail_msg("server start failed: %s", setup_err);
    }

    s_assert_int_equal(s,
                       curl_mtls_request(server.port, "GET", "/v1/attestation/evidence/latest",
                                         NULL, &status, body, sizeof(body)),
                       0);
    s_assert_int_equal(s, status, 404);

    vantaq_test_server_stop(&server);
    (void)unlink(ring_path);
}

static void test_latest_visible_record_is_selected_for_verifier(void **state) {
    struct GetLatestEvidenceApiSuite *s = *state;
    struct vantaq_test_server_handle server;
    char ring_path[512];
    char setup_err[512];
    char body[8192];
    char evidence_id[128];
    int status;

    if (s == NULL) {
        skip();
    }

    VANTAQ_ZERO_STRUCT(server);
    setup_err[0] = '\0';

    s_assert_int_equal(
        s, make_temp_file_path(s->temp_dir, "ring_visible", ".ring", ring_path, sizeof(ring_path)),
        0);

    s_assert_int_equal(s,
                       append_record_to_ring(
                           ring_path, "ev-govt-old", "govt-verifier-01",
                           "{\"evidence_id\":\"ev-govt-old\",\"verifier_id\":\"govt-verifier-01\"}",
                           1770200101),
                       0);
    s_assert_int_equal(
        s,
        append_record_to_ring(
            ring_path, "ev-other-new", "other-verifier-01",
            "{\"evidence_id\":\"ev-other-new\",\"verifier_id\":\"other-verifier-01\"}", 1770200102),
        0);

    if (start_server_with_ring(&server, ring_path, setup_err, sizeof(setup_err)) != 0) {
        if (is_transient_startup_failure(setup_err)) {
            (void)unlink(ring_path);
            skip();
            return;
        }
        fail_msg("server start failed: %s", setup_err);
    }

    s_assert_int_equal(s,
                       curl_mtls_request(server.port, "GET", "/v1/attestation/evidence/latest",
                                         NULL, &status, body, sizeof(body)),
                       0);
    s_assert_int_equal(s, status, 200);
    s_assert_int_equal(
        s, extract_json_string_field(body, "evidence_id", evidence_id, sizeof(evidence_id)), 0);
    s_assert_int_equal(s, strcmp(evidence_id, "ev-govt-old"), 0);

    vantaq_test_server_stop(&server);
    (void)unlink(ring_path);
}

static void test_legacy_alias_matches_new_route(void **state) {
    struct GetLatestEvidenceApiSuite *s = *state;
    struct vantaq_test_server_handle server;
    char ring_path[512];
    char setup_err[512];
    char challenge_id[128];
    char nonce[128];
    char req[512];
    char body_new[8192];
    char body_old[8192];
    char ev_new[128];
    char ev_old[128];
    int status;

    if (s == NULL) {
        skip();
    }

    VANTAQ_ZERO_STRUCT(server);
    setup_err[0] = '\0';

    s_assert_int_equal(
        s, make_temp_file_path(s->temp_dir, "ring_alias", ".ring", ring_path, sizeof(ring_path)),
        0);

    if (start_server_with_ring(&server, ring_path, setup_err, sizeof(setup_err)) != 0) {
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

    (void)snprintf(req, sizeof(req),
                   "{\"challenge_id\":\"%s\",\"nonce\":\"%s\",\"claims\":[\"%s\"]}", challenge_id,
                   nonce, VANTAQ_CLAIM_DEVICE_IDENTITY);
    s_assert_int_equal(s,
                       curl_mtls_request(server.port, "POST", "/v1/attestation/evidence", req,
                                         &status, body_new, sizeof(body_new)),
                       0);
    s_assert_int_equal(s, status, 200);

    s_assert_int_equal(s,
                       curl_mtls_request(server.port, "GET", "/v1/attestation/evidence/latest",
                                         NULL, &status, body_new, sizeof(body_new)),
                       0);
    s_assert_int_equal(s, status, 200);
    s_assert_int_equal(
        s, extract_json_string_field(body_new, "evidence_id", ev_new, sizeof(ev_new)), 0);

    s_assert_int_equal(s,
                       curl_mtls_request(server.port, "GET", "/v1/attestation/latest-evidence",
                                         NULL, &status, body_old, sizeof(body_old)),
                       0);
    s_assert_int_equal(s, status, 200);
    s_assert_int_equal(
        s, extract_json_string_field(body_old, "evidence_id", ev_old, sizeof(ev_old)), 0);

    s_assert_int_equal(s, strcmp(ev_new, ev_old), 0);

    vantaq_test_server_stop(&server);
    (void)unlink(ring_path);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_empty_ring_returns_404, suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_post_then_latest_returns_created_evidence, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_latest_signature_integrity_unchanged, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_visibility_absence_returns_404, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_latest_visible_record_is_selected_for_verifier,
                                        suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_legacy_alias_matches_new_route, suite_setup,
                                        suite_teardown),
    };

    return cmocka_run_group_tests_name("integration_get_latest_evidence_api", tests, NULL, NULL);
}
