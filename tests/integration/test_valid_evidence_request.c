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
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <cmocka.h>

struct ValidEvidenceTestSuite {
    struct vantaq_test_server_handle server;
};

#define s_assert_int_equal(s, a, b) assert_int_equal(a, b)
#define s_assert_non_null(s, a) assert_non_null(a)
#define s_assert_true(s, a) assert_true(a)

static int suite_setup(void **state) {
    struct ValidEvidenceTestSuite *s = malloc(sizeof(struct ValidEvidenceTestSuite));
    struct vantaq_test_server_opts opts;
    char setup_err[512];

    if (!s)
        return -1;
    memset(s, 0, sizeof(*s));

    memset(&opts, 0, sizeof(opts));
    opts.tls_enabled            = true;
    opts.require_client_cert    = true;
    opts.include_challenge      = true;
    opts.allowed_subnets        = "127.0.0.1/32";
    opts.dev_allow_all_networks = "false";
    opts.allowed_apis_yaml      = "      - POST /v1/attestation/challenge\n"
                                  "      - POST /v1/attestation/evidence\n";
    opts.startup_timeout_ms     = 4000;
    opts.max_start_retries      = 5;
    setup_err[0]                = '\0';

    if (vantaq_test_server_start(&opts, &s->server, setup_err, sizeof(setup_err)) != 0) {
        if (setup_err[0] != '\0') {
            print_error("test_valid_evidence_request setup failed: %s\n", setup_err);
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
    struct ValidEvidenceTestSuite *s = *state;
    if (s) {
        vantaq_test_server_stop(&s->server);
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

static void test_valid_evidence_request_success(void **state) {
    struct ValidEvidenceTestSuite *s = *state;
    if (s == NULL) {
        skip();
    }
    char body[4096];
    char challenge_id[128];
    char nonce[128];

    // 1. Get Challenge
    int rc = curl_mtls_post(s->server.port, "/v1/attestation/challenge",
                            "{\"purpose\":\"remote_attestation\"}", body, sizeof(body));
    s_assert_int_equal(s, rc, 0);
    s_assert_non_null(s, strstr(body, "\"challenge_id\":"));

    char *p = strstr(body, "\"challenge_id\":\"");
    if (p) {
        p += 16;
        char *end = strchr(p, '\"');
        if (end) {
            size_t len = (size_t)(end - p);
            memcpy(challenge_id, p, len);
            challenge_id[len] = '\0';
        }
    }

    p = strstr(body, "\"nonce\":\"");
    if (p) {
        p += 9;
        char *end = strchr(p, '\"');
        if (end) {
            size_t len = (size_t)(end - p);
            memcpy(nonce, p, len);
            nonce[len] = '\0';
        }
    }

    s_assert_true(s, strlen(challenge_id) > 0);
    s_assert_true(s, strlen(nonce) > 0);

    // 2. Get Evidence
    char evidence_req[512];
    snprintf(evidence_req, sizeof(evidence_req),
             "{\"challenge_id\":\"%s\",\"nonce\":\"%s\",\"claims\":[\"%s\"]}", challenge_id, nonce,
             VANTAQ_CLAIM_DEVICE_IDENTITY);

    rc = curl_mtls_post(s->server.port, "/v1/attestation/evidence", evidence_req, body,
                        sizeof(body));
    s_assert_int_equal(s, rc, 0);
    s_assert_non_null(s, strstr(body, "\"signature\":"));
    s_assert_non_null(s, strstr(body, "\"evidence_id\":"));

    // 3. Verify via CLI
    FILE *ef = fopen("/tmp/vantaq_test_evidence.json", "w");
    if (ef) {
        fprintf(ef, "%s", body);
        fclose(ef);

        rc = system("./bin/verify_evidence /tmp/vantaq_test_evidence.json "
                    "config/certs/device-server.crt > /dev/null 2>&1");
        s_assert_int_equal(s, WEXITSTATUS(rc), 0);
        unlink("/tmp/vantaq_test_evidence.json");
    }
}

static void test_evidence_request_missing_nonce(void **state) {
    struct ValidEvidenceTestSuite *s = *state;
    if (s == NULL) {
        skip();
    }
    char body[4096];
    char cmd[2048];

    // Using curl with -w to get status code
    snprintf(
        cmd, sizeof(cmd),
        "curl -sS -k -o /dev/null -w \"%%{http_code}\" --cert config/certs/govt-verifier-01.crt "
        "--key config/certs/govt-verifier-01.key "
        "-X POST -d '{\"challenge_id\":\"some-id\"}' https://127.0.0.1:%d/v1/attestation/evidence",
        s->server.port);

    FILE *fp = popen(cmd, "r");
    if (fp) {
        if (fgets(body, sizeof(body), fp)) {
            int status = atoi(body);
            s_assert_int_equal(s, status, 400);
        }
        pclose(fp);
    }
}

static void test_evidence_request_missing_challenge_id(void **state) {
    struct ValidEvidenceTestSuite *s = *state;
    if (s == NULL) {
        skip();
    }
    char body[4096];
    char cmd[2048];

    snprintf(
        cmd, sizeof(cmd),
        "curl -sS -k -o /dev/null -w \"%%{http_code}\" --cert config/certs/govt-verifier-01.crt "
        "--key config/certs/govt-verifier-01.key "
        "-X POST -d '{\"nonce\":\"some-nonce\"}' "
        "https://127.0.0.1:%d/v1/attestation/evidence",
        s->server.port);

    FILE *fp = popen(cmd, "r");
    if (fp) {
        if (fgets(body, sizeof(body), fp)) {
            int status = atoi(body);
            s_assert_int_equal(s, status, 400);
        }
        pclose(fp);
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_valid_evidence_request_success, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_evidence_request_missing_nonce, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_evidence_request_missing_challenge_id, suite_setup,
                                        suite_teardown),
    };

    return cmocka_run_group_tests_name("integration_valid_evidence_request", tests, NULL, NULL);
}
