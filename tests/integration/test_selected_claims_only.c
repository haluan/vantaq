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

struct SelectedClaimsOnlySuite {
    struct vantaq_test_server_handle server;
    char firmware_path[256];
    char security_config_path[256];
    char agent_binary_path[256];
    char boot_state_path[256];
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

    snprintf(body_file, sizeof(body_file), "/tmp/vantaq_selected_claims_body_%d.tmp", getpid());
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

static int request_evidence_with_claims(int port, const char *claims_json, int *status_out,
                                        char *body_out, size_t body_size) {
    char challenge_id[128];
    char nonce[128];
    char req[2048];

    if (claims_json == NULL || status_out == NULL || body_out == NULL || body_size == 0) {
        return -1;
    }

    if (request_challenge(port, challenge_id, sizeof(challenge_id), nonce, sizeof(nonce)) != 0) {
        return -1;
    }

    snprintf(req, sizeof(req), "{\"challenge_id\":\"%s\",\"nonce\":\"%s\",\"claims\":%s}",
             challenge_id, nonce, claims_json);
    return curl_mtls_post_status_body(port, "/v1/attestation/evidence", req, status_out, body_out,
                                      body_size);
}

static int verify_evidence_signature(const char *evidence_body, const char *suffix) {
    char evidence_path[256];
    char cmd[512];
    FILE *fp;
    int rc;

    if (evidence_body == NULL || suffix == NULL) {
        return -1;
    }

    snprintf(evidence_path, sizeof(evidence_path), "/tmp/vantaq_selected_claims_%s_%d.json", suffix,
             getpid());

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
    struct SelectedClaimsOnlySuite *s = malloc(sizeof(*s));
    struct vantaq_test_server_opts opts;
    char setup_err[512];

    if (s == NULL) {
        return -1;
    }
    VANTAQ_ZERO_STRUCT(*s);

    snprintf(s->firmware_path, sizeof(s->firmware_path), "/tmp/vantaq_sel_firmware_%d.bin",
             getpid());
    snprintf(s->security_config_path, sizeof(s->security_config_path),
             "/tmp/vantaq_sel_security_%d.conf", getpid());
    snprintf(s->agent_binary_path, sizeof(s->agent_binary_path), "/tmp/vantaq_sel_agent_%d.bin",
             getpid());
    snprintf(s->boot_state_path, sizeof(s->boot_state_path), "/tmp/vantaq_sel_boot_%d.txt",
             getpid());

    if (write_file(s->firmware_path, "firmware-content-v1") != 0 ||
        write_file(s->security_config_path, "policy=v1\n") != 0 ||
        write_file(s->agent_binary_path, "agent-binary-content-v1") != 0 ||
        write_file(s->boot_state_path,
                   "secure_boot=mock_enabled\nboot_mode=normal\nrollback_detected=false\n") != 0) {
        unlink(s->firmware_path);
        unlink(s->security_config_path);
        unlink(s->agent_binary_path);
        unlink(s->boot_state_path);
        free(s);
        return -1;
    }

    VANTAQ_ZERO_STRUCT(opts);
    opts.tls_enabled                      = true;
    opts.require_client_cert              = true;
    opts.include_challenge                = true;
    opts.allowed_subnets                  = "127.0.0.1/32";
    opts.dev_allow_all_networks           = "false";
    opts.allowed_apis_yaml                = "      - POST /v1/attestation/challenge\n"
                                            "      - POST /v1/attestation/evidence\n";
    opts.supported_claims_yaml            = "    - device_identity\n"
                                            "    - firmware_hash\n"
                                            "    - config_hash\n"
                                            "    - agent_integrity\n"
                                            "    - boot_state\n";
    opts.measurement_firmware_path        = s->firmware_path;
    opts.measurement_security_config_path = s->security_config_path;
    opts.measurement_agent_binary_path    = s->agent_binary_path;
    opts.measurement_boot_state_path      = s->boot_state_path;
    opts.startup_timeout_ms               = 4000;
    opts.max_start_retries                = 5;
    setup_err[0]                          = '\0';

    if (vantaq_test_server_start(&opts, &s->server, setup_err, sizeof(setup_err)) != 0) {
        if (setup_err[0] != '\0') {
            print_error("test_selected_claims_only setup failed: %s\n", setup_err);
        }
        if (strstr(setup_err, "unable to reserve port") != NULL ||
            strstr(setup_err, "bind_failed") != NULL ||
            strstr(setup_err, "startup_timeout") != NULL) {
            unlink(s->firmware_path);
            unlink(s->security_config_path);
            unlink(s->agent_binary_path);
            unlink(s->boot_state_path);
            free(s);
            *state = NULL;
            return 0;
        }
        unlink(s->firmware_path);
        unlink(s->security_config_path);
        unlink(s->agent_binary_path);
        unlink(s->boot_state_path);
        free(s);
        return -1;
    }

    *state = s;
    return 0;
}

static int suite_teardown(void **state) {
    struct SelectedClaimsOnlySuite *s = *state;
    if (s != NULL) {
        vantaq_test_server_stop(&s->server);
        unlink(s->firmware_path);
        unlink(s->security_config_path);
        unlink(s->agent_binary_path);
        unlink(s->boot_state_path);
        free(s);
    }
    return 0;
}

static void test_only_firmware_hash_included(void **state) {
    struct SelectedClaimsOnlySuite *s = *state;
    char body[8192];
    int status = 0;

    if (s == NULL) {
        skip();
    }

    s_assert_int_equal(s,
                       request_evidence_with_claims(s->server.port, "[\"firmware_hash\"]", &status,
                                                    body, sizeof(body)),
                       0);
    s_assert_int_equal(s, status, 200);
    s_assert_non_null(s, strstr(body, "firmware_hash"));
    s_assert_true(s, strstr(body, "\"config_hash\":") == NULL);
    s_assert_true(s, strstr(body, "\"agent_integrity\":") == NULL);
    s_assert_true(s, strstr(body, "\"boot_state\":") == NULL);
    s_assert_true(s, strstr(body, "\"device_identity\":") == NULL);
    s_assert_int_equal(s, verify_evidence_signature(body, "only_firmware"), 0);
}

static void test_only_config_hash_included(void **state) {
    struct SelectedClaimsOnlySuite *s = *state;
    char body[8192];
    int status = 0;

    if (s == NULL) {
        skip();
    }

    s_assert_int_equal(s,
                       request_evidence_with_claims(s->server.port, "[\"config_hash\"]", &status,
                                                    body, sizeof(body)),
                       0);
    s_assert_int_equal(s, status, 200);
    s_assert_non_null(s, strstr(body, "config_hash"));
    s_assert_true(s, strstr(body, "\"firmware_hash\":") == NULL);
    s_assert_true(s, strstr(body, "\"agent_integrity\":") == NULL);
    s_assert_true(s, strstr(body, "\"boot_state\":") == NULL);
    s_assert_true(s, strstr(body, "\"device_identity\":") == NULL);
    s_assert_int_equal(s, verify_evidence_signature(body, "only_config"), 0);
}

static void test_firmware_hash_and_boot_state_only_included(void **state) {
    struct SelectedClaimsOnlySuite *s = *state;
    char body[8192];
    int status = 0;

    if (s == NULL) {
        skip();
    }

    s_assert_int_equal(s,
                       request_evidence_with_claims(s->server.port,
                                                    "[\"firmware_hash\",\"boot_state\"]", &status,
                                                    body, sizeof(body)),
                       0);
    s_assert_int_equal(s, status, 200);
    s_assert_non_null(s, strstr(body, "firmware_hash"));
    s_assert_non_null(s, strstr(body, "boot_state"));
    s_assert_non_null(s, strstr(body, "secure_boot"));
    s_assert_non_null(s, strstr(body, "boot_mode"));
    s_assert_true(s, strstr(body, "\"config_hash\":") == NULL);
    s_assert_true(s, strstr(body, "\"agent_integrity\":") == NULL);
    s_assert_true(s, strstr(body, "\"device_identity\":") == NULL);
    s_assert_int_equal(s, verify_evidence_signature(body, "firmware_boot"), 0);
}

static void test_all_supported_claims_included(void **state) {
    struct SelectedClaimsOnlySuite *s = *state;
    char body[8192];
    int status = 0;

    if (s == NULL) {
        skip();
    }

    s_assert_int_equal(
        s,
        request_evidence_with_claims(s->server.port,
                                     "[\"device_identity\",\"firmware_hash\",\"config_hash\","
                                     "\"agent_integrity\",\"boot_state\"]",
                                     &status, body, sizeof(body)),
        0);
    s_assert_int_equal(s, status, 200);
    s_assert_non_null(s, strstr(body, "device_identity"));
    s_assert_non_null(s, strstr(body, "firmware_hash"));
    s_assert_non_null(s, strstr(body, "config_hash"));
    s_assert_non_null(s, strstr(body, "agent_integrity"));
    s_assert_non_null(s, strstr(body, "boot_state"));
    s_assert_int_equal(s, verify_evidence_signature(body, "all_supported"), 0);
}

static void test_unsupported_claim_returns_400(void **state) {
    struct SelectedClaimsOnlySuite *s = *state;
    char body[8192];
    int status = 0;

    if (s == NULL) {
        skip();
    }

    s_assert_int_equal(s,
                       request_evidence_with_claims(s->server.port, "[\"not_a_real_claim\"]",
                                                    &status, body, sizeof(body)),
                       0);
    s_assert_int_equal(s, status, 400);
    s_assert_non_null(s, strstr(body, "unsupported_claim"));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_only_firmware_hash_included, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_only_config_hash_included, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_firmware_hash_and_boot_state_only_included,
                                        suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_all_supported_claims_included, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_unsupported_claim_returns_400, suite_setup,
                                        suite_teardown),
    };

    return cmocka_run_group_tests_name("integration_selected_claims_only", tests, NULL, NULL);
}
