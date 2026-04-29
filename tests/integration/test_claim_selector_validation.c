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

struct ClaimSelectorValidationSuite {
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

    snprintf(body_file, sizeof(body_file), "/tmp/vantaq_selector_claim_body_%d.tmp", getpid());
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

static int suite_setup(void **state) {
    struct ClaimSelectorValidationSuite *s = malloc(sizeof(*s));
    struct vantaq_test_server_opts opts;
    char setup_err[512];

    if (s == NULL) {
        return -1;
    }
    VANTAQ_ZERO_STRUCT(*s);

    snprintf(s->firmware_path, sizeof(s->firmware_path), "/tmp/vantaq_selector_firmware_%d.bin",
             getpid());
    snprintf(s->security_config_path, sizeof(s->security_config_path),
             "/tmp/vantaq_selector_security_%d.conf", getpid());
    snprintf(s->agent_binary_path, sizeof(s->agent_binary_path),
             "/tmp/vantaq_selector_agent_%d.bin", getpid());
    snprintf(s->boot_state_path, sizeof(s->boot_state_path), "/tmp/vantaq_selector_boot_%d.txt",
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
            print_error("test_claim_selector_validation setup failed: %s\n", setup_err);
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
    struct ClaimSelectorValidationSuite *s = *state;
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

static void test_unknown_claim_returns_400(void **state) {
    struct ClaimSelectorValidationSuite *s = *state;
    char challenge_id[128];
    char nonce[128];
    char req[768];
    char body[4096];
    int status = 0;

    if (s == NULL) {
        skip();
    }

    s_assert_int_equal(
        s,
        request_challenge(s->server.port, challenge_id, sizeof(challenge_id), nonce, sizeof(nonce)),
        0);
    snprintf(req, sizeof(req),
             "{\"challenge_id\":\"%s\",\"nonce\":\"%s\",\"claims\":[\"not_a_claim\"]}",
             challenge_id, nonce);
    s_assert_int_equal(s,
                       curl_mtls_post_status_body(s->server.port, "/v1/attestation/evidence", req,
                                                  &status, body, sizeof(body)),
                       0);
    s_assert_int_equal(s, status, 400);
    s_assert_non_null(s, strstr(body, "UNSUPPORTED_CLAIM"));
}

static void test_duplicate_claim_returns_400(void **state) {
    struct ClaimSelectorValidationSuite *s = *state;
    char challenge_id[128];
    char nonce[128];
    char req[768];
    char body[4096];
    int status = 0;

    if (s == NULL) {
        skip();
    }

    s_assert_int_equal(
        s,
        request_challenge(s->server.port, challenge_id, sizeof(challenge_id), nonce, sizeof(nonce)),
        0);
    snprintf(req, sizeof(req),
             "{\"challenge_id\":\"%s\",\"nonce\":\"%s\",\"claims\":[\"firmware_hash\",\"firmware_"
             "hash\"]}",
             challenge_id, nonce);
    s_assert_int_equal(s,
                       curl_mtls_post_status_body(s->server.port, "/v1/attestation/evidence", req,
                                                  &status, body, sizeof(body)),
                       0);
    s_assert_int_equal(s, status, 400);
    s_assert_non_null(s, strstr(body, "INVALID_CLAIMS"));
}

static void test_too_many_claims_returns_400(void **state) {
    struct ClaimSelectorValidationSuite *s = *state;
    char challenge_id[128];
    char nonce[128];
    char req[1024];
    char body[4096];
    int status = 0;

    if (s == NULL) {
        skip();
    }

    s_assert_int_equal(
        s,
        request_challenge(s->server.port, challenge_id, sizeof(challenge_id), nonce, sizeof(nonce)),
        0);
    snprintf(req, sizeof(req),
             "{\"challenge_id\":\"%s\",\"nonce\":\"%s\",\"claims\":[\"firmware_hash\",\"device_"
             "identity\",\"config_hash\",\"agent_integrity\",\"boot_state\",\"firmware_hash\","
             "\"device_identity\",\"config_hash\",\"agent_integrity\"]}",
             challenge_id, nonce);
    s_assert_int_equal(s,
                       curl_mtls_post_status_body(s->server.port, "/v1/attestation/evidence", req,
                                                  &status, body, sizeof(body)),
                       0);
    s_assert_int_equal(s, status, 400);
    s_assert_non_null(s, strstr(body, "INVALID_CLAIMS"));
}

static void test_known_disallowed_claim_returns_403(void **state) {
    struct ClaimSelectorValidationSuite *s = *state;
    struct vantaq_test_server_handle deny_server;
    struct vantaq_test_server_opts opts;
    char firmware_path[256];
    char security_config_path[256];
    char agent_binary_path[256];
    char boot_state_path[256];
    char setup_err[512];
    char challenge_id[128];
    char nonce[128];
    char req[768];
    char body[4096];
    int status = 0;

    if (s == NULL) {
        skip();
    }

    VANTAQ_ZERO_STRUCT(deny_server);
    VANTAQ_ZERO_STRUCT(opts);

    snprintf(firmware_path, sizeof(firmware_path), "/tmp/vantaq_selector_deny_firmware_%d.bin",
             getpid());
    snprintf(security_config_path, sizeof(security_config_path),
             "/tmp/vantaq_selector_deny_security_%d.conf", getpid());
    snprintf(agent_binary_path, sizeof(agent_binary_path), "/tmp/vantaq_selector_deny_agent_%d.bin",
             getpid());
    snprintf(boot_state_path, sizeof(boot_state_path), "/tmp/vantaq_selector_deny_boot_%d.txt",
             getpid());

    s_assert_int_equal(s, write_file(firmware_path, "firmware-content-v1"), 0);
    s_assert_int_equal(s, write_file(security_config_path, "policy=v1\n"), 0);
    s_assert_int_equal(s, write_file(agent_binary_path, "agent-binary-content-v1"), 0);
    s_assert_int_equal(s,
                       write_file(boot_state_path, "secure_boot=mock_enabled\nboot_mode=normal\n"
                                                   "rollback_detected=false\n"),
                       0);

    opts.tls_enabled                      = true;
    opts.require_client_cert              = true;
    opts.include_challenge                = true;
    opts.allowed_subnets                  = "127.0.0.1/32";
    opts.dev_allow_all_networks           = "false";
    opts.allowed_apis_yaml                = "      - POST /v1/attestation/challenge\n"
                                            "      - POST /v1/attestation/evidence\n";
    opts.supported_claims_yaml            = "    - device_identity\n";
    opts.measurement_firmware_path        = firmware_path;
    opts.measurement_security_config_path = security_config_path;
    opts.measurement_agent_binary_path    = agent_binary_path;
    opts.measurement_boot_state_path      = boot_state_path;
    opts.startup_timeout_ms               = 4000;
    opts.max_start_retries                = 5;
    setup_err[0]                          = '\0';

    s_assert_int_equal(
        s, vantaq_test_server_start(&opts, &deny_server, setup_err, sizeof(setup_err)), 0);

    s_assert_int_equal(s,
                       request_challenge(deny_server.port, challenge_id, sizeof(challenge_id),
                                         nonce, sizeof(nonce)),
                       0);
    snprintf(req, sizeof(req),
             "{\"challenge_id\":\"%s\",\"nonce\":\"%s\",\"claims\":[\"boot_state\"]}", challenge_id,
             nonce);
    s_assert_int_equal(s,
                       curl_mtls_post_status_body(deny_server.port, "/v1/attestation/evidence", req,
                                                  &status, body, sizeof(body)),
                       0);
    s_assert_int_equal(s, status, 403);
    s_assert_non_null(s, strstr(body, "CLAIM_NOT_ALLOWED"));

    vantaq_test_server_stop(&deny_server);
    unlink(firmware_path);
    unlink(security_config_path);
    unlink(agent_binary_path);
    unlink(boot_state_path);
}

static void test_valid_subset_has_deterministic_order_and_valid_signature(void **state) {
    struct ClaimSelectorValidationSuite *s = *state;
    char challenge_id[128];
    char nonce[128];
    char req[1024];
    char body[8192];
    int status = 0;
    const char *pos_device_identity;
    const char *pos_firmware_hash;
    const char *pos_config_hash;
    const char *pos_agent_integrity;
    const char *pos_boot_state;
    FILE *fp;
    int rc;

    if (s == NULL) {
        skip();
    }

    s_assert_int_equal(
        s,
        request_challenge(s->server.port, challenge_id, sizeof(challenge_id), nonce, sizeof(nonce)),
        0);

    snprintf(req, sizeof(req),
             "{\"challenge_id\":\"%s\",\"nonce\":\"%s\",\"claims\":[\"boot_state\",\"firmware_"
             "hash\",\"device_identity\",\"agent_integrity\",\"config_hash\"]}",
             challenge_id, nonce);
    s_assert_int_equal(s,
                       curl_mtls_post_status_body(s->server.port, "/v1/attestation/evidence", req,
                                                  &status, body, sizeof(body)),
                       0);
    s_assert_int_equal(s, status, 200);

    pos_device_identity = strstr(body, "\"device_identity\":{");
    pos_firmware_hash   = strstr(body, "\"firmware_hash\":\"sha256:");
    pos_config_hash     = strstr(body, "\"config_hash\":\"sha256:");
    pos_agent_integrity = strstr(body, "\"agent_integrity\":\"sha256:");
    pos_boot_state      = strstr(body, "\"boot_state\":{");

    s_assert_non_null(s, pos_device_identity);
    s_assert_non_null(s, pos_firmware_hash);
    s_assert_non_null(s, pos_config_hash);
    s_assert_non_null(s, pos_agent_integrity);
    s_assert_non_null(s, pos_boot_state);

    s_assert_true(s, pos_device_identity < pos_firmware_hash);
    s_assert_true(s, pos_firmware_hash < pos_config_hash);
    s_assert_true(s, pos_config_hash < pos_agent_integrity);
    s_assert_true(s, pos_agent_integrity < pos_boot_state);

    fp = fopen("/tmp/vantaq_selector_claim_evidence.json", "wb");
    s_assert_non_null(s, fp);
    fprintf(fp, "%s", body);
    fclose(fp);

    rc = system("./bin/verify_evidence /tmp/vantaq_selector_claim_evidence.json "
                "config/certs/device-server.crt > /dev/null 2>&1");
    s_assert_int_equal(s, WEXITSTATUS(rc), 0);
    unlink("/tmp/vantaq_selector_claim_evidence.json");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_unknown_claim_returns_400, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_duplicate_claim_returns_400, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_too_many_claims_returns_400, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_known_disallowed_claim_returns_403, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(
            test_valid_subset_has_deterministic_order_and_valid_signature, suite_setup,
            suite_teardown),
    };

    return cmocka_run_group_tests_name("integration_claim_selector_validation", tests, NULL, NULL);
}
