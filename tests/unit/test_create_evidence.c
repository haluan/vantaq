// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/attestation_challenge/create_challenge.h"
#include "application/evidence/create_evidence.h"
#include "domain/measurement/supported_claims.h"
#include "infrastructure/config_loader.h"
#include "infrastructure/config_loader_internal.h"
#include "infrastructure/crypto/device_key_loader.h"
#include "infrastructure/memory/challenge_store_memory.h"
#include "infrastructure/memory/zero_struct.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <cmocka.h>

#define TEST_PRIV_KEY "test_priv_ev.pem"
#define TEST_PUB_KEY "test_pub_ev.pem"

// Suite Pattern: Struct to hold test state
struct CreateEvidenceTestSuite {
    struct vantaq_challenge_store *store;
    struct vantaq_latest_evidence_store *latest_store;
    vantaq_device_key_t *device_key;
    struct vantaq_runtime_config runtime_config;
    int64_t current_time;
};

// Assert Pattern: Direct s_assert_xyz style macros
#define s_assert_int_equal(s, a, b) assert_int_equal(a, b)
#define s_assert_non_null(s, a) assert_non_null(a)
#define s_assert_null(s, a) assert_null(a)
#define s_assert_string_equal(s, a, b) assert_string_equal(a, b)

static void create_test_keys() {
    (void)system(
        "openssl ecparam -name prime256v1 -genkey -noout -out test_priv_ev.pem 2>/dev/null");
    (void)system("openssl ec -in test_priv_ev.pem -pubout -out test_pub_ev.pem 2>/dev/null");
}

static void remove_test_keys() {
    (void)remove(TEST_PRIV_KEY);
    (void)remove(TEST_PUB_KEY);
}

static void set_supported_claims(struct vantaq_runtime_config *config, bool include_firmware_hash) {
    config->supported_claims.count    = 0;
    config->supported_claims.items[0] = (char *)VANTAQ_CLAIM_DEVICE_IDENTITY;
    config->supported_claims.count    = 1;
    if (include_firmware_hash) {
        config->supported_claims.items[1] = (char *)VANTAQ_CLAIM_FIRMWARE_HASH;
        config->supported_claims.count    = 2;
    }
}

static int suite_setup(void **state) {
    create_test_keys();
    struct CreateEvidenceTestSuite *s = malloc(sizeof(struct CreateEvidenceTestSuite));
    if (!s)
        return -1;

    s->store        = vantaq_challenge_store_memory_create(10, 5);
    s->latest_store = vantaq_latest_evidence_store_create(5);
    s->device_key   = NULL;
    vantaq_device_key_load(NULL, TEST_PRIV_KEY, TEST_PUB_KEY, &s->device_key);
    VANTAQ_ZERO_STRUCT(s->runtime_config);
    s->runtime_config.cbSize = sizeof(s->runtime_config);
    strncpy(s->runtime_config.model, "edge-gateway-v1", sizeof(s->runtime_config.model) - 1);
    strncpy(s->runtime_config.serial_number, "SN-001", sizeof(s->runtime_config.serial_number) - 1);
    strncpy(s->runtime_config.measurement_firmware_path, "/tmp/vantaq_missing_firmware.bin",
            sizeof(s->runtime_config.measurement_firmware_path) - 1);
    s->runtime_config.measurement_max_file_bytes = 1024;
    set_supported_claims(&s->runtime_config, false);
    s->current_time = (int64_t)time(NULL);

    *state = s;
    return 0;
}

static int suite_teardown(void **state) {
    struct CreateEvidenceTestSuite *s = *state;
    if (s) {
        if (s->device_key)
            vantaq_device_key_destroy(s->device_key);
        if (s->store)
            vantaq_challenge_store_destroy(s->store);
        if (s->latest_store)
            vantaq_latest_evidence_store_destroy(s->latest_store);
        free(s);
    }
    remove_test_keys();
    return 0;
}

static void test_create_evidence_success(void **state) {
    struct CreateEvidenceTestSuite *s  = *state;
    struct vantaq_challenge *challenge = NULL;
    const char *claims[]               = {VANTAQ_CLAIM_DEVICE_IDENTITY};

    vantaq_create_challenge(s->store, "verifier-1", "test", 60, &challenge);
    const char *challenge_id = vantaq_challenge_get_id(challenge);
    const char *nonce        = vantaq_challenge_get_nonce_hex(challenge);

    struct vantaq_create_evidence_req req = {.challenge_id = challenge_id,
                                             .nonce        = nonce,
                                             .device_id    = "test-device-1",
                                             .claims       = claims,
                                             .claims_count = 1};
    struct vantaq_create_evidence_res res;
    memset(&res, 0, sizeof(res));

    struct vantaq_app_evidence_context app_ctx = {.store             = s->store,
                                                  .latest_store      = s->latest_store,
                                                  .runtime_config    = &s->runtime_config,
                                                  .device_key        = s->device_key,
                                                  .current_time_unix = s->current_time};

    vantaq_app_evidence_err_t err = vantaq_app_create_evidence(&app_ctx, "verifier-1", &req, &res);

    s_assert_int_equal(s, err, VANTAQ_APP_EVIDENCE_OK);
    s_assert_non_null(s, res.evidence);
    s_assert_non_null(s, res.signature_b64);
    s_assert_string_equal(s, vantaq_evidence_get_challenge_id(res.evidence), challenge_id);
    s_assert_string_equal(s, vantaq_evidence_get_nonce(res.evidence), nonce);
    s_assert_string_equal(s, vantaq_evidence_get_signature(res.evidence), res.signature_b64);

    vantaq_create_evidence_res_free(&res);
}

static void test_create_evidence_challenge_not_found(void **state) {
    struct CreateEvidenceTestSuite *s     = *state;
    const char *claims[]                  = {VANTAQ_CLAIM_DEVICE_IDENTITY};
    struct vantaq_create_evidence_req req = {.challenge_id = "non-existent",
                                             .nonce        = "abcd",
                                             .device_id    = "test-device-1",
                                             .claims       = claims,
                                             .claims_count = 1};
    struct vantaq_create_evidence_res res;
    memset(&res, 0, sizeof(res));

    struct vantaq_app_evidence_context app_ctx = {.store             = s->store,
                                                  .latest_store      = s->latest_store,
                                                  .runtime_config    = &s->runtime_config,
                                                  .device_key        = s->device_key,
                                                  .current_time_unix = s->current_time};

    vantaq_app_evidence_err_t err = vantaq_app_create_evidence(&app_ctx, "verifier-1", &req, &res);

    s_assert_int_equal(s, err, VANTAQ_APP_EVIDENCE_ERR_CHALLENGE_NOT_FOUND);
}

static void test_create_evidence_nonce_mismatch(void **state) {
    struct CreateEvidenceTestSuite *s  = *state;
    struct vantaq_challenge *challenge = NULL;
    const char *claims[]               = {VANTAQ_CLAIM_DEVICE_IDENTITY};
    vantaq_create_challenge(s->store, "verifier-1", "test", 60, &challenge);
    const char *challenge_id = vantaq_challenge_get_id(challenge);

    struct vantaq_create_evidence_req req = {.challenge_id = challenge_id,
                                             .nonce        = "wrong-nonce",
                                             .device_id    = "test-device-1",
                                             .claims       = claims,
                                             .claims_count = 1};
    struct vantaq_create_evidence_res res;
    memset(&res, 0, sizeof(res));

    struct vantaq_app_evidence_context app_ctx = {.store             = s->store,
                                                  .latest_store      = s->latest_store,
                                                  .runtime_config    = &s->runtime_config,
                                                  .device_key        = s->device_key,
                                                  .current_time_unix = s->current_time};

    vantaq_app_evidence_err_t err = vantaq_app_create_evidence(&app_ctx, "verifier-1", &req, &res);

    s_assert_int_equal(s, err, VANTAQ_APP_EVIDENCE_ERR_NONCE_MISMATCH);
}

static void test_create_evidence_challenge_expired(void **state) {
    struct CreateEvidenceTestSuite *s  = *state;
    struct vantaq_challenge *challenge = NULL;
    const char *claims[]               = {VANTAQ_CLAIM_DEVICE_IDENTITY};
    // Expire in 1 second
    vantaq_create_challenge(s->store, "verifier-1", "test", 1, &challenge);
    const char *challenge_id = vantaq_challenge_get_id(challenge);
    const char *nonce        = vantaq_challenge_get_nonce_hex(challenge);

    struct vantaq_create_evidence_req req = {.challenge_id = challenge_id,
                                             .nonce        = nonce,
                                             .device_id    = "test-device-1",
                                             .claims       = claims,
                                             .claims_count = 1};
    struct vantaq_create_evidence_res res;
    memset(&res, 0, sizeof(res));

    // Request 10 seconds later
    struct vantaq_app_evidence_context app_ctx = {.store             = s->store,
                                                  .latest_store      = s->latest_store,
                                                  .runtime_config    = &s->runtime_config,
                                                  .device_key        = s->device_key,
                                                  .current_time_unix = s->current_time + 10};

    vantaq_app_evidence_err_t err = vantaq_app_create_evidence(&app_ctx, "verifier-1", &req, &res);

    s_assert_int_equal(s, err, VANTAQ_APP_EVIDENCE_ERR_CHALLENGE_EXPIRED);
}

static void test_create_evidence_verifier_mismatch(void **state) {
    struct CreateEvidenceTestSuite *s  = *state;
    struct vantaq_challenge *challenge = NULL;
    const char *claims[]               = {VANTAQ_CLAIM_DEVICE_IDENTITY};
    vantaq_create_challenge(s->store, "verifier-1", "test", 60, &challenge);
    const char *challenge_id = vantaq_challenge_get_id(challenge);
    const char *nonce        = vantaq_challenge_get_nonce_hex(challenge);

    struct vantaq_create_evidence_req req = {.challenge_id = challenge_id,
                                             .nonce        = nonce,
                                             .device_id    = "test-device-1",
                                             .claims       = claims,
                                             .claims_count = 1};
    struct vantaq_create_evidence_res res;
    memset(&res, 0, sizeof(res));

    // Request from verifier-2 instead of verifier-1
    struct vantaq_app_evidence_context app_ctx = {.store             = s->store,
                                                  .latest_store      = s->latest_store,
                                                  .runtime_config    = &s->runtime_config,
                                                  .device_key        = s->device_key,
                                                  .current_time_unix = s->current_time};

    vantaq_app_evidence_err_t err = vantaq_app_create_evidence(&app_ctx, "verifier-2", &req, &res);

    s_assert_int_equal(s, err, VANTAQ_APP_EVIDENCE_ERR_VERIFIER_MISMATCH);
}

static void test_create_evidence_used_challenge(void **state) {
    struct CreateEvidenceTestSuite *s  = *state;
    struct vantaq_challenge *challenge = NULL;
    const char *claims[]               = {VANTAQ_CLAIM_DEVICE_IDENTITY};

    vantaq_create_challenge(s->store, "verifier-1", "test", 60, &challenge);
    const char *challenge_id = vantaq_challenge_get_id(challenge);
    const char *nonce        = vantaq_challenge_get_nonce_hex(challenge);

    struct vantaq_create_evidence_req req = {.challenge_id = challenge_id,
                                             .nonce        = nonce,
                                             .device_id    = "test-device-1",
                                             .claims       = claims,
                                             .claims_count = 1};
    struct vantaq_create_evidence_res res;
    memset(&res, 0, sizeof(res));

    // First use should succeed
    struct vantaq_app_evidence_context app_ctx = {.store             = s->store,
                                                  .latest_store      = s->latest_store,
                                                  .runtime_config    = &s->runtime_config,
                                                  .device_key        = s->device_key,
                                                  .current_time_unix = s->current_time};

    vantaq_app_evidence_err_t err = vantaq_app_create_evidence(&app_ctx, "verifier-1", &req, &res);
    s_assert_int_equal(s, err, VANTAQ_APP_EVIDENCE_OK);
    vantaq_create_evidence_res_free(&res);

    // Second use should fail with CHALLENGE_USED
    memset(&res, 0, sizeof(res));
    {
        struct vantaq_app_evidence_context app_ctx_local = {.store             = s->store,
                                                            .latest_store      = s->latest_store,
                                                            .runtime_config    = &s->runtime_config,
                                                            .device_key        = s->device_key,
                                                            .current_time_unix = s->current_time};
        err = vantaq_app_create_evidence(&app_ctx_local, "verifier-1", &req, &res);
    }
    s_assert_int_equal(s, err, VANTAQ_APP_EVIDENCE_ERR_CHALLENGE_USED);
}

static void test_create_evidence_unsupported_claim(void **state) {
    struct CreateEvidenceTestSuite *s  = *state;
    struct vantaq_challenge *challenge = NULL;
    const char *claims[]               = {"not_a_claim"};
    struct vantaq_create_evidence_res res;
    struct vantaq_create_evidence_req req;
    vantaq_app_evidence_err_t err;

    vantaq_create_challenge(s->store, "verifier-1", "test", 60, &challenge);
    req.challenge_id = vantaq_challenge_get_id(challenge);
    req.nonce        = vantaq_challenge_get_nonce_hex(challenge);
    req.device_id    = "test-device-1";
    req.claims       = claims;
    req.claims_count = 1;
    memset(&res, 0, sizeof(res));

    {
        struct vantaq_app_evidence_context app_ctx_local = {.store             = s->store,
                                                            .latest_store      = s->latest_store,
                                                            .runtime_config    = &s->runtime_config,
                                                            .device_key        = s->device_key,
                                                            .current_time_unix = s->current_time};
        err = vantaq_app_create_evidence(&app_ctx_local, "verifier-1", &req, &res);
    }
    s_assert_int_equal(s, err, VANTAQ_APP_EVIDENCE_ERR_UNSUPPORTED_CLAIM);
}

static void test_create_evidence_empty_claims_rejected(void **state) {
    struct CreateEvidenceTestSuite *s  = *state;
    struct vantaq_challenge *challenge = NULL;
    struct vantaq_create_evidence_res res;
    struct vantaq_create_evidence_req req;
    vantaq_app_evidence_err_t err;

    vantaq_create_challenge(s->store, "verifier-1", "test", 60, &challenge);
    req.challenge_id = vantaq_challenge_get_id(challenge);
    req.nonce        = vantaq_challenge_get_nonce_hex(challenge);
    req.device_id    = "test-device-1";
    req.claims       = NULL;
    req.claims_count = 0;
    memset(&res, 0, sizeof(res));

    {
        struct vantaq_app_evidence_context app_ctx_local = {.store             = s->store,
                                                            .latest_store      = s->latest_store,
                                                            .runtime_config    = &s->runtime_config,
                                                            .device_key        = s->device_key,
                                                            .current_time_unix = s->current_time};
        err = vantaq_app_create_evidence(&app_ctx_local, "verifier-1", &req, &res);
    }
    s_assert_int_equal(s, err, VANTAQ_APP_EVIDENCE_ERR_INVALID_CLAIMS);
}

static void test_create_evidence_claim_not_allowed(void **state) {
    struct CreateEvidenceTestSuite *s  = *state;
    struct vantaq_challenge *challenge = NULL;
    const char *claims[]               = {VANTAQ_CLAIM_FIRMWARE_HASH};
    struct vantaq_create_evidence_res res;
    struct vantaq_create_evidence_req req;
    vantaq_app_evidence_err_t err;

    set_supported_claims(&s->runtime_config, false);
    vantaq_create_challenge(s->store, "verifier-1", "test", 60, &challenge);
    req.challenge_id = vantaq_challenge_get_id(challenge);
    req.nonce        = vantaq_challenge_get_nonce_hex(challenge);
    req.device_id    = "test-device-1";
    req.claims       = claims;
    req.claims_count = 1;
    memset(&res, 0, sizeof(res));

    {
        struct vantaq_app_evidence_context app_ctx_local = {.store             = s->store,
                                                            .latest_store      = s->latest_store,
                                                            .runtime_config    = &s->runtime_config,
                                                            .device_key        = s->device_key,
                                                            .current_time_unix = s->current_time};
        err = vantaq_app_create_evidence(&app_ctx_local, "verifier-1", &req, &res);
    }
    s_assert_int_equal(s, err, VANTAQ_APP_EVIDENCE_ERR_CLAIM_NOT_ALLOWED);
}

static void test_create_evidence_duplicate_claims_invalid(void **state) {
    struct CreateEvidenceTestSuite *s  = *state;
    struct vantaq_challenge *challenge = NULL;
    const char *claims[]               = {VANTAQ_CLAIM_FIRMWARE_HASH, VANTAQ_CLAIM_FIRMWARE_HASH};
    struct vantaq_create_evidence_res res;
    struct vantaq_create_evidence_req req;
    vantaq_app_evidence_err_t err;

    set_supported_claims(&s->runtime_config, true);
    vantaq_create_challenge(s->store, "verifier-1", "test", 60, &challenge);
    req.challenge_id = vantaq_challenge_get_id(challenge);
    req.nonce        = vantaq_challenge_get_nonce_hex(challenge);
    req.device_id    = "test-device-1";
    req.claims       = claims;
    req.claims_count = 2;
    memset(&res, 0, sizeof(res));

    {
        struct vantaq_app_evidence_context app_ctx_local = {.store             = s->store,
                                                            .latest_store      = s->latest_store,
                                                            .runtime_config    = &s->runtime_config,
                                                            .device_key        = s->device_key,
                                                            .current_time_unix = s->current_time};
        err = vantaq_app_create_evidence(&app_ctx_local, "verifier-1", &req, &res);
    }
    s_assert_int_equal(s, err, VANTAQ_APP_EVIDENCE_ERR_INVALID_CLAIMS);
}

static void test_create_evidence_firmware_source_not_found(void **state) {
    struct CreateEvidenceTestSuite *s  = *state;
    struct vantaq_challenge *challenge = NULL;
    const char *claims[]               = {VANTAQ_CLAIM_FIRMWARE_HASH};
    struct vantaq_create_evidence_res res;
    struct vantaq_create_evidence_req req;
    vantaq_app_evidence_err_t err;

    unlink("/tmp/vantaq_missing_firmware.bin");
    set_supported_claims(&s->runtime_config, true);
    vantaq_create_challenge(s->store, "verifier-1", "test", 60, &challenge);
    req.challenge_id = vantaq_challenge_get_id(challenge);
    req.nonce        = vantaq_challenge_get_nonce_hex(challenge);
    req.device_id    = "test-device-1";
    req.claims       = claims;
    req.claims_count = 1;
    memset(&res, 0, sizeof(res));

    {
        struct vantaq_app_evidence_context app_ctx_local = {.store             = s->store,
                                                            .latest_store      = s->latest_store,
                                                            .runtime_config    = &s->runtime_config,
                                                            .device_key        = s->device_key,
                                                            .current_time_unix = s->current_time};
        err = vantaq_app_create_evidence(&app_ctx_local, "verifier-1", &req, &res);
    }
    s_assert_int_equal(s, err, VANTAQ_APP_EVIDENCE_ERR_MEASUREMENT_SOURCE_NOT_FOUND);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_create_evidence_success, suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_create_evidence_challenge_not_found, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_create_evidence_nonce_mismatch, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_create_evidence_challenge_expired, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_create_evidence_verifier_mismatch, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_create_evidence_used_challenge, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_create_evidence_unsupported_claim, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_create_evidence_empty_claims_rejected, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_create_evidence_claim_not_allowed, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_create_evidence_duplicate_claims_invalid, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_create_evidence_firmware_source_not_found, suite_setup,
                                        suite_teardown),
    };
    return cmocka_run_group_tests_name("unit_create_evidence_validation", tests, NULL, NULL);
}
