// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/attestation_challenge/create_challenge.h"
#include "application/evidence/create_evidence.h"
#include "infrastructure/crypto/device_key_loader.h"
#include "infrastructure/memory/challenge_store_memory.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <cmocka.h>

#define TEST_PRIV_KEY "test_priv_ev.pem"
#define TEST_PUB_KEY "test_pub_ev.pem"

// Suite Pattern: Struct to hold test state
struct CreateEvidenceTestSuite {
    struct vantaq_challenge_store *store;
    struct vantaq_latest_evidence_store *latest_store;
    vantaq_device_key_t *device_key;
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

static int suite_setup(void **state) {
    create_test_keys();
    struct CreateEvidenceTestSuite *s = malloc(sizeof(struct CreateEvidenceTestSuite));
    if (!s)
        return -1;

    s->store        = vantaq_challenge_store_memory_create(10, 5);
    s->latest_store = vantaq_latest_evidence_store_create(5);
    s->device_key   = NULL;
    vantaq_device_key_load(TEST_PRIV_KEY, TEST_PUB_KEY, &s->device_key);
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

    vantaq_create_challenge(s->store, "verifier-1", "test", 60, &challenge);
    const char *challenge_id = vantaq_challenge_get_id(challenge);
    const char *nonce        = vantaq_challenge_get_nonce_hex(challenge);

    struct vantaq_create_evidence_req req = {
        .challenge_id = challenge_id, .nonce = nonce, .claims = NULL, .claims_count = 0};
    struct vantaq_create_evidence_res res;
    memset(&res, 0, sizeof(res));

    vantaq_app_evidence_err_t err = vantaq_app_create_evidence(
        s->store, s->latest_store, s->device_key, "verifier-1", &req, s->current_time, &res);

    s_assert_int_equal(s, err, VANTAQ_APP_EVIDENCE_OK);
    s_assert_non_null(s, res.evidence);
    s_assert_non_null(s, res.signature_b64);
    s_assert_string_equal(s, vantaq_evidence_get_challenge_id(res.evidence), challenge_id);
    s_assert_string_equal(s, vantaq_evidence_get_nonce(res.evidence), nonce);

    vantaq_create_evidence_res_free(&res);
}

static void test_create_evidence_challenge_not_found(void **state) {
    struct CreateEvidenceTestSuite *s     = *state;
    struct vantaq_create_evidence_req req = {
        .challenge_id = "non-existent", .nonce = "abcd", .claims = NULL, .claims_count = 0};
    struct vantaq_create_evidence_res res;
    memset(&res, 0, sizeof(res));

    vantaq_app_evidence_err_t err = vantaq_app_create_evidence(
        s->store, s->latest_store, s->device_key, "verifier-1", &req, s->current_time, &res);

    s_assert_int_equal(s, err, VANTAQ_APP_EVIDENCE_ERR_CHALLENGE_NOT_FOUND);
}

static void test_create_evidence_nonce_mismatch(void **state) {
    struct CreateEvidenceTestSuite *s  = *state;
    struct vantaq_challenge *challenge = NULL;
    vantaq_create_challenge(s->store, "verifier-1", "test", 60, &challenge);
    const char *challenge_id = vantaq_challenge_get_id(challenge);

    struct vantaq_create_evidence_req req = {
        .challenge_id = challenge_id, .nonce = "wrong-nonce", .claims = NULL, .claims_count = 0};
    struct vantaq_create_evidence_res res;
    memset(&res, 0, sizeof(res));

    vantaq_app_evidence_err_t err = vantaq_app_create_evidence(
        s->store, s->latest_store, s->device_key, "verifier-1", &req, s->current_time, &res);

    s_assert_int_equal(s, err, VANTAQ_APP_EVIDENCE_ERR_NONCE_MISMATCH);
}

static void test_create_evidence_challenge_expired(void **state) {
    struct CreateEvidenceTestSuite *s  = *state;
    struct vantaq_challenge *challenge = NULL;
    // Expire in 1 second
    vantaq_create_challenge(s->store, "verifier-1", "test", 1, &challenge);
    const char *challenge_id = vantaq_challenge_get_id(challenge);
    const char *nonce        = vantaq_challenge_get_nonce_hex(challenge);

    struct vantaq_create_evidence_req req = {
        .challenge_id = challenge_id, .nonce = nonce, .claims = NULL, .claims_count = 0};
    struct vantaq_create_evidence_res res;
    memset(&res, 0, sizeof(res));

    // Request 10 seconds later
    vantaq_app_evidence_err_t err = vantaq_app_create_evidence(
        s->store, s->latest_store, s->device_key, "verifier-1", &req, s->current_time + 10, &res);

    s_assert_int_equal(s, err, VANTAQ_APP_EVIDENCE_ERR_CHALLENGE_EXPIRED);
}

static void test_create_evidence_verifier_mismatch(void **state) {
    struct CreateEvidenceTestSuite *s  = *state;
    struct vantaq_challenge *challenge = NULL;
    vantaq_create_challenge(s->store, "verifier-1", "test", 60, &challenge);
    const char *challenge_id = vantaq_challenge_get_id(challenge);
    const char *nonce        = vantaq_challenge_get_nonce_hex(challenge);

    struct vantaq_create_evidence_req req = {
        .challenge_id = challenge_id, .nonce = nonce, .claims = NULL, .claims_count = 0};
    struct vantaq_create_evidence_res res;
    memset(&res, 0, sizeof(res));

    // Request from verifier-2 instead of verifier-1
    vantaq_app_evidence_err_t err = vantaq_app_create_evidence(
        s->store, s->latest_store, s->device_key, "verifier-2", &req, s->current_time, &res);

    s_assert_int_equal(s, err, VANTAQ_APP_EVIDENCE_ERR_VERIFIER_MISMATCH);
}

static void test_create_evidence_used_challenge(void **state) {
    struct CreateEvidenceTestSuite *s  = *state;
    struct vantaq_challenge *challenge = NULL;

    vantaq_create_challenge(s->store, "verifier-1", "test", 60, &challenge);
    const char *challenge_id = vantaq_challenge_get_id(challenge);
    const char *nonce        = vantaq_challenge_get_nonce_hex(challenge);

    struct vantaq_create_evidence_req req = {
        .challenge_id = challenge_id, .nonce = nonce, .claims = NULL, .claims_count = 0};
    struct vantaq_create_evidence_res res;
    memset(&res, 0, sizeof(res));

    // First use should succeed
    vantaq_app_evidence_err_t err = vantaq_app_create_evidence(
        s->store, s->latest_store, s->device_key, "verifier-1", &req, s->current_time, &res);
    s_assert_int_equal(s, err, VANTAQ_APP_EVIDENCE_OK);
    vantaq_create_evidence_res_free(&res);

    // Second use should fail with CHALLENGE_USED
    memset(&res, 0, sizeof(res));
    err = vantaq_app_create_evidence(s->store, s->latest_store, s->device_key, "verifier-1", &req,
                                     s->current_time, &res);
    s_assert_int_equal(s, err, VANTAQ_APP_EVIDENCE_ERR_CHALLENGE_USED);
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
    };
    return cmocka_run_group_tests_name("unit_create_evidence_validation", tests, NULL, NULL);
}
