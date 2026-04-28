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

#include <cmocka.h>

#define TEST_PRIV_KEY "test_priv.pem"
#define TEST_PUB_KEY "test_pub.pem"

static void create_test_keys() {
    system("openssl ecparam -name prime256v1 -genkey -noout -out test_priv.pem");
    system("openssl ec -in test_priv.pem -pubout -out test_pub.pem");
}

static void remove_test_keys() {
    remove(TEST_PRIV_KEY);
    remove(TEST_PUB_KEY);
}

static void test_create_evidence_success(void **state) {
    (void)state;
    struct vantaq_challenge_store *store = vantaq_challenge_store_memory_create(10, 5);
    vantaq_device_key_t *device_key      = NULL;
    vantaq_device_key_load(TEST_PRIV_KEY, TEST_PUB_KEY, &device_key);

    struct vantaq_challenge *challenge = NULL;
    enum vantaq_create_challenge_status store_s =
        vantaq_create_challenge(store, "verifier-1", "test", 60, &challenge);
    (void)store_s;
    const char *challenge_id = vantaq_challenge_get_id(challenge);
    const char *nonce        = vantaq_challenge_get_nonce_hex(challenge);

    struct vantaq_create_evidence_req req = {
        .challenge_id = challenge_id, .nonce = nonce, .claims = NULL, .claims_count = 0};
    struct vantaq_create_evidence_res res;
    memset(&res, 0, sizeof(res));

    vantaq_app_evidence_err_t err =
        vantaq_app_create_evidence(store, device_key, "verifier-1", &req, 1234567890, &res);

    assert_int_equal(err, VANTAQ_APP_EVIDENCE_OK);
    assert_non_null(res.evidence);
    assert_non_null(res.signature_b64);
    assert_string_equal(vantaq_evidence_get_challenge_id(res.evidence), challenge_id);
    assert_string_equal(vantaq_evidence_get_nonce(res.evidence), nonce);

    vantaq_create_evidence_res_free(&res);
    vantaq_device_key_destroy(device_key);
    vantaq_challenge_store_destroy(store);
}

static void test_create_evidence_nonce_mismatch(void **state) {
    (void)state;
    struct vantaq_challenge_store *store = vantaq_challenge_store_memory_create(10, 5);
    vantaq_device_key_t *device_key      = NULL;
    vantaq_device_key_load(TEST_PRIV_KEY, TEST_PUB_KEY, &device_key);

    struct vantaq_challenge *challenge = NULL;
    vantaq_create_challenge(store, "verifier-1", "test", 60, &challenge);
    const char *challenge_id = vantaq_challenge_get_id(challenge);

    struct vantaq_create_evidence_req req = {
        .challenge_id = challenge_id, .nonce = "wrong-nonce", .claims = NULL, .claims_count = 0};
    struct vantaq_create_evidence_res res;
    memset(&res, 0, sizeof(res));

    vantaq_app_evidence_err_t err =
        vantaq_app_create_evidence(store, device_key, "verifier-1", &req, 1234567890, &res);

    assert_int_equal(err, VANTAQ_APP_EVIDENCE_ERR_NONCE_MISMATCH);

    vantaq_device_key_destroy(device_key);
    vantaq_challenge_store_destroy(store);
}

int main(void) {
    create_test_keys();
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_create_evidence_success),
        cmocka_unit_test(test_create_evidence_nonce_mismatch),
    };
    int ret = cmocka_run_group_tests(tests, NULL, NULL);
    remove_test_keys();
    return ret;
}
