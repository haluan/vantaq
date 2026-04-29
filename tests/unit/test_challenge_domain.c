// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "domain/attestation_challenge/challenge.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
// clang-format on
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

// Suite Pattern: Struct to hold test state
struct ChallengeDomainTestSuite {
    struct vantaq_challenge *challenge;
};

// Assert Pattern: s_assert_xyz style macros
#define s_assert_int_equal(s, a, b) assert_int_equal(a, b)
#define s_assert_string_equal(s, a, b) assert_string_equal(a, b)
#define s_assert_non_null(s, a) assert_non_null(a)
#define s_assert_true(s, a) assert_true(a)
#define s_assert_false(s, a) assert_false(a)

static int suite_setup(void **state) {
    struct ChallengeDomainTestSuite *s = calloc(1, sizeof(struct ChallengeDomainTestSuite));
    if (!s)
        return -1;
    *state = s;
    return 0;
}

static int suite_teardown(void **state) {
    struct ChallengeDomainTestSuite *s = *state;
    if (s->challenge) {
        vantaq_challenge_destroy(s->challenge);
    }
    free(s);
    return 0;
}

static void test_challenge_creation_success(void **state) {
    struct ChallengeDomainTestSuite *s = *state;
    const char *id                     = "ch-001";
    const char *nonce                  = "1234567890abcdef1234567890abcdef";
    const char *verifier               = "govt-verifier-01";
    const char *purpose                = "remote_attestation";
    long created                       = 1000;
    long expires                       = 2000;

    s->challenge = vantaq_challenge_create(id, nonce, verifier, purpose, created, expires);

    s_assert_non_null(s, s->challenge);
    s_assert_string_equal(s, vantaq_challenge_get_id(s->challenge), id);
    s_assert_string_equal(s, vantaq_challenge_get_nonce_hex(s->challenge), nonce);
    s_assert_string_equal(s, vantaq_challenge_get_verifier_id(s->challenge), verifier);
    s_assert_string_equal(s, vantaq_challenge_get_purpose(s->challenge), purpose);
    s_assert_int_equal(s, vantaq_challenge_get_expires_at_ms(s->challenge), expires);
    s_assert_false(s, vantaq_challenge_is_used(s->challenge));
}

static void test_challenge_expiry_logic(void **state) {
    struct ChallengeDomainTestSuite *s = *state;

    // Create a challenge that expires at t=2000
    s->challenge = vantaq_challenge_create("ch-001", "nonce", "verifier", "purpose", 1000, 2000);
    s_assert_non_null(s, s->challenge);

    // Not expired at t=1500
    s_assert_false(s, vantaq_challenge_is_expired(s->challenge, 1500));

    // Expired at t=2000 (boundary case)
    s_assert_true(s, vantaq_challenge_is_expired(s->challenge, 2000));

    // Expired at t=2500
    s_assert_true(s, vantaq_challenge_is_expired(s->challenge, 2500));
}

static void test_challenge_mark_used(void **state) {
    struct ChallengeDomainTestSuite *s = *state;
    s->challenge = vantaq_challenge_create("ch-001", "nonce", "verifier", "purpose", 1000, 2000);

    s_assert_false(s, vantaq_challenge_is_used(s->challenge));
    vantaq_challenge_mark_used(s->challenge);
    s_assert_true(s, vantaq_challenge_is_used(s->challenge));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_challenge_creation_success, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_challenge_expiry_logic, suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_challenge_mark_used, suite_setup, suite_teardown),
    };

    return cmocka_run_group_tests_name("challenge_domain_suite", tests, NULL, NULL);
}
