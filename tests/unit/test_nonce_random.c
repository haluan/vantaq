// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

// clang-format off
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>
// clang-format on
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "infrastructure/crypto/nonce_random.h"

// Suite Pattern: Struct to hold test state
struct NonceRandomTestSuite {
    char hex[128];
};

// Assert Pattern: s_assert_xyz style macros
#define s_assert_int_equal(s, a, b) assert_int_equal(a, b)
#define s_assert_string_equal(s, a, b) assert_string_equal(a, b)
#define s_assert_string_not_equal(s, a, b) assert_string_not_equal(a, b)
#define s_assert_true(s, a) assert_true(a)

static int suite_setup(void **state) {
    struct NonceRandomTestSuite *s = calloc(1, sizeof(struct NonceRandomTestSuite));
    if (!s)
        return -1;
    *state = s;
    return 0;
}

static int suite_teardown(void **state) {
    struct NonceRandomTestSuite *s = *state;
    free(s);
    return 0;
}

static void test_generate_nonce_success(void **state) {
    struct NonceRandomTestSuite *s = *state;
    size_t nonce_bytes             = 16;
    size_t expected_hex_len        = 32;

    enum vantaq_crypto_status status =
        vantaq_crypto_generate_nonce_hex(s->hex, sizeof(s->hex), nonce_bytes);

    s_assert_int_equal(s, status, VANTAQ_CRYPTO_OK);
    s_assert_int_equal(s, strlen(s->hex), expected_hex_len);

    // Check if it's hex
    for (size_t i = 0; i < expected_hex_len; i++) {
        char c      = s->hex[i];
        bool is_hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        s_assert_true(s, is_hex);
    }
}

static void test_generate_nonce_uniqueness(void **state) {
    struct NonceRandomTestSuite *s = *state;
    char hex1[128];
    char hex2[128];

    vantaq_crypto_generate_nonce_hex(hex1, sizeof(hex1), 16);
    vantaq_crypto_generate_nonce_hex(hex2, sizeof(hex2), 16);

    s_assert_string_not_equal(s, hex1, hex2);
}

static void test_generate_nonce_invalid_args(void **state) {
    struct NonceRandomTestSuite *s = *state;

    // NULL buffer
    s_assert_int_equal(s, vantaq_crypto_generate_nonce_hex(NULL, 128, 16),
                       VANTAQ_CRYPTO_ERROR_INVALID_ARGS);

    // Too short nonce (new minimum is 16)
    s_assert_int_equal(s, vantaq_crypto_generate_nonce_hex(s->hex, sizeof(s->hex), 15),
                       VANTAQ_CRYPTO_ERROR_INVALID_ARGS);

    // Too long nonce (new maximum is 64)
    s_assert_int_equal(s, vantaq_crypto_generate_nonce_hex(s->hex, sizeof(s->hex), 65),
                       VANTAQ_CRYPTO_ERROR_INVALID_ARGS);

    // Buffer too small (must be at least nonce_bytes * 2 + 1)
    s_assert_int_equal(s, vantaq_crypto_generate_nonce_hex(s->hex, 32, 16),
                       VANTAQ_CRYPTO_ERROR_INVALID_ARGS);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_generate_nonce_success, suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_generate_nonce_uniqueness, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_generate_nonce_invalid_args, suite_setup,
                                        suite_teardown),
    };

    return cmocka_run_group_tests_name("nonce_random_suite", tests, NULL, NULL);
}
