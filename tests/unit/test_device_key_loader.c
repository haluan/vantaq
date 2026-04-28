// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

// clang-format off
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>
// clang-format on
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "infrastructure/crypto/device_key_loader.h"

// Suite Pattern: Struct to hold test state
struct DeviceKeyLoaderTestSuite {
    struct vantaq_device_key_t *key;
    char priv_path[256];
    char pub_path[256];
};

// Assert Pattern: s_assert_xyz style macros
#define s_assert_int_equal(s, a, b) assert_int_equal(a, b)
#define s_assert_string_equal(s, a, b) assert_string_equal(a, b)
#define s_assert_non_null(s, a) assert_non_null(a)
#define s_assert_null(s, a) assert_null(a)
#define s_assert_true(s, a) assert_true(a)
#define s_assert_false(s, a) assert_false(a)

static void write_dummy_file(const char *path, const char *content) {
    FILE *f = fopen(path, "wb");
    assert_non_null(f);
    size_t len     = strlen(content);
    size_t written = fwrite(content, 1, len, f);
    assert_int_equal(written, len);
    fclose(f);
}

static int suite_setup(void **state) {
    struct DeviceKeyLoaderTestSuite *s = calloc(1, sizeof(struct DeviceKeyLoaderTestSuite));
    if (!s)
        return -1;

    snprintf(s->priv_path, sizeof(s->priv_path), "test_priv_%d.pem", getpid());
    snprintf(s->pub_path, sizeof(s->pub_path), "test_pub_%d.pem", getpid());

    *state = s;
    return 0;
}

static int suite_teardown(void **state) {
    struct DeviceKeyLoaderTestSuite *s = *state;
    if (s->key) {
        vantaq_device_key_destroy(s->key);
    }
    unlink(s->priv_path);
    unlink(s->pub_path);
    free(s);
    return 0;
}

static void test_key_load_success(void **state) {
    struct DeviceKeyLoaderTestSuite *s = *state;
    const char *priv_content =
        "-----BEGIN PRIVATE KEY-----\nMOCK_PRIVATE\n-----END PRIVATE KEY-----";
    const char *pub_content = "-----BEGIN PUBLIC KEY-----\nMOCK_PUBLIC\n-----END PUBLIC KEY-----";

    write_dummy_file(s->priv_path, priv_content);
    write_dummy_file(s->pub_path, pub_content);

    vantaq_key_err_t err = vantaq_device_key_load(s->priv_path, s->pub_path, &s->key);

    s_assert_int_equal(s, err, VANTAQ_KEY_OK);
    s_assert_non_null(s, s->key);
    s_assert_string_equal(s, vantaq_device_key_get_private_pem(s->key), priv_content);
    s_assert_string_equal(s, vantaq_device_key_get_public_pem(s->key), pub_content);
}

static void test_key_load_missing_private(void **state) {
    struct DeviceKeyLoaderTestSuite *s = *state;
    unlink(s->priv_path); // Ensure it's gone

    vantaq_key_err_t err = vantaq_device_key_load(s->priv_path, s->pub_path, &s->key);

    s_assert_int_equal(s, err, VANTAQ_KEY_ERR_MISSING_FILE);
    s_assert_null(s, s->key);
}

static void test_key_load_missing_public(void **state) {
    struct DeviceKeyLoaderTestSuite *s = *state;
    write_dummy_file(s->priv_path, "some content");
    unlink(s->pub_path); // Ensure it's gone

    vantaq_key_err_t err = vantaq_device_key_load(s->priv_path, s->pub_path, &s->key);

    s_assert_int_equal(s, err, VANTAQ_KEY_ERR_MISSING_FILE);
    s_assert_null(s, s->key);
}

static void test_key_load_invalid_format(void **state) {
    struct DeviceKeyLoaderTestSuite *s = *state;
    write_dummy_file(s->priv_path, "-----BEGIN PRIVATE KEY-----\nMALFORMED-WITHOUT-END\n");
    write_dummy_file(s->pub_path,
                     "-----BEGIN PUBLIC KEY-----\nMOCK_PUBLIC\n-----END PUBLIC KEY-----");

    vantaq_key_err_t err = vantaq_device_key_load(s->priv_path, s->pub_path, &s->key);

    s_assert_int_equal(s, err, VANTAQ_KEY_ERR_INVALID_FORMAT);
    s_assert_null(s, s->key);
}

static void test_key_load_rejects_oversized_file(void **state) {
    struct DeviceKeyLoaderTestSuite *s = *state;
    FILE *f                            = fopen(s->priv_path, "wb");
    s_assert_non_null(s, f);
    for (size_t i = 0; i < (64U * 1024U) + 1U; ++i) {
        fputc('A', f);
    }
    fclose(f);
    write_dummy_file(s->pub_path,
                     "-----BEGIN PUBLIC KEY-----\nMOCK_PUBLIC\n-----END PUBLIC KEY-----");

    vantaq_key_err_t err = vantaq_device_key_load(s->priv_path, s->pub_path, &s->key);

    s_assert_int_equal(s, err, VANTAQ_KEY_ERR_FILE_TOO_LARGE);
    s_assert_null(s, s->key);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_key_load_success, suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_key_load_missing_private, suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_key_load_missing_public, suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_key_load_invalid_format, suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_key_load_rejects_oversized_file, suite_setup,
                                        suite_teardown),
    };

    return cmocka_run_group_tests_name("device_key_loader_suite", tests, NULL, NULL);
}
