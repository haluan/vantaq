// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "domain/measurement/measurement.h"
#include "domain/measurement/supported_claims.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

struct MeasurementDomainTestSuite {
    struct vantaq_measurement_result *result;
};

#define s_assert_int_equal(s, a, b) assert_int_equal(a, b)
#define s_assert_string_equal(s, a, b) assert_string_equal(a, b)
#define s_assert_non_null(s, a) assert_non_null(a)
#define s_assert_null(s, a) assert_null(a)
#define s_assert_true(s, a) assert_true(a)
#define s_assert_false(s, a) assert_false(a)

static int suite_setup(void **state) {
    struct MeasurementDomainTestSuite *s = calloc(1, sizeof(struct MeasurementDomainTestSuite));
    if (!s)
        return -1;
    *state = s;
    return 0;
}

static int suite_teardown(void **state) {
    struct MeasurementDomainTestSuite *s = *state;
    if (s->result) {
        vantaq_measurement_result_destroy(s->result);
        s->result = NULL;
    }
    free(s);
    return 0;
}

static void fill_buffer(char *buffer, size_t len, char fill_char) {
    memset(buffer, fill_char, len);
    buffer[len] = '\0';
}

static void test_measurement_success_creation(void **state) {
    struct MeasurementDomainTestSuite *s = *state;
    vantaq_measurement_model_err_t err   = vantaq_measurement_result_create_success(
        "firmware_hash", "sha256:abc123", "/opt/vantaqd/firmware/current.bin", &s->result);

    s_assert_int_equal(s, err, VANTAQ_MEASUREMENT_MODEL_OK);
    s_assert_non_null(s, s->result);
    s_assert_string_equal(s, vantaq_measurement_result_get_claim_name(s->result), "firmware_hash");
    s_assert_string_equal(s, vantaq_measurement_result_get_value(s->result), "sha256:abc123");
    s_assert_string_equal(s, vantaq_measurement_result_get_source_path(s->result),
                          "/opt/vantaqd/firmware/current.bin");
    s_assert_int_equal(s, vantaq_measurement_result_get_status(s->result),
                       VANTAQ_MEASUREMENT_STATUS_SUCCESS);
    s_assert_int_equal(s, vantaq_measurement_result_get_error_code(s->result), MEASUREMENT_OK);
}

static void test_measurement_error_source_not_found(void **state) {
    struct MeasurementDomainTestSuite *s = *state;
    vantaq_measurement_model_err_t err   = vantaq_measurement_result_create_error(
        "config_hash", "/etc/vantaqd/security.conf", MEASUREMENT_SOURCE_NOT_FOUND, &s->result);

    s_assert_int_equal(s, err, VANTAQ_MEASUREMENT_MODEL_OK);
    s_assert_non_null(s, s->result);
    s_assert_int_equal(s, vantaq_measurement_result_get_status(s->result),
                       VANTAQ_MEASUREMENT_STATUS_ERROR);
    s_assert_int_equal(s, vantaq_measurement_result_get_error_code(s->result),
                       MEASUREMENT_SOURCE_NOT_FOUND);
    s_assert_string_equal(s, vantaq_measurement_result_get_value(s->result), "");
}

static void test_measurement_error_unsupported_claim(void **state) {
    struct MeasurementDomainTestSuite *s = *state;
    vantaq_measurement_model_err_t err   = vantaq_measurement_result_create_error(
        "unknown_claim", "/run/vantaqd/boot_state", MEASUREMENT_UNSUPPORTED_CLAIM, &s->result);

    s_assert_int_equal(s, err, VANTAQ_MEASUREMENT_MODEL_OK);
    s_assert_non_null(s, s->result);
    s_assert_int_equal(s, vantaq_measurement_result_get_status(s->result),
                       VANTAQ_MEASUREMENT_STATUS_ERROR);
    s_assert_int_equal(s, vantaq_measurement_result_get_error_code(s->result),
                       MEASUREMENT_UNSUPPORTED_CLAIM);
}

static void test_measurement_boundary_pass_max_minus_one(void **state) {
    struct MeasurementDomainTestSuite *s = *state;

    char claim[VANTAQ_MEASUREMENT_CLAIM_NAME_MAX];
    char value[VANTAQ_MEASUREMENT_VALUE_MAX];
    char path[VANTAQ_MEASUREMENT_SOURCE_PATH_MAX];

    fill_buffer(claim, VANTAQ_MEASUREMENT_CLAIM_NAME_MAX - 1, 'c');
    fill_buffer(value, VANTAQ_MEASUREMENT_VALUE_MAX - 1, 'v');
    fill_buffer(path, VANTAQ_MEASUREMENT_SOURCE_PATH_MAX - 1, 'p');

    vantaq_measurement_model_err_t err =
        vantaq_measurement_result_create_success(claim, value, path, &s->result);

    s_assert_int_equal(s, err, VANTAQ_MEASUREMENT_MODEL_OK);
    s_assert_non_null(s, s->result);
    s_assert_int_equal(s, strlen(vantaq_measurement_result_get_claim_name(s->result)),
                       VANTAQ_MEASUREMENT_CLAIM_NAME_MAX - 1);
    s_assert_int_equal(s, strlen(vantaq_measurement_result_get_value(s->result)),
                       VANTAQ_MEASUREMENT_VALUE_MAX - 1);
    s_assert_int_equal(s, strlen(vantaq_measurement_result_get_source_path(s->result)),
                       VANTAQ_MEASUREMENT_SOURCE_PATH_MAX - 1);
}

static void test_measurement_boundary_fail_at_max(void **state) {
    struct MeasurementDomainTestSuite *s  = *state;
    struct vantaq_measurement_result *out = NULL;

    char claim[VANTAQ_MEASUREMENT_CLAIM_NAME_MAX + 1];
    char value[VANTAQ_MEASUREMENT_VALUE_MAX + 1];
    char path[VANTAQ_MEASUREMENT_SOURCE_PATH_MAX + 1];

    fill_buffer(claim, VANTAQ_MEASUREMENT_CLAIM_NAME_MAX, 'c');
    fill_buffer(value, VANTAQ_MEASUREMENT_VALUE_MAX, 'v');
    fill_buffer(path, VANTAQ_MEASUREMENT_SOURCE_PATH_MAX, 'p');

    vantaq_measurement_model_err_t err =
        vantaq_measurement_result_create_success(claim, "ok", "ok", &out);
    s_assert_int_equal(s, err, VANTAQ_MEASUREMENT_MODEL_ERR_FIELD_TOO_LONG);
    s_assert_null(s, out);

    err = vantaq_measurement_result_create_success("ok", value, "ok", &out);
    s_assert_int_equal(s, err, VANTAQ_MEASUREMENT_MODEL_ERR_FIELD_TOO_LONG);
    s_assert_null(s, out);

    err = vantaq_measurement_result_create_success("ok", "ok", path, &out);
    s_assert_int_equal(s, err, VANTAQ_MEASUREMENT_MODEL_ERR_FIELD_TOO_LONG);
    s_assert_null(s, out);

    (void)s;
}

static void test_measurement_missing_fields_rejected(void **state) {
    struct MeasurementDomainTestSuite *s  = *state;
    struct vantaq_measurement_result *out = NULL;

    vantaq_measurement_model_err_t err =
        vantaq_measurement_result_create_success(NULL, "value", "/path", &out);
    s_assert_int_equal(s, err, VANTAQ_MEASUREMENT_MODEL_ERR_MISSING_FIELD);
    s_assert_null(s, out);

    err = vantaq_measurement_result_create_success("claim", "", "/path", &out);
    s_assert_int_equal(s, err, VANTAQ_MEASUREMENT_MODEL_ERR_MISSING_FIELD);
    s_assert_null(s, out);

    err = vantaq_measurement_result_create_error("", "/path", MEASUREMENT_READ_FAILED, &out);
    s_assert_int_equal(s, err, VANTAQ_MEASUREMENT_MODEL_ERR_MISSING_FIELD);
    s_assert_null(s, out);

    err = vantaq_measurement_result_create_error("claim", "", MEASUREMENT_READ_FAILED, &out);
    s_assert_int_equal(s, err, VANTAQ_MEASUREMENT_MODEL_ERR_MISSING_FIELD);
    s_assert_null(s, out);
}

static void test_measurement_whitespace_only_fields_rejected(void **state) {
    struct MeasurementDomainTestSuite *s  = *state;
    struct vantaq_measurement_result *out = NULL;

    vantaq_measurement_model_err_t err =
        vantaq_measurement_result_create_success("   ", "value", "/path", &out);
    s_assert_int_equal(s, err, VANTAQ_MEASUREMENT_MODEL_ERR_MISSING_FIELD);
    s_assert_null(s, out);

    err = vantaq_measurement_result_create_success("claim", "\t", "/path", &out);
    s_assert_int_equal(s, err, VANTAQ_MEASUREMENT_MODEL_ERR_MISSING_FIELD);
    s_assert_null(s, out);

    err = vantaq_measurement_result_create_error("claim", "   ", MEASUREMENT_READ_FAILED, &out);
    s_assert_int_equal(s, err, VANTAQ_MEASUREMENT_MODEL_ERR_MISSING_FIELD);
    s_assert_null(s, out);

    (void)s;
}

static void test_measurement_destroy_null_safe(void **state) {
    struct MeasurementDomainTestSuite *s = *state;
    vantaq_measurement_result_destroy(NULL);
    s_assert_true(s, 1);
}

static void test_measurement_accessors_null_safe(void **state) {
    struct MeasurementDomainTestSuite *s = *state;

    s_assert_string_equal(s, vantaq_measurement_result_get_claim_name(NULL), "");
    s_assert_string_equal(s, vantaq_measurement_result_get_value(NULL), "");
    s_assert_string_equal(s, vantaq_measurement_result_get_source_path(NULL), "");
    s_assert_int_equal(s, vantaq_measurement_result_get_status(NULL),
                       VANTAQ_MEASUREMENT_STATUS_ERROR);
    s_assert_int_equal(s, vantaq_measurement_result_get_error_code(NULL), MEASUREMENT_INVALID);
}

static void test_supported_claim_registry(void **state) {
    char too_long[VANTAQ_SUPPORTED_CLAIM_NAME_MAX + 3];

    (void)state;

    assert_true(VANTAQ_CLAIM_NAME_MAX == VANTAQ_SUPPORTED_CLAIM_NAME_MAX);

    assert_true(vantaq_supported_claim_is_known(VANTAQ_CLAIM_BOOT_STATE));
    assert_int_equal(vantaq_supported_claim_lookup(VANTAQ_CLAIM_BOOT_STATE),
                     VANTAQ_SUPPORTED_CLAIM_ID_BOOT_STATE);
    assert_int_equal(vantaq_supported_claim_lookup(VANTAQ_CLAIM_FIRMWARE_HASH),
                     VANTAQ_SUPPORTED_CLAIM_ID_FIRMWARE_HASH);

    assert_false(vantaq_supported_claim_is_known("Firmware_Hash"));
    assert_false(vantaq_supported_claim_is_known(" firmware_hash"));
    assert_false(vantaq_supported_claim_is_known(NULL));
    assert_false(vantaq_supported_claim_is_known(""));
    assert_int_equal(vantaq_supported_claim_lookup("unknown_claim_xyz"),
                     VANTAQ_SUPPORTED_CLAIM_ID_UNKNOWN);

    memset(too_long, 'z', (size_t)VANTAQ_SUPPORTED_CLAIM_NAME_MAX + 1U);
    too_long[VANTAQ_SUPPORTED_CLAIM_NAME_MAX + 1] = '\0';
    assert_false(vantaq_supported_claim_is_known(too_long));
}

static void test_measurement_error_rejects_ok_code(void **state) {
    struct MeasurementDomainTestSuite *s  = *state;
    struct vantaq_measurement_result *out = NULL;

    vantaq_measurement_model_err_t err =
        vantaq_measurement_result_create_error("claim", "/path", MEASUREMENT_OK, &out);
    s_assert_int_equal(s, err, VANTAQ_MEASUREMENT_MODEL_ERR_INVALID_ARG);
    s_assert_null(s, out);

    (void)s;
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_measurement_success_creation, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_measurement_error_source_not_found, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_measurement_error_unsupported_claim, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_measurement_boundary_pass_max_minus_one, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_measurement_boundary_fail_at_max, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_measurement_missing_fields_rejected, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_measurement_whitespace_only_fields_rejected,
                                        suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_measurement_destroy_null_safe, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_measurement_accessors_null_safe, suite_setup,
                                        suite_teardown),
        cmocka_unit_test(test_supported_claim_registry),
        cmocka_unit_test_setup_teardown(test_measurement_error_rejects_ok_code, suite_setup,
                                        suite_teardown),
    };

    return cmocka_run_group_tests_name("measurement_domain_suite", tests, NULL, NULL);
}
