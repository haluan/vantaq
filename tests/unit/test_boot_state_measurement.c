// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "domain/measurement/measurement.h"
#include "infrastructure/config_loader.h"
#include "infrastructure/config_loader_internal.h"
#include "infrastructure/linux_measurement/boot_state.h"
#include "infrastructure/memory/zero_struct.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>

struct BootStateMeasurementTestSuite {
    char boot_state_path[256];
};

#define s_assert_int_equal(s, a, b) assert_int_equal(a, b)
#define s_assert_non_null(s, a) assert_non_null(a)
#define s_assert_string_equal(s, a, b) assert_string_equal(a, b)
#define s_assert_true(s, a) assert_true(a)
#define s_assert_null(s, a) assert_null(a)

static int suite_setup(void **state) {
    struct BootStateMeasurementTestSuite *s =
        calloc(1, sizeof(struct BootStateMeasurementTestSuite));
    if (!s) {
        return -1;
    }

    snprintf(s->boot_state_path, sizeof(s->boot_state_path), "/tmp/vantaq_boot_state_%d.txt",
             getpid());
    *state = s;
    return 0;
}

static int suite_teardown(void **state) {
    struct BootStateMeasurementTestSuite *s = *state;
    unlink(s->boot_state_path);
    free(s);
    return 0;
}

static int write_file(const char *path, const unsigned char *data, size_t len) {
    FILE *fp = fopen(path, "wb");
    if (fp == NULL) {
        return -1;
    }
    if (len > 0 && fwrite(data, 1, len, fp) != len) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

static void fill_measurement_config(struct vantaq_runtime_config *config,
                                    const char *boot_state_path, size_t max_file_bytes) {
    VANTAQ_ZERO_STRUCT(*config);
    config->cbSize = sizeof(*config);
    strncpy(config->measurement_firmware_path, "/opt/vantaqd/firmware/current.bin",
            sizeof(config->measurement_firmware_path) - 1);
    strncpy(config->measurement_security_config_path, "/etc/vantaqd/security.conf",
            sizeof(config->measurement_security_config_path) - 1);
    strncpy(config->measurement_agent_binary_path, "/usr/local/bin/vantaqd",
            sizeof(config->measurement_agent_binary_path) - 1);
    strncpy(config->measurement_boot_state_path, boot_state_path,
            sizeof(config->measurement_boot_state_path) - 1);
    config->measurement_max_file_bytes = max_file_bytes;
}

static void test_boot_state_success(void **state) {
    struct BootStateMeasurementTestSuite *s = *state;
    struct vantaq_runtime_config config;
    struct vantaq_measurement_result *result = NULL;
    const unsigned char content[]            = "boot_mode=normal\n"
                                               "secure_boot=mock_enabled\n"
                                               "rollback_detected=false\n";

    assert_int_equal(write_file(s->boot_state_path, content, sizeof(content) - 1), 0);
    fill_measurement_config(&config, s->boot_state_path, 1024);

    enum vantaq_boot_state_status status = vantaq_boot_state_measure(&config, &result);

    s_assert_int_equal(s, status, VANTAQ_BOOT_STATE_OK);
    s_assert_non_null(s, result);
    s_assert_int_equal(s, vantaq_measurement_result_get_status(result),
                       VANTAQ_MEASUREMENT_STATUS_SUCCESS);
    s_assert_int_equal(s, vantaq_measurement_result_get_error_code(result), MEASUREMENT_OK);
    s_assert_string_equal(s, vantaq_measurement_result_get_claim_name(result), "boot_state");
    s_assert_string_equal(s, vantaq_measurement_result_get_source_path(result), s->boot_state_path);
    s_assert_string_equal(s, vantaq_measurement_result_get_value(result),
                          "secure_boot=mock_enabled;boot_mode=normal;rollback_detected=false");

    vantaq_measurement_result_destroy(result);
}

static void test_boot_state_unknown_keys_rejected(void **state) {
    struct BootStateMeasurementTestSuite *s = *state;
    struct vantaq_runtime_config config;
    struct vantaq_measurement_result *result = NULL;
    const unsigned char content[]            = "secure_boot=enabled\n"
                                               "extra=foo\n"
                                               "boot_mode=recovery\n";

    assert_int_equal(write_file(s->boot_state_path, content, sizeof(content) - 1), 0);
    fill_measurement_config(&config, s->boot_state_path, 1024);

    enum vantaq_boot_state_status status = vantaq_boot_state_measure(&config, &result);

    s_assert_int_equal(s, status, VANTAQ_BOOT_STATE_ERR_PARSE_FAILED);
    s_assert_non_null(s, result);
    s_assert_int_equal(s, vantaq_measurement_result_get_error_code(result),
                       MEASUREMENT_PARSE_FAILED);

    vantaq_measurement_result_destroy(result);
}

static void test_boot_state_duplicate_key_rejected(void **state) {
    struct BootStateMeasurementTestSuite *s = *state;
    struct vantaq_runtime_config config;
    struct vantaq_measurement_result *result = NULL;
    const unsigned char content[]            = "secure_boot=enabled\n"
                                               "secure_boot=disabled\n"
                                               "boot_mode=normal\n";

    assert_int_equal(write_file(s->boot_state_path, content, sizeof(content) - 1), 0);
    fill_measurement_config(&config, s->boot_state_path, 1024);

    enum vantaq_boot_state_status status = vantaq_boot_state_measure(&config, &result);

    s_assert_int_equal(s, status, VANTAQ_BOOT_STATE_ERR_PARSE_FAILED);
    s_assert_non_null(s, result);
    s_assert_int_equal(s, vantaq_measurement_result_get_error_code(result),
                       MEASUREMENT_PARSE_FAILED);

    vantaq_measurement_result_destroy(result);
}

static void test_boot_state_empty_rollback_value_rejected(void **state) {
    struct BootStateMeasurementTestSuite *s = *state;
    struct vantaq_runtime_config config;
    struct vantaq_measurement_result *result = NULL;
    const unsigned char content[]            = "secure_boot=enabled\n"
                                               "boot_mode=normal\n"
                                               "rollback_detected=\n";

    assert_int_equal(write_file(s->boot_state_path, content, sizeof(content) - 1), 0);
    fill_measurement_config(&config, s->boot_state_path, 1024);

    enum vantaq_boot_state_status status = vantaq_boot_state_measure(&config, &result);

    s_assert_int_equal(s, status, VANTAQ_BOOT_STATE_ERR_PARSE_FAILED);
    s_assert_non_null(s, result);
    s_assert_int_equal(s, vantaq_measurement_result_get_error_code(result),
                       MEASUREMENT_PARSE_FAILED);

    vantaq_measurement_result_destroy(result);
}

static void test_boot_state_missing_source(void **state) {
    struct BootStateMeasurementTestSuite *s = *state;
    struct vantaq_runtime_config config;
    struct vantaq_measurement_result *result = NULL;

    unlink(s->boot_state_path);
    fill_measurement_config(&config, s->boot_state_path, 1024);

    enum vantaq_boot_state_status status = vantaq_boot_state_measure(&config, &result);

    s_assert_int_equal(s, status, VANTAQ_BOOT_STATE_ERR_SOURCE_NOT_FOUND);
    s_assert_non_null(s, result);
    s_assert_int_equal(s, vantaq_measurement_result_get_status(result),
                       VANTAQ_MEASUREMENT_STATUS_ERROR);
    s_assert_int_equal(s, vantaq_measurement_result_get_error_code(result),
                       MEASUREMENT_SOURCE_NOT_FOUND);

    vantaq_measurement_result_destroy(result);
}

static void test_boot_state_malformed_line(void **state) {
    struct BootStateMeasurementTestSuite *s = *state;
    struct vantaq_runtime_config config;
    struct vantaq_measurement_result *result = NULL;
    const unsigned char content[]            = "secure_boot=enabled\n"
                                               "boot_mode\n";

    assert_int_equal(write_file(s->boot_state_path, content, sizeof(content) - 1), 0);
    fill_measurement_config(&config, s->boot_state_path, 1024);

    enum vantaq_boot_state_status status = vantaq_boot_state_measure(&config, &result);

    s_assert_int_equal(s, status, VANTAQ_BOOT_STATE_ERR_PARSE_FAILED);
    s_assert_non_null(s, result);
    s_assert_int_equal(s, vantaq_measurement_result_get_error_code(result),
                       MEASUREMENT_PARSE_FAILED);

    vantaq_measurement_result_destroy(result);
}

static void test_boot_state_missing_required_keys(void **state) {
    struct BootStateMeasurementTestSuite *s = *state;
    struct vantaq_runtime_config config;
    struct vantaq_measurement_result *result = NULL;
    const unsigned char content[]            = "secure_boot=enabled\n";

    assert_int_equal(write_file(s->boot_state_path, content, sizeof(content) - 1), 0);
    fill_measurement_config(&config, s->boot_state_path, 1024);

    enum vantaq_boot_state_status status = vantaq_boot_state_measure(&config, &result);

    s_assert_int_equal(s, status, VANTAQ_BOOT_STATE_ERR_PARSE_FAILED);
    s_assert_non_null(s, result);
    s_assert_int_equal(s, vantaq_measurement_result_get_error_code(result),
                       MEASUREMENT_PARSE_FAILED);

    vantaq_measurement_result_destroy(result);
}

static void test_boot_state_deterministic_output(void **state) {
    struct BootStateMeasurementTestSuite *s = *state;
    struct vantaq_runtime_config config;
    struct vantaq_measurement_result *result1 = NULL;
    struct vantaq_measurement_result *result2 = NULL;
    const unsigned char content[]             = "secure_boot=enabled\n"
                                                "boot_mode=normal\n"
                                                "rollback_detected=false\n";

    fill_measurement_config(&config, s->boot_state_path, 1024);
    assert_int_equal(write_file(s->boot_state_path, content, sizeof(content) - 1), 0);

    s_assert_int_equal(s, vantaq_boot_state_measure(&config, &result1), VANTAQ_BOOT_STATE_OK);
    s_assert_int_equal(s, vantaq_boot_state_measure(&config, &result2), VANTAQ_BOOT_STATE_OK);
    s_assert_string_equal(s, vantaq_measurement_result_get_value(result1),
                          vantaq_measurement_result_get_value(result2));

    vantaq_measurement_result_destroy(result1);
    vantaq_measurement_result_destroy(result2);
}

static void test_boot_state_invalid_args(void **state) {
    struct BootStateMeasurementTestSuite *s = *state;
    struct vantaq_runtime_config config;
    struct vantaq_measurement_result *result = NULL;

    s_assert_int_equal(s, vantaq_boot_state_measure(NULL, &result),
                       VANTAQ_BOOT_STATE_ERR_INVALID_ARG);
    s_assert_int_equal(s, vantaq_boot_state_measure(&config, NULL),
                       VANTAQ_BOOT_STATE_ERR_INVALID_ARG);

    fill_measurement_config(&config, "", 1024);
    s_assert_int_equal(s, vantaq_boot_state_measure(&config, &result),
                       VANTAQ_BOOT_STATE_ERR_INVALID_ARG);
    s_assert_null(s, result);

    fill_measurement_config(&config, s->boot_state_path, 0);
    s_assert_int_equal(s, vantaq_boot_state_measure(&config, &result),
                       VANTAQ_BOOT_STATE_ERR_INVALID_ARG);
    s_assert_null(s, result);
}

static void test_boot_state_file_too_large(void **state) {
    struct BootStateMeasurementTestSuite *s = *state;
    struct vantaq_runtime_config config;
    struct vantaq_measurement_result *result = NULL;
    const unsigned char content[]            = "secure_boot=enabled\nboot_mode=normal\n";

    assert_int_equal(write_file(s->boot_state_path, content, sizeof(content) - 1), 0);
    fill_measurement_config(&config, s->boot_state_path, 4);

    enum vantaq_boot_state_status status = vantaq_boot_state_measure(&config, &result);

    s_assert_int_equal(s, status, VANTAQ_BOOT_STATE_ERR_FILE_TOO_LARGE);
    s_assert_non_null(s, result);
    s_assert_int_equal(s, vantaq_measurement_result_get_error_code(result),
                       MEASUREMENT_READ_FAILED);

    vantaq_measurement_result_destroy(result);
}

static void test_boot_state_rejects_delimiter_injection(void **state) {
    struct BootStateMeasurementTestSuite *s = *state;
    struct vantaq_runtime_config config;
    struct vantaq_measurement_result *result = NULL;
    const unsigned char content[]            = "secure_boot=enabled;injected=true\n"
                                               "boot_mode=normal\n";

    assert_int_equal(write_file(s->boot_state_path, content, sizeof(content) - 1), 0);
    fill_measurement_config(&config, s->boot_state_path, 1024);

    enum vantaq_boot_state_status status = vantaq_boot_state_measure(&config, &result);

    s_assert_int_equal(s, status, VANTAQ_BOOT_STATE_ERR_PARSE_FAILED);
    s_assert_non_null(s, result);
    s_assert_int_equal(s, vantaq_measurement_result_get_error_code(result),
                       MEASUREMENT_PARSE_FAILED);

    vantaq_measurement_result_destroy(result);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_boot_state_success, suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_boot_state_unknown_keys_rejected, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_boot_state_duplicate_key_rejected, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_boot_state_empty_rollback_value_rejected, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_boot_state_missing_source, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_boot_state_malformed_line, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_boot_state_missing_required_keys, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_boot_state_deterministic_output, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_boot_state_invalid_args, suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_boot_state_file_too_large, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_boot_state_rejects_delimiter_injection, suite_setup,
                                        suite_teardown),
    };

    return cmocka_run_group_tests_name("boot_state_measurement_suite", tests, NULL, NULL);
}
