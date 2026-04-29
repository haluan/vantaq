// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "domain/measurement/measurement.h"
#include "infrastructure/config_loader.h"
#include "infrastructure/config_loader_internal.h"
#include "infrastructure/linux_measurement/config_hash.h"
#include "infrastructure/memory/zero_struct.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>

struct ConfigHashMeasurementTestSuite {
    char config_path[256];
};

#define s_assert_int_equal(s, a, b) assert_int_equal(a, b)
#define s_assert_non_null(s, a) assert_non_null(a)
#define s_assert_string_equal(s, a, b) assert_string_equal(a, b)
#define s_assert_true(s, a) assert_true(a)
#define s_assert_null(s, a) assert_null(a)

static int suite_setup(void **state) {
    struct ConfigHashMeasurementTestSuite *s =
        calloc(1, sizeof(struct ConfigHashMeasurementTestSuite));
    if (!s) {
        return -1;
    }

    snprintf(s->config_path, sizeof(s->config_path), "/tmp/vantaq_security_conf_%d.bin", getpid());
    *state = s;
    return 0;
}

static int suite_teardown(void **state) {
    struct ConfigHashMeasurementTestSuite *s = *state;
    unlink(s->config_path);
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

static void fill_measurement_config(struct vantaq_runtime_config *config, const char *config_path,
                                    size_t max_file_bytes) {
    VANTAQ_ZERO_STRUCT(*config);
    config->cbSize = sizeof(*config);
    strncpy(config->measurement_firmware_path, "/opt/vantaqd/firmware/current.bin",
            sizeof(config->measurement_firmware_path) - 1);
    strncpy(config->measurement_security_config_path, config_path,
            sizeof(config->measurement_security_config_path) - 1);
    strncpy(config->measurement_agent_binary_path, "/usr/local/bin/vantaqd",
            sizeof(config->measurement_agent_binary_path) - 1);
    strncpy(config->measurement_boot_state_path, "/run/vantaqd/boot_state",
            sizeof(config->measurement_boot_state_path) - 1);
    config->measurement_max_file_bytes = max_file_bytes;
}

static void test_config_hash_success(void **state) {
    struct ConfigHashMeasurementTestSuite *s = *state;
    struct vantaq_runtime_config config;
    struct vantaq_measurement_result *result = NULL;
    const unsigned char content[]            = "allow_tls=true\\nmode=strict\\n";

    assert_int_equal(write_file(s->config_path, content, sizeof(content) - 1), 0);
    fill_measurement_config(&config, s->config_path, 1024);

    enum vantaq_config_hash_status status = vantaq_config_hash_measure(&config, &result);

    s_assert_int_equal(s, status, VANTAQ_CONFIG_HASH_OK);
    s_assert_non_null(s, result);
    s_assert_int_equal(s, vantaq_measurement_result_get_status(result),
                       VANTAQ_MEASUREMENT_STATUS_SUCCESS);
    s_assert_int_equal(s, vantaq_measurement_result_get_error_code(result), MEASUREMENT_OK);
    s_assert_string_equal(s, vantaq_measurement_result_get_claim_name(result), "config_hash");
    s_assert_string_equal(s, vantaq_measurement_result_get_source_path(result), s->config_path);
    s_assert_true(s, strncmp(vantaq_measurement_result_get_value(result), "sha256:", 7) == 0);
    s_assert_int_equal(s, strlen(vantaq_measurement_result_get_value(result)), 71);

    vantaq_measurement_result_destroy(result);
}

static void test_config_hash_missing_source(void **state) {
    struct ConfigHashMeasurementTestSuite *s = *state;
    struct vantaq_runtime_config config;
    struct vantaq_measurement_result *result = NULL;

    unlink(s->config_path);
    fill_measurement_config(&config, s->config_path, 1024);

    enum vantaq_config_hash_status status = vantaq_config_hash_measure(&config, &result);

    s_assert_int_equal(s, status, VANTAQ_CONFIG_HASH_ERR_SOURCE_NOT_FOUND);
    s_assert_non_null(s, result);
    s_assert_int_equal(s, vantaq_measurement_result_get_status(result),
                       VANTAQ_MEASUREMENT_STATUS_ERROR);
    s_assert_int_equal(s, vantaq_measurement_result_get_error_code(result),
                       MEASUREMENT_SOURCE_NOT_FOUND);

    vantaq_measurement_result_destroy(result);
}

static void test_config_hash_deterministic_and_changes(void **state) {
    struct ConfigHashMeasurementTestSuite *s = *state;
    struct vantaq_runtime_config config;
    struct vantaq_measurement_result *result1 = NULL;
    struct vantaq_measurement_result *result2 = NULL;
    struct vantaq_measurement_result *result3 = NULL;
    const unsigned char content_a[]           = "k=v\\n";
    const unsigned char content_b[]           = "k=v2\\n";

    fill_measurement_config(&config, s->config_path, 1024);

    assert_int_equal(write_file(s->config_path, content_a, sizeof(content_a) - 1), 0);
    s_assert_int_equal(s, vantaq_config_hash_measure(&config, &result1), VANTAQ_CONFIG_HASH_OK);
    s_assert_int_equal(s, vantaq_config_hash_measure(&config, &result2), VANTAQ_CONFIG_HASH_OK);
    s_assert_string_equal(s, vantaq_measurement_result_get_value(result1),
                          vantaq_measurement_result_get_value(result2));

    assert_int_equal(write_file(s->config_path, content_b, sizeof(content_b) - 1), 0);
    s_assert_int_equal(s, vantaq_config_hash_measure(&config, &result3), VANTAQ_CONFIG_HASH_OK);
    s_assert_true(s, strcmp(vantaq_measurement_result_get_value(result1),
                            vantaq_measurement_result_get_value(result3)) != 0);

    vantaq_measurement_result_destroy(result1);
    vantaq_measurement_result_destroy(result2);
    vantaq_measurement_result_destroy(result3);
}

static void test_config_hash_rejects_proc_and_sys_paths(void **state) {
    struct ConfigHashMeasurementTestSuite *s = *state;
    struct vantaq_runtime_config config;
    struct vantaq_measurement_result *result = NULL;

    fill_measurement_config(&config, "/proc/cpuinfo", 1024);
    s_assert_int_equal(s, vantaq_config_hash_measure(&config, &result),
                       VANTAQ_CONFIG_HASH_ERR_INVALID_ARG);
    s_assert_null(s, result);

    fill_measurement_config(&config, "/sys/class/net/lo/address", 1024);
    s_assert_int_equal(s, vantaq_config_hash_measure(&config, &result),
                       VANTAQ_CONFIG_HASH_ERR_INVALID_ARG);
    s_assert_null(s, result);
}

static void test_config_hash_invalid_args(void **state) {
    struct ConfigHashMeasurementTestSuite *s = *state;
    struct vantaq_runtime_config config;
    struct vantaq_measurement_result *result = NULL;

    s_assert_int_equal(s, vantaq_config_hash_measure(NULL, &result),
                       VANTAQ_CONFIG_HASH_ERR_INVALID_ARG);
    s_assert_int_equal(s, vantaq_config_hash_measure(&config, NULL),
                       VANTAQ_CONFIG_HASH_ERR_INVALID_ARG);

    fill_measurement_config(&config, "", 1024);
    s_assert_int_equal(s, vantaq_config_hash_measure(&config, &result),
                       VANTAQ_CONFIG_HASH_ERR_INVALID_ARG);
    s_assert_null(s, result);

    fill_measurement_config(&config, s->config_path, 0);
    s_assert_int_equal(s, vantaq_config_hash_measure(&config, &result),
                       VANTAQ_CONFIG_HASH_ERR_INVALID_ARG);
    s_assert_null(s, result);
}

static void test_config_hash_file_too_large(void **state) {
    struct ConfigHashMeasurementTestSuite *s = *state;
    struct vantaq_runtime_config config;
    struct vantaq_measurement_result *result = NULL;
    const unsigned char content[]            = "0123456789abcdef";

    assert_int_equal(write_file(s->config_path, content, sizeof(content) - 1), 0);
    fill_measurement_config(&config, s->config_path, 4);

    enum vantaq_config_hash_status status = vantaq_config_hash_measure(&config, &result);

    s_assert_int_equal(s, status, VANTAQ_CONFIG_HASH_ERR_FILE_TOO_LARGE);
    s_assert_non_null(s, result);
    s_assert_int_equal(s, vantaq_measurement_result_get_status(result),
                       VANTAQ_MEASUREMENT_STATUS_ERROR);
    s_assert_int_equal(s, vantaq_measurement_result_get_error_code(result),
                       MEASUREMENT_READ_FAILED);

    vantaq_measurement_result_destroy(result);
}

static void test_config_hash_empty_file_rejected(void **state) {
    struct ConfigHashMeasurementTestSuite *s = *state;
    struct vantaq_runtime_config config;
    struct vantaq_measurement_result *result = NULL;

    assert_int_equal(write_file(s->config_path, (const unsigned char *)"", 0), 0);
    fill_measurement_config(&config, s->config_path, 1024);

    enum vantaq_config_hash_status status = vantaq_config_hash_measure(&config, &result);

    s_assert_int_equal(s, status, VANTAQ_CONFIG_HASH_ERR_READ_FAILED);
    s_assert_non_null(s, result);
    s_assert_int_equal(s, vantaq_measurement_result_get_status(result),
                       VANTAQ_MEASUREMENT_STATUS_ERROR);
    s_assert_int_equal(s, vantaq_measurement_result_get_error_code(result),
                       MEASUREMENT_READ_FAILED);

    vantaq_measurement_result_destroy(result);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_config_hash_success, suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_config_hash_missing_source, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_config_hash_deterministic_and_changes, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_config_hash_rejects_proc_and_sys_paths, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_config_hash_invalid_args, suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_config_hash_file_too_large, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_config_hash_empty_file_rejected, suite_setup,
                                        suite_teardown),
    };

    return cmocka_run_group_tests_name("config_hash_measurement_suite", tests, NULL, NULL);
}
