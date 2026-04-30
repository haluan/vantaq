// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "domain/ring_buffer/ring_buffer.h"

static void test_config_enforces_upper_bound(void **state) {
    (void)state;
    struct vantaq_ring_buffer_config *config = NULL;

    // Test limit + 1
    ring_buffer_err_t err = vantaq_ring_buffer_config_create(
        "/tmp/test.ring", 4, VANTAQ_RING_BUFFER_MAX_RECORD_BYTES_LIMIT + 1, true, &config);
    assert_int_equal(err, RING_BUFFER_INVALID_CONFIG);
    assert_null(config);

    // Test exactly limit
    err = vantaq_ring_buffer_config_create(
        "/tmp/test.ring", 4, VANTAQ_RING_BUFFER_MAX_RECORD_BYTES_LIMIT, true, &config);
    assert_int_equal(err, RING_BUFFER_OK);
    assert_non_null(config);
    vantaq_ring_buffer_config_destroy(config);
}

static void test_record_create_enforces_issued_at_positive(void **state) {
    (void)state;
    struct vantaq_ring_buffer_config *config = NULL;
    struct vantaq_ring_buffer_record *record = NULL;

    vantaq_ring_buffer_config_create("/tmp/test.ring", 4, 1024, true, &config);

    // Test issued_at = 0
    ring_buffer_err_t err = vantaq_ring_buffer_record_create(config, 0, 0, "ev-1", "ver-1", 0, "{}",
                                                             "hash", "chk", &record);
    assert_int_equal(err, RING_BUFFER_INVALID_CONFIG);

    // Test issued_at = -1
    err = vantaq_ring_buffer_record_create(config, 0, 0, "ev-1", "ver-1", -1, "{}", "hash", "chk",
                                           &record);
    assert_int_equal(err, RING_BUFFER_INVALID_CONFIG);

    vantaq_ring_buffer_config_destroy(config);
}

static void test_error_results_use_invalid_sentinels(void **state) {
    (void)state;
    struct vantaq_ring_buffer_append_result *append_res = NULL;
    struct vantaq_ring_buffer_read_result *read_res     = NULL;

    // Append error
    vantaq_ring_buffer_append_result_create_error(RING_BUFFER_IO_ERROR, &append_res);
    assert_int_equal(vantaq_ring_buffer_append_result_get_record_slot(append_res),
                     VANTAQ_RING_BUFFER_INVALID_SLOT);
    assert_int_equal(vantaq_ring_buffer_append_result_get_record_sequence(append_res),
                     VANTAQ_RING_BUFFER_INVALID_SEQUENCE);
    vantaq_ring_buffer_append_result_destroy(append_res);

    // Read error
    vantaq_ring_buffer_read_result_create_error(RING_BUFFER_RECORD_NOT_FOUND, &read_res);
    assert_int_equal(vantaq_ring_buffer_read_result_get_record_slot(read_res),
                     VANTAQ_RING_BUFFER_INVALID_SLOT);
    assert_int_equal(vantaq_ring_buffer_read_result_get_record_sequence(read_res),
                     VANTAQ_RING_BUFFER_INVALID_SEQUENCE);
    vantaq_ring_buffer_read_result_destroy(read_res);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_config_enforces_upper_bound),
        cmocka_unit_test(test_record_create_enforces_issued_at_positive),
        cmocka_unit_test(test_error_results_use_invalid_sentinels),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
