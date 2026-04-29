// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "json_utils.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>

#include <cmocka.h>

static void test_escape_control_chars_with_u00xx(void **state) {
    char src[] = {'A', (char)0x1F, 'B', '\0'};
    char dst[32];
    size_t written = vantaq_json_escape_str(src, dst, sizeof(dst));

    assert_true(written > 0);
    assert_string_equal(dst, "A\\u001fB");
    (void)state;
}

static void test_extract_str_unescapes_uXXXX(void **state) {
    const char *json = "{\"k\":\"A\\u001fB\"}";
    char out[16];

    assert_true(vantaq_json_extract_str(json, "k", out, sizeof(out)));
    assert_int_equal((unsigned char)out[0], 'A');
    assert_int_equal((unsigned char)out[1], 0x1F);
    assert_int_equal((unsigned char)out[2], 'B');
    assert_int_equal((unsigned char)out[3], '\0');
    (void)state;
}

static void test_extract_str_handles_escaped_quote_in_other_key(void **state) {
    const char *json = "{\"ke\\\"y\":\"v1\",\"target\":\"ok\"}";
    char out[16];

    assert_true(vantaq_json_extract_str(json, "target", out, sizeof(out)));
    assert_string_equal(out, "ok");
    (void)state;
}

static void test_extract_str_array_allows_empty_items(void **state) {
    const char *json = "{\"items\":[\"a\",\"\",\"b\"]}";
    char items[3][8];
    size_t count = 0;
    bool present = false;

    memset(items, 0, sizeof(items));
    assert_true(vantaq_json_extract_str_array(json, "items", (char *)items, sizeof(items[0]), 3,
                                              &count, &present));
    assert_true(present);
    assert_int_equal(count, 3);
    assert_string_equal(items[0], "a");
    assert_string_equal(items[1], "");
    assert_string_equal(items[2], "b");
    (void)state;
}

static void test_extract_str_rejects_malformed_escape(void **state) {
    const char *json = "{\"k\":\"bad\\x\"}";
    char out[16];

    assert_false(vantaq_json_extract_str(json, "k", out, sizeof(out)));
    (void)state;
}

static void test_extract_str_rejects_malformed_u_escape(void **state) {
    const char *json = "{\"k\":\"bad\\u12xz\"}";
    char out[16];

    assert_false(vantaq_json_extract_str(json, "k", out, sizeof(out)));
    (void)state;
}

static void test_extract_nested_object_does_not_shadow_top_level_key(void **state) {
    const char *json = "{\"meta\": {\"id\": \"inner\"}, \"id\": \"outer\"}";
    char out[16];

    assert_true(vantaq_json_extract_str(json, "id", out, sizeof(out)));
    assert_string_equal(out, "outer");
    (void)state;
}

static void test_extract_str_status_not_found_vs_ok(void **state) {
    const char *json = "{\"a\":\"x\"}";
    char out[16];

    assert_int_equal(vantaq_json_extract_str_status(json, "missing", out, sizeof(out)),
                     VANTAQ_JSON_EXTRACT_NOT_FOUND);
    assert_int_equal(vantaq_json_extract_str_status(json, "a", out, sizeof(out)),
                     VANTAQ_JSON_EXTRACT_OK);
    assert_string_equal(out, "x");
    (void)state;
}

static void test_extract_str_status_buffer_too_small(void **state) {
    const char *json = "{\"k\":\"hello\"}";
    char out[3];

    assert_int_equal(vantaq_json_extract_str_status(json, "k", out, sizeof(out)),
                     VANTAQ_JSON_EXTRACT_BUFFER_TOO_SMALL);
    (void)state;
}

static void test_escape_str_status_truncated(void **state) {
    const char *src = "hello";
    char dst[4];
    size_t w = 0;

    assert_int_equal(vantaq_json_escape_str_status(src, dst, sizeof(dst), &w),
                     VANTAQ_JSON_ESCAPE_TRUNCATED);
    assert_true(w < strlen(src));
    (void)state;
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_escape_control_chars_with_u00xx),
        cmocka_unit_test(test_extract_str_unescapes_uXXXX),
        cmocka_unit_test(test_extract_str_handles_escaped_quote_in_other_key),
        cmocka_unit_test(test_extract_str_array_allows_empty_items),
        cmocka_unit_test(test_extract_str_rejects_malformed_escape),
        cmocka_unit_test(test_extract_str_rejects_malformed_u_escape),
        cmocka_unit_test(test_extract_nested_object_does_not_shadow_top_level_key),
        cmocka_unit_test(test_extract_str_status_not_found_vs_ok),
        cmocka_unit_test(test_extract_str_status_buffer_too_small),
        cmocka_unit_test(test_escape_str_status_truncated),
    };

    return cmocka_run_group_tests_name("json_utils_suite", tests, NULL, NULL);
}
