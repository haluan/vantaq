// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/app.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <cmocka.h>

typedef struct test_io_buffer {
    char out[256];
    char err[256];
} test_io_buffer;

static void append_text(char *dst, size_t dst_size, const char *src) {
    size_t used     = strlen(dst);
    size_t incoming = strlen(src);

    if (used >= dst_size - 1) {
        return;
    }

    if (incoming > dst_size - used - 1) {
        incoming = dst_size - used - 1;
    }

    memcpy(dst + used, src, incoming);
    dst[used + incoming] = '\0';
}

static int capture_out(void *ctx, const char *data) {
    test_io_buffer *buffer = (test_io_buffer *)ctx;
    append_text(buffer->out, sizeof(buffer->out), data);
    return 0;
}

static int capture_err(void *ctx, const char *data) {
    test_io_buffer *buffer = (test_io_buffer *)ctx;
    append_text(buffer->err, sizeof(buffer->err), data);
    return 0;
}

static int setup(void **state) {
    static test_io_buffer buffer;
    memset(&buffer, 0, sizeof(buffer));
    *state = &buffer;
    return 0;
}

static void test_version_flag_prints_version(void **state) {
    test_io_buffer *buffer  = (test_io_buffer *)*state;
    char *argv[]            = {"vantaqd", "--version"};
    struct vantaq_app_io io = {
        .write_out = capture_out,
        .write_err = capture_err,
        .ctx       = buffer,
    };

    int rc = vantaq_app_run(2, argv, &io);

    assert_int_equal(rc, 0);
    assert_string_equal(buffer->out, "vantaqd 0.1.0\n");
    assert_string_equal(buffer->err, "");
}

static void test_unknown_argument_returns_usage_error(void **state) {
    test_io_buffer *buffer  = (test_io_buffer *)*state;
    char *argv[]            = {"vantaqd", "--bad-flag"};
    struct vantaq_app_io io = {
        .write_out = capture_out,
        .write_err = capture_err,
        .ctx       = buffer,
    };

    int rc = vantaq_app_run(2, argv, &io);

    assert_int_equal(rc, 64);
    assert_string_equal(buffer->out, "");
    assert_string_equal(buffer->err, "Usage: vantaqd [--version] [--config <path>]\n");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_version_flag_prints_version, setup),
        cmocka_unit_test_setup(test_unknown_argument_returns_usage_error, setup),
    };

    return cmocka_run_group_tests_name("unit_app_cli", tests, NULL, NULL);
}
