// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#include <cmocka.h>

static void test_binary_starts_with_default_path(void **state) {
    (void)state;
    int status =
        system("./bin/vantaqd --config ./config/device-1/vantaqd.yaml >/dev/null 2>/dev/null");

    assert_true(WIFEXITED(status));
    assert_int_equal(WEXITSTATUS(status), 0);
}

static void test_binary_rejects_unknown_argument(void **state) {
    (void)state;
    int status = system("./bin/vantaqd --bad-flag >/dev/null 2>/dev/null");

    assert_true(WIFEXITED(status));
    assert_int_equal(WEXITSTATUS(status), 64);
}

static void test_version_output_shape(void **state) {
    (void)state;
    FILE *pipe   = popen("./bin/vantaqd --version", "r");
    char buf[64] = {0};
    int status;

    assert_non_null(pipe);
    assert_non_null(fgets(buf, sizeof(buf), pipe));

    status = pclose(pipe);

    assert_true(WIFEXITED(status));
    assert_int_equal(WEXITSTATUS(status), 0);
    assert_string_equal(buf, "vantaqd 0.1.0\n");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_binary_starts_with_default_path),
        cmocka_unit_test(test_binary_rejects_unknown_argument),
        cmocka_unit_test(test_version_output_shape),
    };

    return cmocka_run_group_tests_name("integration_cli_smoke", tests, NULL, NULL);
}
