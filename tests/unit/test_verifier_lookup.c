// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/security/verifier_lookup.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

// Suite Pattern: Struct to hold test state
struct VerifierLookupTestSuite {
    struct vantaq_runtime_config config;
};

// Assert Pattern: s_assert_xyz style macros
#define s_assert_int_equal(s, a, b) assert_int_equal(a, b)

static int suite_setup(void **state) {
    struct VerifierLookupTestSuite *s = calloc(1, sizeof(struct VerifierLookupTestSuite));
    if (!s)
        return -1;
    s->config.cbSize = sizeof(struct vantaq_runtime_config);
    *state           = s;
    return 0;
}

static int suite_teardown(void **state) {
    struct VerifierLookupTestSuite *s = *state;
    free(s);
    return 0;
}

static void test_lookup_active(void **state) {
    struct VerifierLookupTestSuite *s = *state;
    s->config.verifiers_count         = 1;
    strncpy(s->config.verifiers[0].verifier_id, "v-001", VANTAQ_MAX_FIELD_LEN - 1);
    strncpy(s->config.verifiers[0].status, VANTAQ_VERIFIER_STATUS_STR_ACTIVE,
            VANTAQ_MAX_FIELD_LEN - 1);

    enum vantaq_verifier_status_code status = vantaq_verifier_lookup_status(&s->config, "v-001");
    s_assert_int_equal(s, status, VANTAQ_VERIFIER_STATUS_ACTIVE);
}

static void test_lookup_inactive(void **state) {
    struct VerifierLookupTestSuite *s = *state;
    s->config.verifiers_count         = 1;
    strncpy(s->config.verifiers[0].verifier_id, "v-002", VANTAQ_MAX_FIELD_LEN - 1);
    strncpy(s->config.verifiers[0].status, VANTAQ_VERIFIER_STATUS_STR_INACTIVE,
            VANTAQ_MAX_FIELD_LEN - 1);

    enum vantaq_verifier_status_code status = vantaq_verifier_lookup_status(&s->config, "v-002");
    s_assert_int_equal(s, status, VANTAQ_VERIFIER_STATUS_INACTIVE);
}

static void test_lookup_not_found(void **state) {
    struct VerifierLookupTestSuite *s = *state;
    s->config.verifiers_count         = 1;
    strncpy(s->config.verifiers[0].verifier_id, "v-001", VANTAQ_MAX_FIELD_LEN - 1);

    enum vantaq_verifier_status_code status = vantaq_verifier_lookup_status(&s->config, "v-999");
    s_assert_int_equal(s, status, VANTAQ_VERIFIER_STATUS_NOT_FOUND);
}

static void test_lookup_misconfigured_status(void **state) {
    struct VerifierLookupTestSuite *s = *state;
    s->config.verifiers_count         = 1;
    strncpy(s->config.verifiers[0].verifier_id, "v-003", VANTAQ_MAX_FIELD_LEN - 1);
    strncpy(s->config.verifiers[0].status, "invalid-status", VANTAQ_MAX_FIELD_LEN - 1);

    enum vantaq_verifier_status_code status = vantaq_verifier_lookup_status(&s->config, "v-003");
    s_assert_int_equal(s, status, VANTAQ_VERIFIER_STATUS_MISCONFIGURED);
}

static void test_lookup_invalid_args(void **state) {
    struct VerifierLookupTestSuite *s = *state;

    /* NULL config */
    s_assert_int_equal(s, vantaq_verifier_lookup_status(NULL, "v-001"),
                       VANTAQ_VERIFIER_STATUS_INVALID_ARGUMENT);

    /* NULL ID */
    s_assert_int_equal(s, vantaq_verifier_lookup_status(&s->config, NULL),
                       VANTAQ_VERIFIER_STATUS_INVALID_ARGUMENT);

    /* Empty ID */
    s_assert_int_equal(s, vantaq_verifier_lookup_status(&s->config, ""),
                       VANTAQ_VERIFIER_STATUS_INVALID_ARGUMENT);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_lookup_active, suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_lookup_inactive, suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_lookup_not_found, suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_lookup_misconfigured_status, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_lookup_invalid_args, suite_setup, suite_teardown),
    };

    return cmocka_run_group_tests_name("verifier_lookup_suite", tests, NULL, NULL);
}
