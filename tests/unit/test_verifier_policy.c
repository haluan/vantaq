// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

// clang-format off
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>
// clang-format on
#include <stdlib.h>
#include <string.h>

#include "domain/verifier_access/verifier_policy.h"

// Suite Pattern: Struct to hold test state
struct VerifierPolicyTestSuite {
    struct vantaq_verifier_identity identity;
};

// Assert Pattern: s_assert_xyz style macros
#define s_assert_int_equal(s, a, b) assert_int_equal(a, b)

static int suite_setup(void **state) {
    struct VerifierPolicyTestSuite *s = calloc(1, sizeof(struct VerifierPolicyTestSuite));
    if (!s)
        return -1;
    *state = s;
    return 0;
}

static int suite_teardown(void **state) {
    struct VerifierPolicyTestSuite *s = *state;
    free(s);
    return 0;
}

static void test_evaluate_active_verifier(void **state) {
    struct VerifierPolicyTestSuite *s = *state;
    strncpy(s->identity.id, "verifier-001", sizeof(s->identity.id) - 1);

    enum vantaq_verifier_policy_decision decision =
        vantaq_verifier_policy_evaluate(&s->identity, VANTAQ_VERIFIER_STATUS_ACTIVE);

    s_assert_int_equal(s, decision, VANTAQ_VERIFIER_POLICY_ALLOW);
}

static void test_evaluate_inactive_verifier(void **state) {
    struct VerifierPolicyTestSuite *s = *state;
    strncpy(s->identity.id, "verifier-002", sizeof(s->identity.id) - 1);

    enum vantaq_verifier_policy_decision decision =
        vantaq_verifier_policy_evaluate(&s->identity, VANTAQ_VERIFIER_STATUS_INACTIVE);

    s_assert_int_equal(s, decision, VANTAQ_VERIFIER_POLICY_REJECT_INACTIVE);
}

static void test_evaluate_unknown_verifier(void **state) {
    struct VerifierPolicyTestSuite *s = *state;
    strncpy(s->identity.id, "verifier-999", sizeof(s->identity.id) - 1);

    enum vantaq_verifier_policy_decision decision =
        vantaq_verifier_policy_evaluate(&s->identity, VANTAQ_VERIFIER_STATUS_UNKNOWN);

    s_assert_int_equal(s, decision, VANTAQ_VERIFIER_POLICY_REJECT_UNKNOWN);
}

static void test_evaluate_missing_identity(void **state) {
    struct VerifierPolicyTestSuite *s = *state;
    s->identity.id[0]                 = '\0';

    enum vantaq_verifier_policy_decision decision =
        vantaq_verifier_policy_evaluate(&s->identity, VANTAQ_VERIFIER_STATUS_ACTIVE);

    s_assert_int_equal(s, decision, VANTAQ_VERIFIER_POLICY_REJECT_MISSING_ID);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_evaluate_active_verifier, suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_evaluate_inactive_verifier, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_evaluate_unknown_verifier, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_evaluate_missing_identity, suite_setup,
                                        suite_teardown),
    };

    return cmocka_run_group_tests_name("verifier_policy_suite", tests, NULL, NULL);
}
