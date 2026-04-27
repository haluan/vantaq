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

#include "infrastructure/memory/challenge_store_memory.h"

// Suite Pattern: Struct to hold test state
struct ChallengeStoreMemoryTestSuite {
    struct vantaq_challenge_store *store;
};

// Assert Pattern: s_assert_xyz style macros
#define s_assert_int_equal(s, a, b) assert_int_equal(a, b)
#define s_assert_ptr_equal(s, a, b) assert_ptr_equal(a, b)
#define s_assert_ptr_not_null(s, a) assert_non_null(a)
#define s_assert_ptr_null(s, a) assert_null(a)

static int suite_setup(void **state) {
    struct ChallengeStoreMemoryTestSuite *s =
        calloc(1, sizeof(struct ChallengeStoreMemoryTestSuite));
    if (!s)
        return -1;

    // Create store with 5 global slots, max 2 per verifier
    s->store = vantaq_challenge_store_memory_create(5, 2);
    if (!s->store) {
        free(s);
        return -1;
    }

    *state = s;
    return 0;
}

static int suite_teardown(void **state) {
    struct ChallengeStoreMemoryTestSuite *s = *state;
    if (s->store) {
        s->store->destroy(s->store);
    }
    free(s);
    return 0;
}

static void test_store_insert_lookup(void **state) {
    struct ChallengeStoreMemoryTestSuite *s = *state;
    struct vantaq_challenge *ch = vantaq_challenge_create("ch-001", "nonce", "v1", "p", 0, 1000);

    enum vantaq_challenge_store_status status = s->store->insert(s->store, ch);
    s_assert_int_equal(s, status, VANTAQ_CHALLENGE_STORE_OK);

    struct vantaq_challenge *found = s->store->lookup(s->store, "ch-001");
    s_assert_ptr_equal(s, found, ch);
}

static void test_store_global_limit(void **state) {
    struct ChallengeStoreMemoryTestSuite *s = *state;

    // We already have 1 from previous test if setup/teardown is per group,
    // but setup/teardown in my main is per test.
    // Let's assume fresh store for each test (setup/teardown linked in main).

    for (int i = 0; i < 5; i++) {
        char id[16];
        char v_id[16];
        sprintf(id, "ch-%d", i);
        sprintf(v_id, "v-%d", i);
        struct vantaq_challenge *ch = vantaq_challenge_create(id, "n", v_id, "p", 0, 1000);
        s_assert_ptr_not_null(s, ch);
        s->store->insert(s->store, ch);
    }

    struct vantaq_challenge *extra = vantaq_challenge_create("extra", "n", "v1", "p", 0, 1000);
    enum vantaq_challenge_store_status status = s->store->insert(s->store, extra);
    s_assert_int_equal(s, status, VANTAQ_CHALLENGE_STORE_ERROR_GLOBAL_CAPACITY_REACHED);

    vantaq_challenge_destroy(extra);
}

static void test_store_verifier_limit(void **state) {
    struct ChallengeStoreMemoryTestSuite *s = *state;

    struct vantaq_challenge *ch1 = vantaq_challenge_create("ch-1", "n", "v-limit", "p", 0, 1000);
    struct vantaq_challenge *ch2 = vantaq_challenge_create("ch-2", "n", "v-limit", "p", 0, 1000);
    struct vantaq_challenge *ch3 = vantaq_challenge_create("ch-3", "n", "v-limit", "p", 0, 1000);

    s_assert_int_equal(s, s->store->insert(s->store, ch1), VANTAQ_CHALLENGE_STORE_OK);
    s_assert_int_equal(s, s->store->insert(s->store, ch2), VANTAQ_CHALLENGE_STORE_OK);

    // 3rd for same verifier should fail (limit 2)
    s_assert_int_equal(s, s->store->insert(s->store, ch3),
                       VANTAQ_CHALLENGE_STORE_ERROR_VERIFIER_CAPACITY_REACHED);

    vantaq_challenge_destroy(ch3);
}

static void test_store_cleanup(void **state) {
    struct ChallengeStoreMemoryTestSuite *s = *state;

    struct vantaq_challenge *valid   = vantaq_challenge_create("valid", "n", "v", "p", 0, 2000);
    struct vantaq_challenge *expired = vantaq_challenge_create("expired", "n", "v", "p", 0, 500);

    s->store->insert(s->store, valid);
    s->store->insert(s->store, expired);

    s_assert_int_equal(s, s->store->count_global_pending(s->store), 2);

    // Cleanup at t=1000
    s->store->cleanup_expired(s->store, 1000);

    s_assert_int_equal(s, s->store->count_global_pending(s->store), 1);
    s_assert_ptr_not_null(s, s->store->lookup(s->store, "valid"));
    s_assert_ptr_null(s, s->store->lookup(s->store, "expired"));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_store_insert_lookup, suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_store_global_limit, suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_store_verifier_limit, suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_store_cleanup, suite_setup, suite_teardown),
    };

    return cmocka_run_group_tests_name("challenge_store_memory_suite", tests, NULL, NULL);
}
