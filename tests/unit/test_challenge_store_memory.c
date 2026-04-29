// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/memory/challenge_store_memory.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

struct ChallengeStoreMemoryTestSuite {
    struct vantaq_challenge_store *store;
};

#define s_assert_int_equal(s, a, b) assert_int_equal(a, b)
#define s_assert_ptr_equal(s, a, b) assert_ptr_equal(a, b)
#define s_assert_ptr_not_null(s, a) assert_non_null(a)
#define s_assert_ptr_null(s, a) assert_null(a)

static int suite_setup(void **state) {
    struct ChallengeStoreMemoryTestSuite *s =
        calloc(1, sizeof(struct ChallengeStoreMemoryTestSuite));
    if (!s)
        return -1;

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
        vantaq_challenge_store_destroy(s->store);
    }
    free(s);
    return 0;
}

static void test_store_insert_lookup(void **state) {
    struct ChallengeStoreMemoryTestSuite *s = *state;
    struct vantaq_challenge *ch = vantaq_challenge_create("ch-001", "nonce", "v1", "p", 100, 1000);
    struct vantaq_challenge *found = NULL;

    enum vantaq_challenge_store_status status = vantaq_challenge_store_insert(s->store, ch);
    s_assert_int_equal(s, status, VANTAQ_CHALLENGE_STORE_OK);

    status = vantaq_challenge_store_find_and_consume(s->store, "ch-001", 500, false, &found);
    s_assert_int_equal(s, status, VANTAQ_CHALLENGE_STORE_OK);
    s_assert_ptr_equal(s, found, ch);
}

static void test_store_global_limit(void **state) {
    struct ChallengeStoreMemoryTestSuite *s = *state;

    for (int i = 0; i < 5; i++) {
        char id[16];
        char v_id[16];
        sprintf(id, "ch-%d", i);
        sprintf(v_id, "v-%d", i);
        struct vantaq_challenge *ch = vantaq_challenge_create(id, "n", v_id, "p", 100, 1000);
        s_assert_ptr_not_null(s, ch);
        vantaq_challenge_store_insert(s->store, ch);
    }

    struct vantaq_challenge *extra = vantaq_challenge_create("extra", "n", "v1", "p", 100, 1000);
    enum vantaq_challenge_store_status status = vantaq_challenge_store_insert(s->store, extra);
    s_assert_int_equal(s, status, VANTAQ_CHALLENGE_STORE_ERROR_GLOBAL_CAPACITY_REACHED);

    vantaq_challenge_destroy(extra);
}

static void test_store_verifier_limit(void **state) {
    struct ChallengeStoreMemoryTestSuite *s = *state;

    struct vantaq_challenge *ch1 = vantaq_challenge_create("ch-1", "n", "v-limit", "p", 100, 1000);
    struct vantaq_challenge *ch2 = vantaq_challenge_create("ch-2", "n", "v-limit", "p", 100, 1000);
    struct vantaq_challenge *ch3 = vantaq_challenge_create("ch-3", "n", "v-limit", "p", 100, 1000);

    s_assert_int_equal(s, vantaq_challenge_store_insert(s->store, ch1), VANTAQ_CHALLENGE_STORE_OK);
    s_assert_int_equal(s, vantaq_challenge_store_insert(s->store, ch2), VANTAQ_CHALLENGE_STORE_OK);

    s_assert_int_equal(s, vantaq_challenge_store_insert(s->store, ch3),
                       VANTAQ_CHALLENGE_STORE_ERROR_VERIFIER_CAPACITY_REACHED);

    vantaq_challenge_destroy(ch3);
}

static void test_store_cleanup_on_insert(void **state) {
    struct ChallengeStoreMemoryTestSuite *s = *state;

    /* Fill up the store with nearly-expired entries */
    for (int i = 0; i < 5; i++) {
        char id[16];
        sprintf(id, "exp-%d", i);
        struct vantaq_challenge *ch = vantaq_challenge_create(id, "n", "v", "p", 100, 500);
        vantaq_challenge_store_insert(s->store, ch);
    }

    /* Insertion of a new challenge at t=600 should trigger internal cleanup and succeed */
    struct vantaq_challenge *new_ch = vantaq_challenge_create("new", "n", "v", "p", 600, 1000);
    enum vantaq_challenge_store_status status = vantaq_challenge_store_insert(s->store, new_ch);
    s_assert_int_equal(s, status, VANTAQ_CHALLENGE_STORE_OK);
    s_assert_int_equal(s, vantaq_challenge_store_count_global_pending(s->store), 1);
}

static void test_store_find_and_consume(void **state) {
    struct ChallengeStoreMemoryTestSuite *s = *state;
    struct vantaq_challenge *ch = vantaq_challenge_create("ch-001", "nonce", "v1", "p", 100, 1000);
    struct vantaq_challenge *found = NULL;

    vantaq_challenge_store_insert(s->store, ch);

    /* Atomic consume */
    enum vantaq_challenge_store_status status =
        vantaq_challenge_store_find_and_consume(s->store, "ch-001", 500, true, &found);

    s_assert_int_equal(s, status, VANTAQ_CHALLENGE_STORE_OK);
    s_assert_ptr_equal(s, found, ch);
    s_assert_int_equal(s, vantaq_challenge_is_used(ch), true);

    /* Try to consume again */
    status = vantaq_challenge_store_find_and_consume(s->store, "ch-001", 600, true, &found);
    s_assert_int_equal(s, status, VANTAQ_CHALLENGE_STORE_ERROR_INTERNAL); /* Already used */
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_store_insert_lookup, suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_store_global_limit, suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_store_verifier_limit, suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_store_cleanup_on_insert, suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_store_find_and_consume, suite_setup, suite_teardown),
    };

    return cmocka_run_group_tests_name("challenge_store_memory_suite", tests, NULL, NULL);
}
