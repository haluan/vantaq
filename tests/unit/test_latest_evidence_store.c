// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/evidence/latest_evidence_store.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

// Assert pattern
#define s_assert_int_equal(suite, a, b) assert_int_equal(a, b)
#define s_assert_non_null(suite, p) assert_non_null(p)
#define s_assert_string_equal(suite, a, b) assert_string_equal(a, b)
#define s_assert_null(suite, p) assert_null(p)

struct LatestEvidenceSuite {
    struct vantaq_latest_evidence_store *store;
};

static int suite_setup(void **state) {
    struct LatestEvidenceSuite *s = malloc(sizeof(struct LatestEvidenceSuite));
    if (!s)
        return -1;
    s->store = vantaq_latest_evidence_store_create(2);
    *state   = s;
    return 0;
}

static int suite_teardown(void **state) {
    struct LatestEvidenceSuite *s = *state;
    if (s) {
        vantaq_latest_evidence_store_destroy(s->store);
        free(s);
    }
    return 0;
}

static void test_latest_evidence_store_put_get_success(void **state) {
    struct LatestEvidenceSuite *s    = *state;
    struct vantaq_evidence *evidence = NULL;
    struct vantaq_evidence *out_ev   = NULL;
    char *out_sig                    = NULL;

    vantaq_evidence_create("ev-1", "dev-1", "verifier-1", "ch-1", "nonce-1", "test", 12345, "{}",
                           "alg-1", "sig-1", &evidence);

    vantaq_latest_evidence_err_t err =
        vantaq_latest_evidence_store_put(s->store, "verifier-1", evidence, "sig-1-b64");
    s_assert_int_equal(s, err, VANTAQ_LATEST_EVIDENCE_OK);

    err = vantaq_latest_evidence_store_get(s->store, "verifier-1", &out_ev, &out_sig);
    s_assert_int_equal(s, err, VANTAQ_LATEST_EVIDENCE_OK);
    s_assert_non_null(s, out_ev);
    s_assert_string_equal(s, vantaq_evidence_get_evidence_id(out_ev), "ev-1");
    s_assert_string_equal(s, out_sig, "sig-1-b64");
    s_assert_string_equal(s, vantaq_evidence_get_signature(out_ev), "sig-1");

    vantaq_evidence_destroy(evidence);
    vantaq_evidence_destroy(out_ev);
    free(out_sig);
}

static void test_latest_evidence_store_overwrite(void **state) {
    struct LatestEvidenceSuite *s  = *state;
    struct vantaq_evidence *ev1    = NULL;
    struct vantaq_evidence *ev2    = NULL;
    struct vantaq_evidence *out_ev = NULL;
    char *out_sig                  = NULL;

    vantaq_evidence_create("ev-1", "dev-1", "verifier-1", "ch-1", "nonce-1", "test", 12345, "{}",
                           "alg-1", "sig-1", &ev1);
    vantaq_evidence_create("ev-2", "dev-1", "verifier-1", "ch-2", "nonce-2", "test", 12346, "{}",
                           "alg-1", "sig-2", &ev2);

    vantaq_latest_evidence_store_put(s->store, "verifier-1", ev1, "sig-1-b64");
    vantaq_latest_evidence_err_t err =
        vantaq_latest_evidence_store_put(s->store, "verifier-1", ev2, "sig-2-b64");
    s_assert_int_equal(s, err, VANTAQ_LATEST_EVIDENCE_OK);

    vantaq_latest_evidence_store_get(s->store, "verifier-1", &out_ev, &out_sig);
    s_assert_string_equal(s, vantaq_evidence_get_evidence_id(out_ev), "ev-2");
    s_assert_string_equal(s, out_sig, "sig-2-b64");

    vantaq_evidence_destroy(ev1);
    vantaq_evidence_destroy(ev2);
    vantaq_evidence_destroy(out_ev);
    free(out_sig);
}

static void test_latest_evidence_store_not_found(void **state) {
    struct LatestEvidenceSuite *s  = *state;
    struct vantaq_evidence *out_ev = NULL;
    char *out_sig                  = NULL;

    vantaq_latest_evidence_err_t err =
        vantaq_latest_evidence_store_get(s->store, "unknown", &out_ev, &out_sig);
    s_assert_int_equal(s, err, VANTAQ_LATEST_EVIDENCE_ERR_NOT_FOUND);
}

static void test_latest_evidence_store_full(void **state) {
    struct LatestEvidenceSuite *s = *state;
    struct vantaq_evidence *ev    = NULL;
    vantaq_evidence_create("ev", "dev", "v", "ch", "n", "t", 1, "{}", "a", "s", &ev);

    vantaq_latest_evidence_store_put(s->store, "v1", ev, "s1");
    vantaq_latest_evidence_store_put(s->store, "v2", ev, "s2");
    vantaq_latest_evidence_err_t err = vantaq_latest_evidence_store_put(s->store, "v3", ev, "s3");
    s_assert_int_equal(s, err, VANTAQ_LATEST_EVIDENCE_ERR_FULL);

    vantaq_evidence_destroy(ev);
}

static void test_latest_evidence_store_rejects_too_long_verifier_id(void **state) {
    struct LatestEvidenceSuite *s  = *state;
    struct vantaq_evidence *ev     = NULL;
    struct vantaq_evidence *out_ev = NULL;
    char *out_sig                  = NULL;
    char long_verifier_id[VANTAQ_VERIFIER_ID_MAX + 16];

    memset(long_verifier_id, 'a', sizeof(long_verifier_id) - 1);
    long_verifier_id[sizeof(long_verifier_id) - 1] = '\0';

    vantaq_evidence_create("ev", "dev", "verifier-1", "ch", "n", "t", 1, "{}", "a", "s", &ev);
    vantaq_latest_evidence_err_t err =
        vantaq_latest_evidence_store_put(s->store, long_verifier_id, ev, "s1");
    s_assert_int_equal(s, err, VANTAQ_LATEST_EVIDENCE_ERR_VERIFIER_ID_TOO_LONG);

    err = vantaq_latest_evidence_store_get(s->store, long_verifier_id, &out_ev, &out_sig);
    s_assert_int_equal(s, err, VANTAQ_LATEST_EVIDENCE_ERR_NOT_FOUND);
    s_assert_null(s, out_ev);
    s_assert_null(s, out_sig);

    vantaq_evidence_destroy(ev);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_latest_evidence_store_put_get_success, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_latest_evidence_store_overwrite, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_latest_evidence_store_not_found, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_latest_evidence_store_full, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_latest_evidence_store_rejects_too_long_verifier_id,
                                        suite_setup, suite_teardown),
    };
    return cmocka_run_group_tests_name("unit_latest_evidence_store", tests, NULL, NULL);
}
