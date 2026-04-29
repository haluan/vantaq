// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "domain/evidence/evidence_canonical.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

// Suite Pattern: Struct to hold test state
struct EvidenceCanonicalTestSuite {
    struct vantaq_evidence *evidence;
    char *canonical_buffer;
    size_t canonical_len;
};

// Assert Pattern: s_assert_xyz style macros
#define s_assert_int_equal(s, a, b) assert_int_equal(a, b)
#define s_assert_string_equal(s, a, b) assert_string_equal(a, b)
#define s_assert_non_null(s, a) assert_non_null(a)
#define s_assert_null(s, a) assert_null(a)
#define s_assert_true(s, a) assert_true(a)
#define s_assert_false(s, a) assert_false(a)

static int suite_setup(void **state) {
    struct EvidenceCanonicalTestSuite *s = calloc(1, sizeof(struct EvidenceCanonicalTestSuite));
    if (!s)
        return -1;
    *state = s;
    return 0;
}

static int suite_teardown(void **state) {
    struct EvidenceCanonicalTestSuite *s = *state;
    if (s->evidence) {
        vantaq_evidence_destroy(s->evidence);
    }
    if (s->canonical_buffer) {
        vantaq_evidence_canonical_destroy(s->canonical_buffer);
    }
    free(s);
    return 0;
}

static void test_serialization_determinism(void **state) {
    struct EvidenceCanonicalTestSuite *s = *state;

    // Create evidence
    vantaq_evidence_create("ev-1", "dev-1", "ver-1", "ch-1", "nonce-1", "purpose-1", 1000,
                           "{\"claims\":\"val\"}", "alg-1", "sig-1", &s->evidence);
    s_assert_non_null(s, s->evidence);

    // Serialize first time
    char *buf1                = NULL;
    size_t len1               = 0;
    vantaq_evidence_err_t err = vantaq_evidence_serialize_canonical(s->evidence, &buf1, &len1);
    s_assert_int_equal(s, err, VANTAQ_EVIDENCE_OK);
    s_assert_non_null(s, buf1);

    // Serialize second time
    char *buf2  = NULL;
    size_t len2 = 0;
    err         = vantaq_evidence_serialize_canonical(s->evidence, &buf2, &len2);
    s_assert_int_equal(s, err, VANTAQ_EVIDENCE_OK);
    s_assert_non_null(s, buf2);

    // Must be identical
    s_assert_int_equal(s, len1, len2);
    s_assert_string_equal(s, buf1, buf2);

    vantaq_evidence_canonical_destroy(buf1);
    vantaq_evidence_canonical_destroy(buf2);
}

static void test_serialization_nonce_variation(void **state) {
    struct EvidenceCanonicalTestSuite *s = *state;

    struct vantaq_evidence *ev1 = NULL;
    struct vantaq_evidence *ev2 = NULL;

    vantaq_evidence_create("ev-1", "dev-1", "ver-1", "ch-1", "nonce-A", "purpose-1", 1000, "{}",
                           "alg-1", "sig-1", &ev1);
    vantaq_evidence_create("ev-1", "dev-1", "ver-1", "ch-1", "nonce-B", "purpose-1", 1000, "{}",
                           "alg-1", "sig-1", &ev2);

    char *buf1  = NULL;
    size_t len1 = 0;
    char *buf2  = NULL;
    size_t len2 = 0;

    vantaq_evidence_serialize_canonical(ev1, &buf1, &len1);
    vantaq_evidence_serialize_canonical(ev2, &buf2, &len2);

    // Must be different
    s_assert_false(s, (len1 == len2 && strcmp(buf1, buf2) == 0));

    vantaq_evidence_canonical_destroy(buf1);
    vantaq_evidence_canonical_destroy(buf2);
    vantaq_evidence_destroy(ev1);
    vantaq_evidence_destroy(ev2);
}

static void test_serialization_signature_exclusion(void **state) {
    struct EvidenceCanonicalTestSuite *s = *state;
    const char *sig_val                  = "SECRET_SIGNATURE_VALUE";

    vantaq_evidence_create("ev-1", "dev-1", "ver-1", "ch-1", "nonce-1", "purpose-1", 1000, "{}",
                           "alg-1", sig_val, &s->evidence);

    char *buf  = NULL;
    size_t len = 0;
    vantaq_evidence_serialize_canonical(s->evidence, &buf, &len);

    // Serialized output must NOT contain the signature value
    s_assert_null(s, strstr(buf, sig_val));

    vantaq_evidence_canonical_destroy(buf);
}

static void test_serialization_escapes_pipe_delimiter_in_claims(void **state) {
    struct EvidenceCanonicalTestSuite *s = *state;

    vantaq_evidence_create("ev-1", "dev-1", "ver-1", "ch-1", "nonce-1", "purpose-1", 1000,
                           "{\"alg\":\"ES256|RS256\"}", "alg-1", "sig-1", &s->evidence);

    char *buf                 = NULL;
    size_t len                = 0;
    vantaq_evidence_err_t err = vantaq_evidence_serialize_canonical(s->evidence, &buf, &len);
    s_assert_int_equal(s, err, VANTAQ_EVIDENCE_OK);
    s_assert_non_null(s, buf);
    s_assert_true(s, strstr(buf, "claims:{\"alg\":\"ES256\\|RS256\"}") != NULL);

    vantaq_evidence_canonical_destroy(buf);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_serialization_determinism, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_serialization_nonce_variation, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_serialization_signature_exclusion, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_serialization_escapes_pipe_delimiter_in_claims,
                                        suite_setup, suite_teardown),
    };

    return cmocka_run_group_tests_name("evidence_canonical_suite", tests, NULL, NULL);
}
