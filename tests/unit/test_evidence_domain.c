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

#include "domain/evidence/evidence.h"

// Suite Pattern: Struct to hold test state
struct EvidenceDomainTestSuite {
    struct vantaq_evidence *evidence;
};

// Assert Pattern: s_assert_xyz style macros
#define s_assert_int_equal(s, a, b) assert_int_equal(a, b)
#define s_assert_int64_equal(s, a, b) assert_int_equal(a, b)
#define s_assert_string_equal(s, a, b) assert_string_equal(a, b)
#define s_assert_non_null(s, a) assert_non_null(a)
#define s_assert_null(s, a) assert_null(a)
#define s_assert_true(s, a) assert_true(a)
#define s_assert_false(s, a) assert_false(a)

static int suite_setup(void **state) {
    struct EvidenceDomainTestSuite *s = calloc(1, sizeof(struct EvidenceDomainTestSuite));
    if (!s)
        return -1;
    *state = s;
    return 0;
}

static int suite_teardown(void **state) {
    struct EvidenceDomainTestSuite *s = *state;
    if (s->evidence) {
        vantaq_evidence_destroy(s->evidence);
    }
    free(s);
    return 0;
}

static void test_evidence_creation_success(void **state) {
    struct EvidenceDomainTestSuite *s = *state;
    const char *ev_id                 = "ev-001";
    const char *dev_id                = "device-001";
    const char *ver_id                = "verifier-001";
    const char *ch_id                 = "ch-001";
    const char *nonce                 = "nonce-123";
    const char *purpose               = "remote_attestation";
    int64_t issued_at                 = 1770000000;
    const char *claims                = "{\"claim1\":\"value1\"}";
    const char *sig_alg               = "ECDSA-P256-SHA256";
    const char *sig                   = "base64-signature";

    vantaq_evidence_err_t err =
        vantaq_evidence_create(ev_id, dev_id, ver_id, ch_id, nonce, purpose, issued_at, claims,
                               sig_alg, sig, &s->evidence);

    s_assert_int_equal(s, err, VANTAQ_EVIDENCE_OK);
    s_assert_non_null(s, s->evidence);
    s_assert_string_equal(s, vantaq_evidence_get_evidence_id(s->evidence), ev_id);
    s_assert_string_equal(s, vantaq_evidence_get_device_id(s->evidence), dev_id);
    s_assert_string_equal(s, vantaq_evidence_get_verifier_id(s->evidence), ver_id);
    s_assert_string_equal(s, vantaq_evidence_get_challenge_id(s->evidence), ch_id);
    s_assert_string_equal(s, vantaq_evidence_get_nonce(s->evidence), nonce);
    s_assert_string_equal(s, vantaq_evidence_get_purpose(s->evidence), purpose);
    s_assert_int64_equal(s, vantaq_evidence_get_issued_at_unix(s->evidence), issued_at);
    s_assert_string_equal(s, vantaq_evidence_get_claims(s->evidence), claims);
    s_assert_string_equal(s, vantaq_evidence_get_signature_alg(s->evidence), sig_alg);
    s_assert_string_equal(s, vantaq_evidence_get_signature(s->evidence), sig);
}

static void test_evidence_creation_missing_fields(void **state) {
    struct EvidenceDomainTestSuite *s = *state;

    // Test with NULL evidence_id
    vantaq_evidence_err_t err = vantaq_evidence_create(NULL, "dev", "ver", "ch", "nonce", "purpose",
                                                       1234, "claims", "alg", "sig", &s->evidence);
    s_assert_int_equal(s, err, VANTAQ_EVIDENCE_ERR_MISSING_FIELD);
    s_assert_null(s, s->evidence);

    // Test with empty string
    err = vantaq_evidence_create("ev", "", "ver", "ch", "nonce", "purpose", 1234, "claims", "alg",
                                 "sig", &s->evidence);
    s_assert_int_equal(s, err, VANTAQ_EVIDENCE_ERR_MISSING_FIELD);
    s_assert_null(s, s->evidence);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_evidence_creation_success, suite_setup,
                                        suite_teardown),
        cmocka_unit_test_setup_teardown(test_evidence_creation_missing_fields, suite_setup,
                                        suite_teardown),
    };

    return cmocka_run_group_tests_name("evidence_domain_suite", tests, NULL, NULL);
}
