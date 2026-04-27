// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

// clang-format off
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>
// clang-format on
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string.h>

#include "infrastructure/tls/client_cert.h"
#include "infrastructure/tls_server.h"

// Suite Pattern: Struct to hold test state
struct ClientCertTestSuite {
    X509 *cert;
    EVP_PKEY *pkey;
};

// Assert Pattern: s_assert_xyz style macros
#define s_assert_int_equal(s, a, b) assert_int_equal(a, b)
#define s_assert_string_equal(s, a, b) assert_string_equal(a, b)

static int suite_setup(void **state) {
    struct ClientCertTestSuite *s = calloc(1, sizeof(struct ClientCertTestSuite));
    if (!s)
        return -1;

    s->pkey = EVP_PKEY_new();
    // Modern EVP key generation for tests (avoids deprecated RSA_generate_key)
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_keygen(ctx, &s->pkey);
    EVP_PKEY_CTX_free(ctx);

    *state = s;
    return 0;
}

static int suite_teardown(void **state) {
    struct ClientCertTestSuite *s = *state;
    if (s) {
        if (s->cert)
            X509_free(s->cert);
        if (s->pkey)
            EVP_PKEY_free(s->pkey);
        free(s);
    }
    return 0;
}

static X509 *create_cert(EVP_PKEY *pkey, const char *cn, const char *uri_san, const char *dns_san) {
    X509 *cert = X509_new();
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);
    X509_set_pubkey(cert, pkey);

    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)cn, -1, -1, 0);
    X509_set_issuer_name(cert, name);

    if (uri_san || dns_san) {
        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, NULL, cert, NULL, NULL, 0);

        char san_buf[512] = {0};
        if (uri_san && dns_san) {
            snprintf(san_buf, sizeof(san_buf), "URI:%s,DNS:%s", uri_san, dns_san);
        } else if (uri_san) {
            snprintf(san_buf, sizeof(san_buf), "URI:%s", uri_san);
        } else if (dns_san) {
            snprintf(san_buf, sizeof(san_buf), "DNS:%s", dns_san);
        }

        X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, san_buf);
        if (ext) {
            X509_add_ext(cert, ext, -1);
            X509_EXTENSION_free(ext);
        }
    }

    X509_sign(cert, pkey, EVP_sha256());
    return cert;
}

static void test_extract_from_uri_san(void **state) {
    struct ClientCertTestSuite *s = *state;
    struct vantaq_verifier_identity identity;
    const struct vantaq_tls_ops *ops = vantaq_tls_ops_default();

    s->cert = create_cert(s->pkey, "some-cn", "spiffe://vantaqd/verifier/verifier-001", NULL);

    enum vantaq_verifier_identity_status status =
        vantaq_tls_extract_verifier_id(ops, (struct x509_st *)s->cert, &identity);
    s_assert_int_equal(s, status, VANTAQ_VERIFIER_IDENTITY_STATUS_OK);
    s_assert_string_equal(s, identity.id, "verifier-001");
}

static void test_extract_from_dns_san(void **state) {
    struct ClientCertTestSuite *s = *state;
    struct vantaq_verifier_identity identity;
    const struct vantaq_tls_ops *ops = vantaq_tls_ops_default();

    s->cert = create_cert(s->pkey, "some-cn", NULL, "verifier-002.verifier.vantaqd.local");

    enum vantaq_verifier_identity_status status =
        vantaq_tls_extract_verifier_id(ops, (struct x509_st *)s->cert, &identity);
    s_assert_int_equal(s, status, VANTAQ_VERIFIER_IDENTITY_STATUS_OK);
    s_assert_string_equal(s, identity.id, "verifier-002");
}

static void test_cn_fallback_removal(void **state) {
    struct ClientCertTestSuite *s = *state;
    struct vantaq_verifier_identity identity;
    const struct vantaq_tls_ops *ops = vantaq_tls_ops_default();

    /* S-4, D-2: CN fallback should be removed. This cert has no SAN. */
    s->cert = create_cert(s->pkey, "verifier-003", NULL, NULL);

    enum vantaq_verifier_identity_status status =
        vantaq_tls_extract_verifier_id(ops, (struct x509_st *)s->cert, &identity);
    s_assert_int_equal(s, status, VANTAQ_VERIFIER_IDENTITY_STATUS_MISSING);
}

static void test_injection_protection(void **state) {
    struct ClientCertTestSuite *s = *state;
    struct vantaq_verifier_identity identity;
    const struct vantaq_tls_ops *ops = vantaq_tls_ops_default();

    /* S-2, D-3: Path traversal / dots / slashes must be rejected */
    s->cert = create_cert(s->pkey, "some-cn", "spiffe://vantaqd/verifier/../admin", NULL);
    enum vantaq_verifier_identity_status status =
        vantaq_tls_extract_verifier_id(ops, (struct x509_st *)s->cert, &identity);
    s_assert_int_equal(s, status, VANTAQ_VERIFIER_IDENTITY_STATUS_MISSING);

    /* Characters outside [a-zA-Z0-9_-] must be rejected */
    X509_free(s->cert);
    s->cert = create_cert(s->pkey, "some-cn", "spiffe://vantaqd/verifier/foo$bar", NULL);
    status  = vantaq_tls_extract_verifier_id(ops, (struct x509_st *)s->cert, &identity);
    s_assert_int_equal(s, status, VANTAQ_VERIFIER_IDENTITY_STATUS_MISSING);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_extract_from_uri_san, suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_extract_from_dns_san, suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_cn_fallback_removal, suite_setup, suite_teardown),
        cmocka_unit_test_setup_teardown(test_injection_protection, suite_setup, suite_teardown),
    };

    return cmocka_run_group_tests_name("client_cert_identity_suite", tests, NULL, NULL);
}
