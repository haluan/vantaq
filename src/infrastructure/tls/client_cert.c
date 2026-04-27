// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/tls/client_cert.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdbool.h>
#include <string.h>

#define SPIFFE_PREFIX "spiffe://vantaqd/verifier/"
#define DNS_SUFFIX ".verifier.vantaqd.local"

static bool extract_from_sans(X509 *cert, struct vantaq_verifier_identity *identity_out) {
    GENERAL_NAMES *sans = NULL;
    int i;
    bool found = false;

    sans = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (sans == NULL) {
        return false;
    }

    for (i = 0; i < sk_GENERAL_NAME_num(sans); i++) {
        GENERAL_NAME *name = sk_GENERAL_NAME_value(sans, i);

        if (name->type == GEN_URI) {
            const char *uri =
                (const char *)ASN1_STRING_get0_data(name->d.uniformResourceIdentifier);
            if (strncmp(uri, SPIFFE_PREFIX, strlen(SPIFFE_PREFIX)) == 0) {
                strncpy(identity_out->id, uri + strlen(SPIFFE_PREFIX),
                        VANTAQ_VERIFIER_ID_MAX_LEN - 1);
                identity_out->id[VANTAQ_VERIFIER_ID_MAX_LEN - 1] = '\0';
                found                                            = true;
                break;
            }
        } else if (name->type == GEN_DNS) {
            const char *dns   = (const char *)ASN1_STRING_get0_data(name->d.dNSName);
            size_t dns_len    = strlen(dns);
            size_t suffix_len = strlen(DNS_SUFFIX);
            if (dns_len > suffix_len && strcmp(dns + dns_len - suffix_len, DNS_SUFFIX) == 0) {
                size_t id_len = dns_len - suffix_len;
                if (id_len < VANTAQ_VERIFIER_ID_MAX_LEN) {
                    strncpy(identity_out->id, dns, id_len);
                    identity_out->id[id_len] = '\0';
                    found                    = true;
                    break;
                }
            }
        }
    }

    GENERAL_NAMES_free(sans);
    return found;
}

static bool extract_from_cn(X509 *cert, struct vantaq_verifier_identity *identity_out) {
    X509_NAME *subject = X509_get_subject_name(cert);
    if (subject == NULL) {
        return false;
    }

    if (X509_NAME_get_text_by_NID(subject, NID_commonName, identity_out->id,
                                  VANTAQ_VERIFIER_ID_MAX_LEN) > 0) {
        return true;
    }

    return false;
}

enum vantaq_verifier_identity_status
vantaq_tls_extract_verifier_id(void *x509_cert, struct vantaq_verifier_identity *identity_out) {
    X509 *cert = (X509 *)x509_cert;

    if (cert == NULL || identity_out == NULL) {
        return VANTAQ_VERIFIER_IDENTITY_STATUS_INVALID;
    }

    memset(identity_out->id, 0, sizeof(identity_out->id));

    if (extract_from_sans(cert, identity_out)) {
        return VANTAQ_VERIFIER_IDENTITY_STATUS_OK;
    }

    if (extract_from_cn(cert, identity_out)) {
        return VANTAQ_VERIFIER_IDENTITY_STATUS_OK;
    }

    return VANTAQ_VERIFIER_IDENTITY_STATUS_MISSING;
}
