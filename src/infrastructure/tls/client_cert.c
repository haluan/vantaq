// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/tls/client_cert.h"
#include "infrastructure/memory/zero_struct.h"
#include "infrastructure/tls_server.h"

#include <ctype.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdbool.h>
#include <string.h>

#define SPIFFE_PREFIX "spiffe://vantaqd/verifier/"
#define DNS_SUFFIX ".verifier.vantaqd.local"

/**
 * Validate verifier ID segment .
 * Allowed characters: [a-zA-Z0-9_-]
 */
static bool is_valid_verifier_id(const char *id, size_t len) {
    size_t i;
    if (len == 0 || len >= VANTAQ_VERIFIER_ID_MAX_LEN) {
        return false;
    }
    for (i = 0; i < len; i++) {
        char c = id[i];
        if (!isalnum(c) && c != '_' && c != '-') {
            return false;
        }
    }
    return true;
}

static bool extract_from_sans(const struct vantaq_tls_ops *ops, struct x509_st *cert,
                              struct vantaq_verifier_identity *identity_out) {
    void *sans = NULL; /* GENERAL_NAMES */
    int i;
    bool found = false;

    sans = ops->cert_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (sans == NULL) {
        return false;
    }

    for (i = 0; i < ops->sans_count(sans); i++) {
        GENERAL_NAME *name = ops->sans_get(sans, i);

        if (name->type == GEN_URI) {
            const unsigned char *uri_data = ops->asn1_get_data(name->d.uniformResourceIdentifier);
            int uri_len                   = ops->asn1_get_len(name->d.uniformResourceIdentifier);
            size_t prefix_len             = strlen(SPIFFE_PREFIX);

            /* Use length-aware comparisons, NULL guards */
            if (uri_data != NULL && uri_len > (int)prefix_len) {
                if (memcmp(uri_data, SPIFFE_PREFIX, prefix_len) == 0) {
                    size_t id_len = (size_t)uri_len - prefix_len;

                    /* Validate segment before copy */
                    if (is_valid_verifier_id((const char *)uri_data + prefix_len, id_len)) {
                        memcpy(identity_out->id, uri_data + prefix_len, id_len);
                        identity_out->id[id_len] = '\0';
                        found                    = true;
                        break;
                    }
                }
            }
        } else if (name->type == GEN_DNS) {
            const unsigned char *dns_data = ops->asn1_get_data(name->d.dNSName);
            int dns_len                   = ops->asn1_get_len(name->d.dNSName);
            size_t suffix_len             = strlen(DNS_SUFFIX);

            /* Length-aware DNS suffix check */
            if (dns_data != NULL && dns_len > (int)suffix_len) {
                if (memcmp(dns_data + dns_len - suffix_len, DNS_SUFFIX, suffix_len) == 0) {
                    size_t id_len = (size_t)dns_len - suffix_len;

                    /* Validate segment before copy */
                    if (is_valid_verifier_id((const char *)dns_data, id_len)) {
                        memcpy(identity_out->id, dns_data, id_len);
                        identity_out->id[id_len] = '\0';
                        found                    = true;
                        break;
                    }
                }
            }
        }
    }

    ops->sans_free(sans, (void (*)(void *))GENERAL_NAME_free);
    return found;
}

/**
 * Identity MUST be expressed in SANs (URI or DNS).
 */

enum vantaq_verifier_identity_status
vantaq_tls_extract_verifier_id(const struct vantaq_tls_ops *ops, struct x509_st *x509_cert,
                               struct vantaq_verifier_identity *identity_out) {
    if (ops == NULL || x509_cert == NULL || identity_out == NULL) {
        return VANTAQ_VERIFIER_IDENTITY_STATUS_INVALID;
    }

    VANTAQ_ZERO_STRUCT(*identity_out);

    if (extract_from_sans(ops, x509_cert, identity_out)) {
        return VANTAQ_VERIFIER_IDENTITY_STATUS_OK;
    }

    return VANTAQ_VERIFIER_IDENTITY_STATUS_MISSING;
}
