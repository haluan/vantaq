// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/crypto/evidence_signer.h"
#include "infrastructure/memory/zero_struct.h"

#include <limits.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdlib.h>
#include <string.h>

vantaq_signer_err_t vantaq_evidence_sign(const vantaq_device_key_t *key, const char *signature_alg,
                                         const char *payload, size_t payload_len,
                                         char **out_signature_b64) {
    if (!key || !signature_alg || !payload || !out_signature_b64) {
        return VANTAQ_SIGNER_ERR_INVALID_ARG;
    }
    *out_signature_b64 = NULL;

    ERR_clear_error();

    // Only support ECDSA-P256-SHA256 for now
    if (strcmp(signature_alg, "ECDSA-P256-SHA256") != 0) {
        return VANTAQ_SIGNER_ERR_UNSUPPORTED_ALG;
    }

    vantaq_signer_err_t status = VANTAQ_SIGNER_ERR_SIGN_FAILED;
    EVP_PKEY *pkey             = NULL;
    BIO *bio                   = NULL;
    EVP_MD_CTX *ctx            = NULL;
    unsigned char *sig         = NULL;
    size_t sig_len             = 0;
    char *b64_sig              = NULL;

    const char *priv_pem = vantaq_device_key_get_private_pem(key);
    if (!priv_pem) {
        status = VANTAQ_SIGNER_ERR_KEY_LOAD;
        goto cleanup;
    }

    bio = BIO_new_mem_buf(priv_pem, -1);
    if (!bio) {
        status = VANTAQ_SIGNER_ERR_MALLOC_FAILED;
        goto cleanup;
    }

    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        status = VANTAQ_SIGNER_ERR_KEY_LOAD;
        goto cleanup;
    }

    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        status = VANTAQ_SIGNER_ERR_MALLOC_FAILED;
        goto cleanup;
    }

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        goto cleanup;
    }

    if (EVP_DigestSignUpdate(ctx, payload, payload_len) <= 0) {
        goto cleanup;
    }

    // Determine signature length
    if (EVP_DigestSignFinal(ctx, NULL, &sig_len) <= 0) {
        goto cleanup;
    }
    if (sig_len == 0) {
        goto cleanup;
    }

    sig = malloc(sig_len);
    if (!sig) {
        status = VANTAQ_SIGNER_ERR_MALLOC_FAILED;
        goto cleanup;
    }

    if (EVP_DigestSignFinal(ctx, sig, &sig_len) <= 0) {
        goto cleanup;
    }

    // Base64 encode
    // The output length of EVP_EncodeBlock is 4 * ((sig_len + 2) / 3)
    if (sig_len > (size_t)INT_MAX) {
        status = VANTAQ_SIGNER_ERR_BASE64_FAILED;
        goto cleanup;
    }
    size_t b64_len = ((sig_len + 2U) / 3U) * 4U;
    b64_sig        = malloc(b64_len + 1U);
    if (!b64_sig) {
        status = VANTAQ_SIGNER_ERR_MALLOC_FAILED;
        goto cleanup;
    }

    if (EVP_EncodeBlock((unsigned char *)b64_sig, sig, (int)sig_len) < 0) {
        status = VANTAQ_SIGNER_ERR_BASE64_FAILED;
        goto cleanup;
    }
    b64_sig[b64_len] = '\0';

    *out_signature_b64 = b64_sig;
    status             = VANTAQ_SIGNER_OK;

cleanup:
    if (ctx)
        EVP_MD_CTX_free(ctx);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (bio)
        BIO_free(bio);
    if (sig) {
        vantaq_explicit_bzero(sig, sig_len);
        free(sig);
    }
    if (status != VANTAQ_SIGNER_OK && b64_sig)
        free(b64_sig);
    if (status != VANTAQ_SIGNER_OK) {
        while (ERR_get_error() != 0) {
        }
    }

    return status;
}

void vantaq_signature_b64_destroy(char *signature_b64) {
    if (signature_b64) {
        vantaq_explicit_bzero(signature_b64, strlen(signature_b64));
        free(signature_b64);
    }
}
