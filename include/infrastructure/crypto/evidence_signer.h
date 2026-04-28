// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_INFRASTRUCTURE_CRYPTO_EVIDENCE_SIGNER_H
#define VANTAQ_INFRASTRUCTURE_CRYPTO_EVIDENCE_SIGNER_H

#include "infrastructure/crypto/device_key_loader.h"
#include <stddef.h>

typedef enum {
    VANTAQ_SIGNER_OK = 0,
    VANTAQ_SIGNER_ERR_INVALID_ARG = 1,
    VANTAQ_SIGNER_ERR_KEY_LOAD = 2,
    VANTAQ_SIGNER_ERR_SIGN_FAILED = 3,
    VANTAQ_SIGNER_ERR_BASE64_FAILED = 4,
    VANTAQ_SIGNER_ERR_MALLOC_FAILED = 5,
    VANTAQ_SIGNER_ERR_UNSUPPORTED_ALG = 6
} vantaq_signer_err_t;

/**
 * @brief Sign canonical evidence payload with the device private key.
 * 
 * @param key Loaded device key object containing the private key.
 * @param signature_alg Signature algorithm to use (e.g., "ECDSA-P256-SHA256").
 * @param payload Canonical bytes to sign.
 * @param payload_len Length of the payload.
 * @param out_signature_b64 Pointer to hold the allocated base64-encoded signature.
 * @return vantaq_signer_err_t Status code.
 */
vantaq_signer_err_t vantaq_evidence_sign(const vantaq_device_key_t *key,
                                         const char *signature_alg,
                                         const char *payload,
                                         size_t payload_len,
                                         char **out_signature_b64);

/**
 * @brief Destroy the base64 signature allocated by vantaq_evidence_sign.
 */
void vantaq_signature_b64_destroy(char *signature_b64);

/**
 * @brief Backward-compatible alias for vantaq_signature_b64_destroy.
 */
void vantaq_signature_b64_free(char *signature_b64);

#endif
