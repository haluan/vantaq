// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_INFRASTRUCTURE_CRYPTO_NONCE_RANDOM_H
#define VANTAQ_INFRASTRUCTURE_CRYPTO_NONCE_RANDOM_H

#include <stddef.h>

enum vantaq_crypto_status {
    VANTAQ_CRYPTO_OK = 0,
    VANTAQ_CRYPTO_ERROR_INVALID_ARGS,
    VANTAQ_CRYPTO_ERROR_RNG_FAILED,
    VANTAQ_CRYPTO_ERROR_MALLOC_FAILED,
};

/**
 * @brief Generate a cryptographically secure random nonce encoded as hex.
 * 
 * @param out_hex Output buffer for hex-encoded nonce.
 * @param out_len Length of the output buffer (must be at least nonce_bytes * 2 + 1).
 * @param nonce_bytes Number of random bytes to generate (must be at least 16).
 * @return enum vantaq_crypto_status 
 */
enum vantaq_crypto_status vantaq_crypto_generate_nonce_hex(char *out_hex, size_t out_len, size_t nonce_bytes);

#endif
