// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_INFRASTRUCTURE_CRYPTO_NONCE_RANDOM_H
#define VANTAQ_INFRASTRUCTURE_CRYPTO_NONCE_RANDOM_H

#include <stddef.h>

/* Explicit upper bound for nonces to prevent unbounded allocation/stack use */
#define VANTAQ_NONCE_BYTES_MAX 64
#define VANTAQ_NONCE_BYTES_MIN 16

enum vantaq_crypto_status {
    VANTAQ_CRYPTO_OK = 0,
    VANTAQ_CRYPTO_ERROR_INVALID_ARGS,
    VANTAQ_CRYPTO_ERROR_RNG_FAILED,
    VANTAQ_CRYPTO_ERROR_MALLOC_FAILED, /* Persisted for ABI but unreachable if D-2 is used */
};

/**
 * @brief Generate a cryptographically secure random nonce encoded as hex.
 *
 * @param out_hex Output buffer for hex-encoded nonce.
 * @param out_len Length of the output buffer (must be at least nonce_bytes * 2 + 1).
 * @param nonce_bytes Number of random bytes to generate (must be between 16 and 64).
 * @return enum vantaq_crypto_status
 */
enum vantaq_crypto_status vantaq_crypto_generate_nonce_hex(char *out_hex, size_t out_len,
                                                           size_t nonce_bytes);

#endif
