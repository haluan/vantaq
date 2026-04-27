// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/crypto/nonce_random.h"
#include "infrastructure/memory/zero_struct.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__
#include <sys/random.h>
#include <unistd.h>
#else
#include <openssl/rand.h>
#endif

enum vantaq_crypto_status vantaq_crypto_generate_nonce_hex(char *out_hex, size_t out_len,
                                                           size_t nonce_bytes) {
    /* Use stack for bounded scratch buffer to eliminate malloc failure paths and heap risks */
    unsigned char raw_bytes[VANTAQ_NONCE_BYTES_MAX];
    enum vantaq_crypto_status status = VANTAQ_CRYPTO_OK;

    /* Defensive initialization */
    if (out_hex && out_len > 0) {
        out_hex[0] = '\0';
    }

    /* Strict input validation with upper and lower bounds */
    if (!out_hex || nonce_bytes < VANTAQ_NONCE_BYTES_MIN || nonce_bytes > VANTAQ_NONCE_BYTES_MAX ||
        out_len < (nonce_bytes * 2 + 1)) {
        return VANTAQ_CRYPTO_ERROR_INVALID_ARGS;
    }

#ifdef __linux__
    ssize_t ret;
    /* Retry on EINTR to handle signal interruptions during RNG calls */
    /* GRND_NONBLOCK ensures the server doesn't hang indefinitely on entropy starvation */
    do {
        ret = getrandom(raw_bytes, nonce_bytes, GRND_NONBLOCK);
    } while (ret < 0 && errno == EINTR);

    if (ret < 0 || (size_t)ret != nonce_bytes) {
        status = VANTAQ_CRYPTO_ERROR_RNG_FAILED;
        goto cleanup;
    }
#else
    /* No risk of truncation cast now that nonce_bytes is bounded to 64 */
    if (RAND_bytes(raw_bytes, (int)nonce_bytes) != 1) {
        status = VANTAQ_CRYPTO_ERROR_RNG_FAILED;
        goto cleanup;
    }
#endif

    for (size_t i = 0; i < nonce_bytes; i++) {
        (void)snprintf(out_hex + (i * 2), 3, "%02x", raw_bytes[i]);
    }
    out_hex[nonce_bytes * 2] = '\0';

cleanup:
    /* Secure memory wipe of intermediate entropy scratch before returning */
    vantaq_explicit_bzero(raw_bytes, sizeof(raw_bytes));
    return status;
}
