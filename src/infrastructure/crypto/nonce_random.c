// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/crypto/nonce_random.h"
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
    enum vantaq_crypto_status status = VANTAQ_CRYPTO_OK;
    unsigned char *raw_bytes         = NULL;

    if (!out_hex || nonce_bytes < 8 || out_len < (nonce_bytes * 2 + 1)) {
        return VANTAQ_CRYPTO_ERROR_INVALID_ARGS;
    }

    raw_bytes = malloc(nonce_bytes);
    if (!raw_bytes) {
        return VANTAQ_CRYPTO_ERROR_MALLOC_FAILED;
    }

#ifdef __linux__
    ssize_t ret = getrandom(raw_bytes, nonce_bytes, 0);
    if (ret < 0 || (size_t)ret != nonce_bytes) {
        status = VANTAQ_CRYPTO_ERROR_RNG_FAILED;
        goto cleanup;
    }
#else
    if (RAND_bytes(raw_bytes, (int)nonce_bytes) != 1) {
        status = VANTAQ_CRYPTO_ERROR_RNG_FAILED;
        goto cleanup;
    }
#endif

    for (size_t i = 0; i < nonce_bytes; i++) {
        snprintf(out_hex + (i * 2), 3, "%02x", raw_bytes[i]);
    }
    out_hex[nonce_bytes * 2] = '\0';

cleanup:
    if (raw_bytes) {
        free(raw_bytes);
    }
    return status;
}
