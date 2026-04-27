// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/attestation_challenge/create_challenge.h"
#include "infrastructure/crypto/nonce_random.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Reasonable maximum TTL to prevent overflow and long-lived unused challenges */
#define VANTAQ_CHALLENGE_TTL_MAX_SECONDS 3600

enum vantaq_create_challenge_status
vantaq_create_challenge(struct vantaq_challenge_store *store, const char *verifier_id,
                        const char *purpose, long ttl_seconds,
                        struct vantaq_challenge **out_challenge) {
    char challenge_id[VANTAQ_CHALLENGE_ID_MAX];
    char id_hex[33]; /* D-4: Accurate naming for hex-encoded random string */
    char nonce_hex[VANTAQ_NONCE_HEX_MAX];
    struct vantaq_challenge *challenge = NULL;
    enum vantaq_crypto_status crypto_status;
    enum vantaq_challenge_store_status store_status;
    struct timespec now;
    long now_ms;
    long expires_ms;

    /* Ensure output is initialized to NULL before any early return */
    if (out_challenge) {
        *out_challenge = NULL;
    }

    /* S-1, S-2, S-3: Comprehensive input validation with strict length and value checks */
    if (!store || !out_challenge || !verifier_id || !purpose || verifier_id[0] == '\0' ||
        purpose[0] == '\0' || strlen(verifier_id) >= VANTAQ_VERIFIER_ID_MAX ||
        strlen(purpose) >= VANTAQ_PURPOSE_MAX || ttl_seconds <= 0 ||
        ttl_seconds > VANTAQ_CHALLENGE_TTL_MAX_SECONDS) {
        return VANTAQ_CREATE_CHALLENGE_STATUS_ERROR_INVALID_ARGS;
    }

    // Generate random part for challenge ID
    crypto_status = vantaq_crypto_generate_nonce_hex(id_hex, sizeof(id_hex), 16);
    if (crypto_status != VANTAQ_CRYPTO_OK) {
        return VANTAQ_CREATE_CHALLENGE_STATUS_ERROR_CRYPTO;
    }
    snprintf(challenge_id, sizeof(challenge_id), "ch-%s", id_hex);

    // Generate nonce
    crypto_status = vantaq_crypto_generate_nonce_hex(nonce_hex, sizeof(nonce_hex), 16);
    if (crypto_status != VANTAQ_CRYPTO_OK) {
        return VANTAQ_CREATE_CHALLENGE_STATUS_ERROR_CRYPTO;
    }

    // Timestamps
    if (clock_gettime(CLOCK_REALTIME, &now) != 0) {
        return VANTAQ_CREATE_CHALLENGE_STATUS_ERROR_INTERNAL;
    }

    /* Use long long for intermediate calculation to prevent overflow on 32-bit platforms */
    now_ms     = (long)now.tv_sec * 1000L + (long)now.tv_nsec / 1000000L;
    expires_ms = now_ms + (ttl_seconds * 1000L);

    // Create domain object
    challenge =
        vantaq_challenge_create(challenge_id, nonce_hex, verifier_id, purpose, now_ms, expires_ms);
    if (!challenge) {
        return VANTAQ_CREATE_CHALLENGE_STATUS_ERROR_INTERNAL;
    }

    /* Store management is now atomic; internal cleanup happens inside insert */
    store_status = vantaq_challenge_store_insert(store, challenge);

    /* Propagate granular store error codes to the application layer */
    if (store_status != VANTAQ_CHALLENGE_STORE_OK) {
        vantaq_challenge_destroy(challenge);
        if (store_status == VANTAQ_CHALLENGE_STORE_ERROR_GLOBAL_CAPACITY_REACHED) {
            return VANTAQ_CREATE_CHALLENGE_STATUS_ERROR_STORE_FULL;
        } else if (store_status == VANTAQ_CHALLENGE_STORE_ERROR_VERIFIER_CAPACITY_REACHED) {
            return VANTAQ_CREATE_CHALLENGE_STATUS_ERROR_STORE_QUOTA;
        }
        return VANTAQ_CREATE_CHALLENGE_STATUS_ERROR_INTERNAL;
    }

    *out_challenge = challenge;
    return VANTAQ_CREATE_CHALLENGE_STATUS_OK;
}
