// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/attestation_challenge/create_challenge.h"
#include "infrastructure/crypto/nonce_random.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum vantaq_create_challenge_status
vantaq_create_challenge(struct vantaq_challenge_store *store, const char *verifier_id,
                        const char *purpose, long ttl_seconds,
                        struct vantaq_challenge **out_challenge) {
    char challenge_id[VANTAQ_CHALLENGE_ID_MAX];
    char id_rand[17];
    char nonce_hex[VANTAQ_NONCE_HEX_MAX];
    struct vantaq_challenge *challenge = NULL;
    enum vantaq_crypto_status crypto_status;
    enum vantaq_challenge_store_status store_status;
    struct timespec now;
    long now_ms;
    long expires_ms;

    if (!store || !verifier_id || verifier_id[0] == '\0' || !purpose || !out_challenge) {
        return VANTAQ_CREATE_CHALLENGE_STATUS_ERROR_INTERNAL;
    }

    // Generate random part for challenge ID
    crypto_status = vantaq_crypto_generate_nonce_hex(id_rand, sizeof(id_rand), 8);
    if (crypto_status != VANTAQ_CRYPTO_OK) {
        return VANTAQ_CREATE_CHALLENGE_STATUS_ERROR_CRYPTO;
    }
    snprintf(challenge_id, sizeof(challenge_id), "ch-%s", id_rand);

    // Generate nonce
    crypto_status = vantaq_crypto_generate_nonce_hex(nonce_hex, sizeof(nonce_hex), 16);
    if (crypto_status != VANTAQ_CRYPTO_OK) {
        return VANTAQ_CREATE_CHALLENGE_STATUS_ERROR_CRYPTO;
    }

    // Timestamps
    if (clock_gettime(CLOCK_REALTIME, &now) != 0) {
        return VANTAQ_CREATE_CHALLENGE_STATUS_ERROR_INTERNAL;
    }
    now_ms     = now.tv_sec * 1000L + now.tv_nsec / 1000000L;
    expires_ms = now_ms + ttl_seconds * 1000L;

    // Create domain object
    challenge =
        vantaq_challenge_create(challenge_id, nonce_hex, verifier_id, purpose, now_ms, expires_ms);
    if (!challenge) {
        return VANTAQ_CREATE_CHALLENGE_STATUS_ERROR_INTERNAL;
    }

    // Store it (cleanup expired first)
    store->cleanup_expired(store, now_ms);
    store_status = store->insert(store, challenge);
    if (store_status != VANTAQ_CHALLENGE_STORE_OK) {
        vantaq_challenge_destroy(challenge);
        return VANTAQ_CREATE_CHALLENGE_STATUS_ERROR_STORE;
    }

    *out_challenge = challenge;
    return VANTAQ_CREATE_CHALLENGE_STATUS_OK;
}
