// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "domain/attestation_challenge/challenge.h"
#include "infrastructure/memory/zero_struct.h"

#include <assert.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

struct vantaq_challenge {
    char challenge_id[VANTAQ_CHALLENGE_ID_MAX];
    char nonce_hex[VANTAQ_NONCE_HEX_MAX];
    char verifier_id[VANTAQ_VERIFIER_ID_MAX];
    char purpose[VANTAQ_PURPOSE_MAX];
    long created_at_ms;
    long expires_at_ms;

    /* S-2, C-1, D-2: Atomic used flag prevents TOCTOU double-spend replay attacks */
    _Atomic bool used;
};

struct vantaq_challenge *vantaq_challenge_create(const char *challenge_id, const char *nonce_hex,
                                                 const char *verifier_id, const char *purpose,
                                                 long created_at_ms, long expires_at_ms) {
    if (challenge_id == NULL || nonce_hex == NULL || verifier_id == NULL || purpose == NULL) {
        return NULL;
    }

    if (challenge_id[0] == '\0' || nonce_hex[0] == '\0' || verifier_id[0] == '\0' ||
        purpose[0] == '\0') {
        return NULL;
    }

    /* S-1, D-3: Strict length invariants rather than silent truncation */
    if (strlen(challenge_id) >= VANTAQ_CHALLENGE_ID_MAX ||
        strlen(nonce_hex) >= VANTAQ_NONCE_HEX_MAX ||
        strlen(verifier_id) >= VANTAQ_VERIFIER_ID_MAX || strlen(purpose) >= VANTAQ_PURPOSE_MAX) {
        return NULL;
    }

    /* C-2, E-3: Validate temporal logic */
    if (created_at_ms < 0 || expires_at_ms <= created_at_ms) {
        return NULL;
    }

    struct vantaq_challenge *challenge = malloc(sizeof(struct vantaq_challenge));
    if (!challenge) {
        return NULL;
    }

    /* C-3, D-1: Use shared zero-struct macro */
    VANTAQ_ZERO_STRUCT(*challenge);

    strncpy(challenge->challenge_id, challenge_id, VANTAQ_CHALLENGE_ID_MAX - 1);
    strncpy(challenge->nonce_hex, nonce_hex, VANTAQ_NONCE_HEX_MAX - 1);
    strncpy(challenge->verifier_id, verifier_id, VANTAQ_VERIFIER_ID_MAX - 1);
    strncpy(challenge->purpose, purpose, VANTAQ_PURPOSE_MAX - 1);

    challenge->created_at_ms = created_at_ms;
    challenge->expires_at_ms = expires_at_ms;
    atomic_init(&challenge->used, false);

    return challenge;
}

void vantaq_challenge_destroy(struct vantaq_challenge *challenge) {
    if (challenge) {
        /*Secure explicit memory wipe for cryptographic material before free */
        vantaq_explicit_bzero(challenge, sizeof(*challenge));
        free(challenge);
    }
}

bool vantaq_challenge_is_expired(const struct vantaq_challenge *challenge, long current_time_ms) {
    assert(challenge != NULL);
    if (!challenge)
        return false;

    return current_time_ms >= challenge->expires_at_ms;
}

bool vantaq_challenge_is_used(const struct vantaq_challenge *challenge) {
    assert(challenge != NULL);
    if (!challenge)
        return false;

    /* Atomic read */
    return atomic_load_explicit(&challenge->used, memory_order_acquire);
}

bool vantaq_challenge_mark_used(struct vantaq_challenge *challenge) {
    assert(challenge != NULL);
    if (!challenge)
        return false;

    /* Atomic test-and-set. Returns true ONLY if we successfully transitioned false->true */
    bool expected = false;
    return atomic_compare_exchange_strong_explicit(&challenge->used, &expected, true,
                                                   memory_order_acq_rel, memory_order_acquire);
}

const char *vantaq_challenge_get_id(const struct vantaq_challenge *challenge) {
    /* Surface null pointer bugs at the call site */
    assert(challenge != NULL);
    return challenge ? challenge->challenge_id : NULL;
}

const char *vantaq_challenge_get_nonce_hex(const struct vantaq_challenge *challenge) {
    assert(challenge != NULL);
    return challenge ? challenge->nonce_hex : NULL;
}

const char *vantaq_challenge_get_verifier_id(const struct vantaq_challenge *challenge) {
    assert(challenge != NULL);
    return challenge ? challenge->verifier_id : NULL;
}

const char *vantaq_challenge_get_purpose(const struct vantaq_challenge *challenge) {
    assert(challenge != NULL);
    return challenge ? challenge->purpose : NULL;
}

long vantaq_challenge_get_created_at_ms(const struct vantaq_challenge *challenge) {
    /*Symmetric accessor */
    assert(challenge != NULL);
    return challenge ? challenge->created_at_ms : 0;
}

long vantaq_challenge_get_expires_at_ms(const struct vantaq_challenge *challenge) {
    assert(challenge != NULL);
    return challenge ? challenge->expires_at_ms : 0;
}
