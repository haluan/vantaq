// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "domain/attestation_challenge/challenge.h"
#include <stdlib.h>
#include <string.h>

struct vantaq_challenge {
    char challenge_id[VANTAQ_CHALLENGE_ID_MAX];
    char nonce_hex[VANTAQ_NONCE_HEX_MAX];
    char verifier_id[VANTAQ_VERIFIER_ID_MAX];
    char purpose[VANTAQ_PURPOSE_MAX];
    long created_at_ms;
    long expires_at_ms;
    bool used;
};

#define VANTAQ_ZERO_STRUCT(s) memset(&(s), 0, sizeof(s))

struct vantaq_challenge *vantaq_challenge_create(const char *challenge_id, const char *nonce_hex,
                                                 const char *verifier_id, const char *purpose,
                                                 long created_at_ms, long expires_at_ms) {
    if (!challenge_id || !nonce_hex || !verifier_id || !purpose) {
        return NULL;
    }

    struct vantaq_challenge *challenge = malloc(sizeof(struct vantaq_challenge));
    if (!challenge) {
        return NULL;
    }

    VANTAQ_ZERO_STRUCT(*challenge);

    strncpy(challenge->challenge_id, challenge_id, VANTAQ_CHALLENGE_ID_MAX - 1);
    strncpy(challenge->nonce_hex, nonce_hex, VANTAQ_NONCE_HEX_MAX - 1);
    strncpy(challenge->verifier_id, verifier_id, VANTAQ_VERIFIER_ID_MAX - 1);
    strncpy(challenge->purpose, purpose, VANTAQ_PURPOSE_MAX - 1);

    challenge->created_at_ms = created_at_ms;
    challenge->expires_at_ms = expires_at_ms;
    challenge->used          = false;

    return challenge;
}

void vantaq_challenge_destroy(struct vantaq_challenge *challenge) {
    if (challenge) {
        free(challenge);
    }
}

bool vantaq_challenge_is_expired(const struct vantaq_challenge *challenge, long current_time_ms) {
    if (!challenge) {
        return true;
    }
    return current_time_ms >= challenge->expires_at_ms;
}

bool vantaq_challenge_is_used(const struct vantaq_challenge *challenge) {
    return challenge ? challenge->used : false;
}

void vantaq_challenge_mark_used(struct vantaq_challenge *challenge) {
    if (challenge) {
        challenge->used = true;
    }
}

const char *vantaq_challenge_get_id(const struct vantaq_challenge *challenge) {
    return challenge ? challenge->challenge_id : NULL;
}

const char *vantaq_challenge_get_nonce_hex(const struct vantaq_challenge *challenge) {
    return challenge ? challenge->nonce_hex : NULL;
}

const char *vantaq_challenge_get_verifier_id(const struct vantaq_challenge *challenge) {
    return challenge ? challenge->verifier_id : NULL;
}

const char *vantaq_challenge_get_purpose(const struct vantaq_challenge *challenge) {
    return challenge ? challenge->purpose : NULL;
}

long vantaq_challenge_get_expires_at_ms(const struct vantaq_challenge *challenge) {
    return challenge ? challenge->expires_at_ms : 0;
}
