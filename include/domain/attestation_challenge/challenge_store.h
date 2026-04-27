// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_DOMAIN_ATTESTATION_CHALLENGE_CHALLENGE_STORE_H
#define VANTAQ_DOMAIN_ATTESTATION_CHALLENGE_CHALLENGE_STORE_H

#include "domain/attestation_challenge/challenge.h"
#include <stddef.h>

enum vantaq_challenge_store_status {
    VANTAQ_CHALLENGE_STORE_OK = 0,
    VANTAQ_CHALLENGE_STORE_ERROR_GLOBAL_CAPACITY_REACHED,
    VANTAQ_CHALLENGE_STORE_ERROR_VERIFIER_CAPACITY_REACHED,
    VANTAQ_CHALLENGE_STORE_ERROR_NOT_FOUND,
    VANTAQ_CHALLENGE_STORE_ERROR_INTERNAL,
};

struct vantaq_challenge_store {
    enum vantaq_challenge_store_status (*insert)(struct vantaq_challenge_store *store, struct vantaq_challenge *challenge);
    struct vantaq_challenge* (*lookup)(struct vantaq_challenge_store *store, const char *challenge_id);
    size_t (*count_pending_for_verifier)(struct vantaq_challenge_store *store, const char *verifier_id);
    size_t (*count_global_pending)(struct vantaq_challenge_store *store);
    void (*cleanup_expired)(struct vantaq_challenge_store *store, long current_time_ms);
    void (*destroy)(struct vantaq_challenge_store *store);
    void *ctx;
};

#endif
