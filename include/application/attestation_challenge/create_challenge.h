// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_APPLICATION_ATTESTATION_CHALLENGE_CREATE_CHALLENGE_H
#define VANTAQ_APPLICATION_ATTESTATION_CHALLENGE_CREATE_CHALLENGE_H

#include "domain/attestation_challenge/challenge.h"
#include "domain/attestation_challenge/challenge_store.h"

enum vantaq_create_challenge_status {
    VANTAQ_CREATE_CHALLENGE_STATUS_OK = 0,
    VANTAQ_CREATE_CHALLENGE_STATUS_ERROR_INVALID_ARGS,
    VANTAQ_CREATE_CHALLENGE_STATUS_ERROR_CRYPTO,
    VANTAQ_CREATE_CHALLENGE_STATUS_ERROR_STORE_FULL,  /* C-2: Global capacity reached */
    VANTAQ_CREATE_CHALLENGE_STATUS_ERROR_STORE_QUOTA, /* C-2: Verifier quota reached */
    VANTAQ_CREATE_CHALLENGE_STATUS_ERROR_INTERNAL,
};

/**
 * @brief Create and store a new attestation challenge.
 *
 * @param store Challenge store instance.
 * @param verifier_id Authenticated verifier ID.
 * @param purpose Purpose string (e.g., "remote_attestation").
 * @param ttl_seconds Challenge TTL in seconds.
 * @param out_challenge Out-parameter for the created challenge.
 * @return enum vantaq_create_challenge_status
 */
enum vantaq_create_challenge_status
vantaq_create_challenge(struct vantaq_challenge_store *store, const char *verifier_id,
                        const char *purpose, long ttl_seconds,
                        struct vantaq_challenge **out_challenge);

#endif
