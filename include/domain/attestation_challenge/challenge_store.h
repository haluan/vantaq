// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_DOMAIN_ATTESTATION_CHALLENGE_CHALLENGE_STORE_H
#define VANTAQ_DOMAIN_ATTESTATION_CHALLENGE_CHALLENGE_STORE_H

#include "domain/attestation_challenge/challenge.h"

#include <stdbool.h>
#include <stddef.h>

/**
 * D-8: Opaque challenge store interface to ensure ABI stability and encapsulation.
 * All operations must be performed via the typed API functions.
 */
struct vantaq_challenge_store;

enum vantaq_challenge_store_status {
    VANTAQ_CHALLENGE_STORE_OK = 0,
    VANTAQ_CHALLENGE_STORE_ERROR_GLOBAL_CAPACITY_REACHED,
    VANTAQ_CHALLENGE_STORE_ERROR_VERIFIER_CAPACITY_REACHED,
    VANTAQ_CHALLENGE_STORE_ERROR_NOT_FOUND,
    VANTAQ_CHALLENGE_STORE_ERROR_EXPIRED,
    VANTAQ_CHALLENGE_STORE_ERROR_INTERNAL,
    VANTAQ_CHALLENGE_STORE_ERROR_INVALID_ARGUMENT,
};

/**
 * @brief Insert a challenge into the store.
 * D-2: Implementation should perform internal cleanup of expired entries before insertion.
 */
enum vantaq_challenge_store_status
vantaq_challenge_store_insert(struct vantaq_challenge_store *store,
                              struct vantaq_challenge *challenge);

/**
 * @brief Find and optionally consume a challenge.
 * D-1: This combines lookup and mark-used into a single atomic operation to prevent TOCTOU.
 * @param challenge_id ID to search for.
 * @param current_time_ms Current time for expiry check.
 * @param consume If true, the challenge will be marked as used (atomic).
 * @param out_challenge If found, the challenge pointer is written here (borrowed).
 */
enum vantaq_challenge_store_status
vantaq_challenge_store_find_and_consume(struct vantaq_challenge_store *store,
                                        const char *challenge_id, long current_time_ms,
                                        bool consume, struct vantaq_challenge **out_challenge);

/**
 * @brief Remove a challenge from the store immediately.
 * D-4: Allows reclaiming slots before TTL expiry.
 */
enum vantaq_challenge_store_status
vantaq_challenge_store_remove(struct vantaq_challenge_store *store, const char *challenge_id);

/**
 * @brief Count pending challenges.
 */
size_t vantaq_challenge_store_count_pending_for_verifier(struct vantaq_challenge_store *store,
                                                         const char *verifier_id);
size_t vantaq_challenge_store_count_global_pending(struct vantaq_challenge_store *store);

/**
 * @brief Destroy the store and release all resources.
 */
void vantaq_challenge_store_destroy(struct vantaq_challenge_store *store);

#endif
