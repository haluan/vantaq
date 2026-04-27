// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_DOMAIN_ATTESTATION_CHALLENGE_CHALLENGE_H
#define VANTAQ_DOMAIN_ATTESTATION_CHALLENGE_CHALLENGE_H

#include <stdbool.h>
#include <stddef.h>

#define VANTAQ_CHALLENGE_ID_MAX 64
#define VANTAQ_NONCE_HEX_MAX 65
#define VANTAQ_VERIFIER_ID_MAX 128
#define VANTAQ_PURPOSE_MAX 64

struct vantaq_challenge;

/**
 * @brief Create a challenge object.
 *
 * @param challenge_id Unique ID for this challenge.
 * @param nonce_hex Hex-encoded random nonce.
 * @param verifier_id Authenticated verifier ID.
 * @param purpose Purpose of the challenge (e.g., "remote_attestation").
 * @param created_at_ms Creation timestamp in epoch ms.
 * @param expires_at_ms Expiry timestamp in epoch ms.
 * @return struct vantaq_challenge* Pointer to new challenge, or NULL on failure.
 */
struct vantaq_challenge *vantaq_challenge_create(const char *challenge_id, const char *nonce_hex,
                                                 const char *verifier_id, const char *purpose,
                                                 long created_at_ms, long expires_at_ms);

/**
 * @brief Destroy a challenge object.
 */
void vantaq_challenge_destroy(struct vantaq_challenge *challenge);

/**
 * @brief Check if the challenge is expired based on current time.
 */
bool vantaq_challenge_is_expired(const struct vantaq_challenge *challenge, long current_time_ms);

/**
 * @brief Check if the challenge has been marked as used.
 */
bool vantaq_challenge_is_used(const struct vantaq_challenge *challenge);

/**
 * @brief Mark the challenge as used.
 */
void vantaq_challenge_mark_used(struct vantaq_challenge *challenge);

/**
 * @brief Getters for challenge fields (since struct is opaque).
 */
const char *vantaq_challenge_get_id(const struct vantaq_challenge *challenge);
const char *vantaq_challenge_get_nonce_hex(const struct vantaq_challenge *challenge);
const char *vantaq_challenge_get_verifier_id(const struct vantaq_challenge *challenge);
const char *vantaq_challenge_get_purpose(const struct vantaq_challenge *challenge);
long vantaq_challenge_get_expires_at_ms(const struct vantaq_challenge *challenge);

#endif
