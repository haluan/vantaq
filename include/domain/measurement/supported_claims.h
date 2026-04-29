// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_DOMAIN_MEASUREMENT_SUPPORTED_CLAIMS_H
#define VANTAQ_DOMAIN_MEASUREMENT_SUPPORTED_CLAIMS_H

#include <stdbool.h>

/** Maximum supported claim name length in bytes (excluding the terminating NUL). */
#define VANTAQ_SUPPORTED_CLAIM_NAME_MAX 64
/** Alias for buffers that hold claim names (same bound as @ref VANTAQ_SUPPORTED_CLAIM_NAME_MAX). */
#define VANTAQ_CLAIM_NAME_MAX VANTAQ_SUPPORTED_CLAIM_NAME_MAX

extern const char *const VANTAQ_CLAIM_DEVICE_IDENTITY;
extern const char *const VANTAQ_CLAIM_FIRMWARE_HASH;
extern const char *const VANTAQ_CLAIM_CONFIG_HASH;
extern const char *const VANTAQ_CLAIM_AGENT_INTEGRITY;
extern const char *const VANTAQ_CLAIM_BOOT_STATE;

typedef enum {
    VANTAQ_SUPPORTED_CLAIM_ID_UNKNOWN = 0,
    VANTAQ_SUPPORTED_CLAIM_ID_DEVICE_IDENTITY,
    VANTAQ_SUPPORTED_CLAIM_ID_FIRMWARE_HASH,
    VANTAQ_SUPPORTED_CLAIM_ID_CONFIG_HASH,
    VANTAQ_SUPPORTED_CLAIM_ID_AGENT_INTEGRITY,
    VANTAQ_SUPPORTED_CLAIM_ID_BOOT_STATE,
} vantaq_supported_claim_id_t;

/**
 * Resolves claim to a stable id, or @ref VANTAQ_SUPPORTED_CLAIM_ID_UNKNOWN.
 *
 * Matching is exact and case-sensitive; surrounding whitespace is not stripped — callers must
 * normalize when reading user or config input.
 *
 * At most @ref VANTAQ_SUPPORTED_CLAIM_NAME_MAX + 1 bytes are read from claim via strnlen (no
 * unbounded strcmp scan). If there is no NUL within the first @ref VANTAQ_SUPPORTED_CLAIM_NAME_MAX
 * + 1 bytes, the claim is rejected.
 */
vantaq_supported_claim_id_t vantaq_supported_claim_lookup(const char *claim);

/** Equivalent to `vantaq_supported_claim_lookup(claim) != VANTAQ_SUPPORTED_CLAIM_ID_UNKNOWN`. */
bool vantaq_supported_claim_is_known(const char *claim);

#endif
