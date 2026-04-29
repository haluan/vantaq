// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "domain/measurement/supported_claims.h"

#include <string.h>

const char *const VANTAQ_CLAIM_DEVICE_IDENTITY = "device_identity";
const char *const VANTAQ_CLAIM_FIRMWARE_HASH   = "firmware_hash";
const char *const VANTAQ_CLAIM_CONFIG_HASH     = "config_hash";
const char *const VANTAQ_CLAIM_AGENT_INTEGRITY = "agent_integrity";
const char *const VANTAQ_CLAIM_BOOT_STATE      = "boot_state";

static const struct {
    const char *name;
    vantaq_supported_claim_id_t id;
} k_known_claim_registry[] = {
    {VANTAQ_CLAIM_DEVICE_IDENTITY, VANTAQ_SUPPORTED_CLAIM_ID_DEVICE_IDENTITY},
    {VANTAQ_CLAIM_FIRMWARE_HASH, VANTAQ_SUPPORTED_CLAIM_ID_FIRMWARE_HASH},
    {VANTAQ_CLAIM_CONFIG_HASH, VANTAQ_SUPPORTED_CLAIM_ID_CONFIG_HASH},
    {VANTAQ_CLAIM_AGENT_INTEGRITY, VANTAQ_SUPPORTED_CLAIM_ID_AGENT_INTEGRITY},
    {VANTAQ_CLAIM_BOOT_STATE, VANTAQ_SUPPORTED_CLAIM_ID_BOOT_STATE},
};

vantaq_supported_claim_id_t vantaq_supported_claim_lookup(const char *claim) {
    size_t claim_len = 0U;
    size_t i         = 0U;

    if (claim == NULL || claim[0] == '\0') {
        return VANTAQ_SUPPORTED_CLAIM_ID_UNKNOWN;
    }

    claim_len = strnlen(claim, VANTAQ_SUPPORTED_CLAIM_NAME_MAX + 1U);
    if (claim_len == 0U || claim_len > VANTAQ_SUPPORTED_CLAIM_NAME_MAX) {
        return VANTAQ_SUPPORTED_CLAIM_ID_UNKNOWN;
    }

    for (i = 0U; i < (sizeof(k_known_claim_registry) / sizeof(k_known_claim_registry[0])); i++) {
        if (strcmp(claim, k_known_claim_registry[i].name) == 0) {
            return k_known_claim_registry[i].id;
        }
    }

    return VANTAQ_SUPPORTED_CLAIM_ID_UNKNOWN;
}

bool vantaq_supported_claim_is_known(const char *claim) {
    return vantaq_supported_claim_lookup(claim) != VANTAQ_SUPPORTED_CLAIM_ID_UNKNOWN;
}
