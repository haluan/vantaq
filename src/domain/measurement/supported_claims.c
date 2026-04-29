// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "domain/measurement/supported_claims.h"

#include <string.h>

#define CLAIM_DEVICE_IDENTITY "device_identity"
#define CLAIM_FIRMWARE_HASH "firmware_hash"
#define CLAIM_CONFIG_HASH "config_hash"
#define CLAIM_AGENT_INTEGRITY "agent_integrity"
#define CLAIM_BOOT_STATE "boot_state"

bool vantaq_supported_claim_is_known(const char *claim) {
    if (claim == NULL || claim[0] == '\0') {
        return false;
    }

    return strcmp(claim, CLAIM_DEVICE_IDENTITY) == 0 || strcmp(claim, CLAIM_FIRMWARE_HASH) == 0 ||
           strcmp(claim, CLAIM_CONFIG_HASH) == 0 || strcmp(claim, CLAIM_AGENT_INTEGRITY) == 0 ||
           strcmp(claim, CLAIM_BOOT_STATE) == 0;
}
