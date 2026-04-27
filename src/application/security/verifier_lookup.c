// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/security/verifier_lookup.h"
#include <string.h>

enum vantaq_verifier_status_code
vantaq_verifier_lookup_status(const struct vantaq_runtime_config *config, const char *verifier_id) {
    size_t count;
    size_t i;

    /* Explicit input validation including empty string check */
    if (config == NULL || verifier_id == NULL || verifier_id[0] == '\0') {
        return VANTAQ_VERIFIER_STATUS_INVALID_ARGUMENT;
    }

    count = vantaq_runtime_verifier_count(config);
    for (i = 0; i < count; i++) {
        const char *id = vantaq_runtime_verifier_id(config, i);
        if (id != NULL && strcmp(id, verifier_id) == 0) {
            const char *status_str = vantaq_runtime_verifier_status(config, i);

            /* Early exit once ID is matched, regardless of status validity */
            if (status_str == NULL) {
                return VANTAQ_VERIFIER_STATUS_MISCONFIGURED;
            }

            /* S-1, D-1: Use shared constants for status strings */
            if (strcmp(status_str, VANTAQ_VERIFIER_STATUS_STR_ACTIVE) == 0) {
                return VANTAQ_VERIFIER_STATUS_ACTIVE;
            } else if (strcmp(status_str, VANTAQ_VERIFIER_STATUS_STR_INACTIVE) == 0) {
                return VANTAQ_VERIFIER_STATUS_INACTIVE;
            }

            /* Unrecognized status string */
            return VANTAQ_VERIFIER_STATUS_MISCONFIGURED;
        }
    }

    /* ID not found in config */
    return VANTAQ_VERIFIER_STATUS_NOT_FOUND;
}
