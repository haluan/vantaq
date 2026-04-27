// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/security/verifier_lookup.h"
#include <string.h>

enum vantaq_verifier_status_code
vantaq_verifier_lookup_status(const struct vantaq_runtime_config *config, const char *verifier_id) {
    size_t count;
    size_t i;

    if (config == NULL || verifier_id == NULL) {
        return VANTAQ_VERIFIER_STATUS_UNKNOWN;
    }

    count = vantaq_runtime_verifier_count(config);
    for (i = 0; i < count; i++) {
        const char *id = vantaq_runtime_verifier_id(config, i);
        if (id != NULL && strcmp(id, verifier_id) == 0) {
            const char *status = vantaq_runtime_verifier_status(config, i);
            if (status != NULL) {
                if (strcmp(status, "active") == 0) {
                    return VANTAQ_VERIFIER_STATUS_ACTIVE;
                } else if (strcmp(status, "inactive") == 0) {
                    return VANTAQ_VERIFIER_STATUS_INACTIVE;
                }
            }
        }
    }

    return VANTAQ_VERIFIER_STATUS_UNKNOWN;
}
