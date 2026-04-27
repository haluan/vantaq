// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "domain/verifier_access/verifier_policy.h"
#include <stddef.h>
#include <string.h>

enum vantaq_verifier_policy_decision
vantaq_verifier_policy_evaluate(const struct vantaq_verifier_identity *identity,
                                enum vantaq_verifier_status_code status) {
    if (identity == NULL || identity->id[0] == '\0') {
        return VANTAQ_VERIFIER_POLICY_REJECT_MISSING_ID;
    }

    switch (status) {
    case VANTAQ_VERIFIER_STATUS_ACTIVE:
        return VANTAQ_VERIFIER_POLICY_ALLOW;
    case VANTAQ_VERIFIER_STATUS_INACTIVE:
        return VANTAQ_VERIFIER_POLICY_REJECT_INACTIVE;
    case VANTAQ_VERIFIER_STATUS_UNKNOWN:
    default:
        return VANTAQ_VERIFIER_POLICY_REJECT_UNKNOWN;
    }
}

bool vantaq_verifier_policy_can_read_metadata(
    const struct vantaq_verifier_identity *caller_identity, const char *target_verifier_id,
    bool caller_is_owner_admin) {
    if (caller_identity == NULL || target_verifier_id == NULL) {
        return false;
    }

    if (caller_is_owner_admin) {
        return true;
    }

    if (strcmp(caller_identity->id, target_verifier_id) == 0) {
        return true;
    }

    return false;
}
