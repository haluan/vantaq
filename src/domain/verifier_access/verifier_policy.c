// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "domain/verifier_access/verifier_policy.h"
#include <stddef.h>

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
