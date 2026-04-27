// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_DOMAIN_VERIFIER_ACCESS_VERIFIER_POLICY_H
#define VANTAQ_DOMAIN_VERIFIER_ACCESS_VERIFIER_POLICY_H

#include <stdbool.h>
#include "domain/verifier_access/verifier_identity.h"

enum vantaq_verifier_status_code {
    VANTAQ_VERIFIER_STATUS_UNKNOWN = 0,
    VANTAQ_VERIFIER_STATUS_ACTIVE,
    VANTAQ_VERIFIER_STATUS_INACTIVE
};

enum vantaq_verifier_policy_decision {
    VANTAQ_VERIFIER_POLICY_ALLOW = 0,
    VANTAQ_VERIFIER_POLICY_REJECT_UNKNOWN,
    VANTAQ_VERIFIER_POLICY_REJECT_INACTIVE,
    VANTAQ_VERIFIER_POLICY_REJECT_MISSING_ID
};

enum vantaq_verifier_policy_decision
vantaq_verifier_policy_evaluate(const struct vantaq_verifier_identity *identity,
                                enum vantaq_verifier_status_code status);

bool vantaq_verifier_policy_can_read_metadata(const struct vantaq_verifier_identity *caller_identity,
                                              const char *target_verifier_id,
                                              bool caller_is_owner_admin);

#endif
