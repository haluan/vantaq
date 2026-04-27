// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_DOMAIN_VERIFIER_ACCESS_VERIFIER_POLICY_H
#define VANTAQ_DOMAIN_VERIFIER_ACCESS_VERIFIER_POLICY_H

#include "domain/verifier_access/verifier_identity.h"

#include <stdbool.h>

#define VANTAQ_VERIFIER_STATUS_STR_ACTIVE "active"
#define VANTAQ_VERIFIER_STATUS_STR_INACTIVE "inactive"

enum vantaq_verifier_status_code {
    VANTAQ_VERIFIER_STATUS_UNKNOWN = 0,
    VANTAQ_VERIFIER_STATUS_ACTIVE,
    VANTAQ_VERIFIER_STATUS_INACTIVE,
    VANTAQ_VERIFIER_STATUS_NOT_FOUND,
    VANTAQ_VERIFIER_STATUS_MISCONFIGURED,
    VANTAQ_VERIFIER_STATUS_INVALID_ARGUMENT
};

enum vantaq_verifier_policy_decision {
    VANTAQ_VERIFIER_POLICY_REJECT_UNKNOWN = 0, /* Secure Default: 0 results in rejection */
    VANTAQ_VERIFIER_POLICY_ALLOW,
    VANTAQ_VERIFIER_POLICY_REJECT_INACTIVE,
    VANTAQ_VERIFIER_POLICY_REJECT_MISSING_ID
};

struct vantaq_runtime_config;

/* VTable for Policy Operations (for Mocking and Injection) */
struct vantaq_verifier_policy_ops {
    enum vantaq_verifier_policy_decision (*evaluate)(
        const struct vantaq_verifier_identity *identity, enum vantaq_verifier_status_code status);

    enum vantaq_verifier_policy_decision (*can_read_metadata)(
        const struct vantaq_runtime_config *config,
        const struct vantaq_verifier_identity *caller_identity, const char *target_verifier_id);
};

/* Singleton access to default policy operations */
const struct vantaq_verifier_policy_ops *vantaq_verifier_policy_ops_default(void);

/* Free functions (thin wrappers around the default VTable) */
enum vantaq_verifier_policy_decision
vantaq_verifier_policy_evaluate(const struct vantaq_verifier_identity *identity,
                                enum vantaq_verifier_status_code status);

enum vantaq_verifier_policy_decision
vantaq_verifier_policy_can_read_metadata(const struct vantaq_runtime_config *config,
                                         const struct vantaq_verifier_identity *caller_identity,
                                         const char *target_verifier_id);

#endif
