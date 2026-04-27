// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "domain/verifier_access/verifier_policy.h"
#include "infrastructure/config_loader.h"
#include <stddef.h>
#include <string.h>

#define VANTAQ_ROLE_OWNER_ADMIN "owner-admin"

/* Private Helpers */

static bool is_owner_admin(const struct vantaq_runtime_config *config,
                           const struct vantaq_verifier_identity *identity) {
    size_t v_count, v_idx;
    if (config == NULL || identity == NULL || identity->id[0] == '\0') {
        return false;
    }

    v_count = vantaq_runtime_verifier_count(config);
    for (v_idx = 0; v_idx < v_count; v_idx++) {
        const char *id = vantaq_runtime_verifier_id(config, v_idx);
        if (id != NULL && strcmp(id, identity->id) == 0) {
            size_t r_count, r_idx;
            r_count = vantaq_runtime_verifier_role_count(config, v_idx);
            for (r_idx = 0; r_idx < r_count; r_idx++) {
                const char *role = vantaq_runtime_verifier_role_item(config, v_idx, r_idx);
                if (role != NULL && strcmp(role, VANTAQ_ROLE_OWNER_ADMIN) == 0) {
                    return true;
                }
            }
            break; /* Found verifier, no need to scan further */
        }
    }
    return false;
}

/* Default VTable Implementation */

static enum vantaq_verifier_policy_decision
default_evaluate(const struct vantaq_verifier_identity *identity,
                 enum vantaq_verifier_status_code status) {

    /* Explicitly guard against empty identity strings */
    if (identity == NULL || identity->id[0] == '\0') {
        return VANTAQ_VERIFIER_POLICY_REJECT_MISSING_ID;
    }

    switch (status) {
    case VANTAQ_VERIFIER_STATUS_ACTIVE:
        return VANTAQ_VERIFIER_POLICY_ALLOW;

    case VANTAQ_VERIFIER_STATUS_INACTIVE:
        return VANTAQ_VERIFIER_POLICY_REJECT_INACTIVE;

    case VANTAQ_VERIFIER_STATUS_NOT_FOUND:
    case VANTAQ_VERIFIER_STATUS_MISCONFIGURED:
    case VANTAQ_VERIFIER_STATUS_INVALID_ARGUMENT:
    case VANTAQ_VERIFIER_STATUS_UNKNOWN:
        return VANTAQ_VERIFIER_POLICY_REJECT_UNKNOWN;

    /* Separate default case to catch unhandled enum values at compile-time */
    default:
        return VANTAQ_VERIFIER_POLICY_REJECT_UNKNOWN;
    }
}

static enum vantaq_verifier_policy_decision
default_can_read_metadata(const struct vantaq_runtime_config *config,
                          const struct vantaq_verifier_identity *caller_identity,
                          const char *target_verifier_id) {

    /* Return specific rejection codes for parameter/identity failures */
    if (caller_identity == NULL || caller_identity->id[0] == '\0') {
        return VANTAQ_VERIFIER_POLICY_REJECT_MISSING_ID;
    }

    if (config == NULL || target_verifier_id == NULL || target_verifier_id[0] == '\0') {
        return VANTAQ_VERIFIER_POLICY_REJECT_UNKNOWN;
    }

    /* Domain layer owns the "owner-admin" privilege evaluation */
    if (is_owner_admin(config, caller_identity)) {
        return VANTAQ_VERIFIER_POLICY_ALLOW;
    }

    /* Standard ownership check: A verifier can always read its own metadata */
    if (strcmp(caller_identity->id, target_verifier_id) == 0) {
        return VANTAQ_VERIFIER_POLICY_ALLOW;
    }

    return VANTAQ_VERIFIER_POLICY_REJECT_UNKNOWN;
}

static const struct vantaq_verifier_policy_ops g_default_ops = {
    .evaluate = default_evaluate, .can_read_metadata = default_can_read_metadata};

/* API Implementation */

const struct vantaq_verifier_policy_ops *vantaq_verifier_policy_ops_default(void) {
    return &g_default_ops;
}

enum vantaq_verifier_policy_decision
vantaq_verifier_policy_evaluate(const struct vantaq_verifier_identity *identity,
                                enum vantaq_verifier_status_code status) {
    return g_default_ops.evaluate(identity, status);
}

enum vantaq_verifier_policy_decision
vantaq_verifier_policy_can_read_metadata(const struct vantaq_runtime_config *config,
                                         const struct vantaq_verifier_identity *caller_identity,
                                         const char *target_verifier_id) {
    return g_default_ops.can_read_metadata(config, caller_identity, target_verifier_id);
}
