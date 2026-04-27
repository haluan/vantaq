// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/security/get_verifier_metadata.h"
#include "domain/verifier_access/verifier_policy.h"
#include "infrastructure/memory/zero_struct.h"

#include <string.h>

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

enum vantaq_verifier_metadata_status
vantaq_get_verifier_metadata(const struct vantaq_runtime_config *config,
                             const struct vantaq_verifier_identity *caller_identity,
                             const char *target_verifier_id,
                             struct vantaq_verifier_metadata_dto *out_dto) {
    size_t verifiers_count;
    size_t i;
    int target_index = -1;

    if (out_dto != NULL) {
        VANTAQ_ZERO_STRUCT(*out_dto);
        out_dto->cbSize = sizeof(struct vantaq_verifier_metadata_dto);
    }

    if (config == NULL || caller_identity == NULL || target_verifier_id == NULL ||
        out_dto == NULL || target_verifier_id[0] == '\0' || caller_identity->id[0] == '\0') {
        return VANTAQ_VERIFIER_METADATA_INTERNAL_ERROR;
    }

    /* 1. Authorization Evaluation (BEFORE target lookup to prevent ID enumeration)
     * A caller must be authorized to query the specific target.
     * If not authorized, we return FORBIDDEN regardless of whether the target exists.
     */
    enum vantaq_verifier_policy_decision decision =
        vantaq_verifier_policy_can_read_metadata(config, caller_identity, target_verifier_id);

    if (decision != VANTAQ_VERIFIER_POLICY_ALLOW) {
        if (decision == VANTAQ_VERIFIER_POLICY_REJECT_MISSING_ID) {
            return VANTAQ_VERIFIER_METADATA_UNAUTHORIZED;
        }
        return VANTAQ_VERIFIER_METADATA_FORBIDDEN;
    }

    /* 2. Find target verifier in configuration */
    verifiers_count = vantaq_runtime_verifier_count(config);
    for (i = 0; i < verifiers_count; i++) {
        const char *id = vantaq_runtime_verifier_id(config, i);
        if (id != NULL && strcmp(id, target_verifier_id) == 0) {
            target_index = (int)i;
            break;
        }
    }

    if (target_index == -1) {
        return VANTAQ_VERIFIER_METADATA_NOT_FOUND;
    }

    /* 3. Populate DTO with value copies
     * Copy values into DTO to prevent UAF risks on RCU swap.
     */
    strncpy(out_dto->verifier_id, target_verifier_id, sizeof(out_dto->verifier_id) - 1);

    const char *status = vantaq_runtime_verifier_status(config, (size_t)target_index);
    if (status != NULL) {
        strncpy(out_dto->status, status, sizeof(out_dto->status) - 1);
    }

    /* Clamped copying of roles and APIs */
    size_t raw_roles_count = vantaq_runtime_verifier_role_count(config, (size_t)target_index);
    out_dto->roles_count   = MIN(raw_roles_count, VANTAQ_MAX_LIST_ITEMS);

    for (i = 0; i < out_dto->roles_count; i++) {
        const char *role = vantaq_runtime_verifier_role_item(config, (size_t)target_index, i);
        if (role != NULL) {
            strncpy(out_dto->roles[i], role, sizeof(out_dto->roles[i]) - 1);
        }
    }

    size_t raw_apis_count = vantaq_runtime_verifier_allowed_api_count(config, (size_t)target_index);
    out_dto->allowed_apis_count = MIN(raw_apis_count, VANTAQ_MAX_LIST_ITEMS);

    for (i = 0; i < out_dto->allowed_apis_count; i++) {
        const char *api = vantaq_runtime_verifier_allowed_api_item(config, (size_t)target_index, i);
        if (api != NULL) {
            strncpy(out_dto->allowed_apis[i], api, sizeof(out_dto->allowed_apis[i]) - 1);
        }
    }

    return VANTAQ_VERIFIER_METADATA_OK;
}
