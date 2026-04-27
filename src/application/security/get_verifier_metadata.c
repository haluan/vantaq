// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/security/get_verifier_metadata.h"
#include <string.h>

enum vantaq_verifier_metadata_status
vantaq_get_verifier_metadata(const struct vantaq_runtime_config *config,
                             const struct vantaq_verifier_identity *caller_identity,
                             const char *target_verifier_id,
                             struct vantaq_verifier_metadata_dto *out_dto) {
    size_t verifiers_count;
    size_t i;
    int target_index           = -1;
    bool caller_is_owner_admin = false;

    if (config == NULL || caller_identity == NULL || target_verifier_id == NULL ||
        out_dto == NULL) {
        return VANTAQ_VERIFIER_METADATA_INTERNAL_ERROR;
    }

    verifiers_count = vantaq_runtime_verifier_count(config);

    // 1. Find target and check if caller is owner-admin
    for (i = 0; i < verifiers_count; i++) {
        const char *id = vantaq_runtime_verifier_id(config, i);
        if (id == NULL)
            continue;

        if (strcmp(id, target_verifier_id) == 0) {
            target_index = (int)i;
        }

        if (strcmp(id, caller_identity->id) == 0) {
            size_t role_count = vantaq_runtime_verifier_role_count(config, i);
            size_t role_idx;
            for (role_idx = 0; role_idx < role_count; role_idx++) {
                const char *role = vantaq_runtime_verifier_role_item(config, i, role_idx);
                if (role != NULL && strcmp(role, "owner-admin") == 0) {
                    caller_is_owner_admin = true;
                    break;
                }
            }
        }
    }

    if (target_index == -1) {
        return VANTAQ_VERIFIER_METADATA_NOT_FOUND;
    }

    // 2. Authorization
    if (!vantaq_verifier_policy_can_read_metadata(caller_identity, target_verifier_id,
                                                  caller_is_owner_admin)) {
        return VANTAQ_VERIFIER_METADATA_FORBIDDEN;
    }

    // 3. Populate DTO
    memset(out_dto, 0, sizeof(*out_dto));
    strncpy(out_dto->verifier_id, target_verifier_id, sizeof(out_dto->verifier_id) - 1);

    const char *status = vantaq_runtime_verifier_status(config, (size_t)target_index);
    if (status != NULL) {
        strncpy(out_dto->status, status, sizeof(out_dto->status) - 1);
    }

    out_dto->roles_count = vantaq_runtime_verifier_role_count(config, (size_t)target_index);
    for (i = 0; i < out_dto->roles_count && i < VANTAQ_MAX_LIST_ITEMS; i++) {
        out_dto->roles[i] = vantaq_runtime_verifier_role_item(config, (size_t)target_index, i);
    }

    out_dto->allowed_apis_count =
        vantaq_runtime_verifier_allowed_api_count(config, (size_t)target_index);
    for (i = 0; i < out_dto->allowed_apis_count && i < VANTAQ_MAX_LIST_ITEMS; i++) {
        out_dto->allowed_apis[i] =
            vantaq_runtime_verifier_allowed_api_item(config, (size_t)target_index, i);
    }

    return VANTAQ_VERIFIER_METADATA_OK;
}
