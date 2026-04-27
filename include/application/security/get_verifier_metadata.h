// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_APPLICATION_SECURITY_GET_VERIFIER_METADATA_H
#define VANTAQ_APPLICATION_SECURITY_GET_VERIFIER_METADATA_H

#include "domain/verifier_access/verifier_policy.h"
#include "infrastructure/config_loader.h"

enum vantaq_verifier_metadata_status {
    VANTAQ_VERIFIER_METADATA_OK = 0,
    VANTAQ_VERIFIER_METADATA_NOT_FOUND,
    VANTAQ_VERIFIER_METADATA_FORBIDDEN,
    VANTAQ_VERIFIER_METADATA_INTERNAL_ERROR
};

struct vantaq_verifier_metadata_dto {
    char verifier_id[VANTAQ_MAX_FIELD_LEN];
    char status[VANTAQ_MAX_FIELD_LEN];
    const char *roles[VANTAQ_MAX_LIST_ITEMS];
    size_t roles_count;
    const char *allowed_apis[VANTAQ_MAX_LIST_ITEMS];
    size_t allowed_apis_count;
};

enum vantaq_verifier_metadata_status vantaq_get_verifier_metadata(
    const struct vantaq_runtime_config *config,
    const struct vantaq_verifier_identity *caller_identity, const char *target_verifier_id,
    struct vantaq_verifier_metadata_dto *out_dto);

#endif
