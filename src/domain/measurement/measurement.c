// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "domain/measurement/measurement.h"
#include "infrastructure/memory/zero_struct.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

struct vantaq_measurement_result {
    char claim_name[VANTAQ_MEASUREMENT_CLAIM_NAME_MAX];
    char value[VANTAQ_MEASUREMENT_VALUE_MAX];
    char source_path[VANTAQ_MEASUREMENT_SOURCE_PATH_MAX];
    vantaq_measurement_status_t status;
    vantaq_measurement_error_code_t error_code;
};

static vantaq_measurement_model_err_t validate_required_text(const char *value, size_t max_len) {
    size_t value_len   = 0U;
    bool has_non_space = false;

    if (value == NULL) {
        return VANTAQ_MEASUREMENT_MODEL_ERR_MISSING_FIELD;
    }
    if (value[0] == '\0') {
        return VANTAQ_MEASUREMENT_MODEL_ERR_MISSING_FIELD;
    }
    if (max_len == 0U) {
        return VANTAQ_MEASUREMENT_MODEL_ERR_INVALID_ARG;
    }

    value_len = strnlen(value, max_len);
    if (value_len >= max_len) {
        return VANTAQ_MEASUREMENT_MODEL_ERR_FIELD_TOO_LONG;
    }

    for (size_t i = 0; i < value_len; i++) {
        if (!isspace((unsigned char)value[i])) {
            has_non_space = true;
            break;
        }
    }
    if (!has_non_space) {
        return VANTAQ_MEASUREMENT_MODEL_ERR_MISSING_FIELD;
    }
    return VANTAQ_MEASUREMENT_MODEL_OK;
}

static struct vantaq_measurement_result *create_common(const char *claim_name,
                                                       const char *source_path,
                                                       vantaq_measurement_model_err_t *out_err) {
    vantaq_measurement_model_err_t err               = VANTAQ_MEASUREMENT_MODEL_OK;
    struct vantaq_measurement_result *created_result = NULL;

    if (out_err == NULL) {
        return NULL;
    }
    *out_err = VANTAQ_MEASUREMENT_MODEL_OK;

    err = validate_required_text(claim_name, VANTAQ_MEASUREMENT_CLAIM_NAME_MAX);
    if (err != VANTAQ_MEASUREMENT_MODEL_OK) {
        *out_err = err;
        return NULL;
    }

    err = validate_required_text(source_path, VANTAQ_MEASUREMENT_SOURCE_PATH_MAX);
    if (err != VANTAQ_MEASUREMENT_MODEL_OK) {
        *out_err = err;
        return NULL;
    }

    created_result = malloc(sizeof(struct vantaq_measurement_result));
    if (created_result == NULL) {
        *out_err = VANTAQ_MEASUREMENT_MODEL_ERR_MALLOC_FAILED;
        return NULL;
    }

    VANTAQ_ZERO_STRUCT(*created_result);
    strncpy(created_result->claim_name, claim_name, VANTAQ_MEASUREMENT_CLAIM_NAME_MAX - 1);
    strncpy(created_result->source_path, source_path, VANTAQ_MEASUREMENT_SOURCE_PATH_MAX - 1);

    return created_result;
}

vantaq_measurement_model_err_t
vantaq_measurement_result_create_success(const char *claim_name, const char *value,
                                         const char *source_path,
                                         struct vantaq_measurement_result **out_result) {
    vantaq_measurement_model_err_t err        = VANTAQ_MEASUREMENT_MODEL_OK;
    struct vantaq_measurement_result *created = NULL;

    if (out_result == NULL) {
        return VANTAQ_MEASUREMENT_MODEL_ERR_INVALID_ARG;
    }
    *out_result = NULL;

    created = create_common(claim_name, source_path, &err);
    if (created == NULL) {
        return err;
    }

    err = validate_required_text(value, VANTAQ_MEASUREMENT_VALUE_MAX);
    if (err != VANTAQ_MEASUREMENT_MODEL_OK) {
        goto cleanup;
    }

    strncpy(created->value, value, VANTAQ_MEASUREMENT_VALUE_MAX - 1);
    created->status     = VANTAQ_MEASUREMENT_STATUS_SUCCESS;
    created->error_code = MEASUREMENT_OK;

    *out_result = created;
    created     = NULL;

cleanup:
    if (created != NULL) {
        vantaq_measurement_result_destroy(created);
    }
    return err;
}

vantaq_measurement_model_err_t
vantaq_measurement_result_create_error(const char *claim_name, const char *source_path,
                                       vantaq_measurement_error_code_t error_code,
                                       struct vantaq_measurement_result **out_result) {
    vantaq_measurement_model_err_t err        = VANTAQ_MEASUREMENT_MODEL_OK;
    struct vantaq_measurement_result *created = NULL;

    if (out_result == NULL) {
        return VANTAQ_MEASUREMENT_MODEL_ERR_INVALID_ARG;
    }
    *out_result = NULL;

    created = create_common(claim_name, source_path, &err);
    if (created == NULL) {
        return err;
    }

    switch (error_code) {
    case MEASUREMENT_SOURCE_NOT_FOUND:
    case MEASUREMENT_READ_FAILED:
    case MEASUREMENT_PARSE_FAILED:
    case MEASUREMENT_HASH_FAILED:
    case MEASUREMENT_UNSUPPORTED_CLAIM:
        break;
    case MEASUREMENT_OK:
    case MEASUREMENT_INVALID:
    default:
        err = VANTAQ_MEASUREMENT_MODEL_ERR_INVALID_ARG;
        goto cleanup;
    }

    created->status     = VANTAQ_MEASUREMENT_STATUS_ERROR;
    created->error_code = error_code;

    *out_result = created;
    created     = NULL;

cleanup:
    if (created != NULL) {
        vantaq_measurement_result_destroy(created);
    }
    return err;
}

void vantaq_measurement_result_destroy(struct vantaq_measurement_result *result) {
    if (result != NULL) {
        vantaq_explicit_bzero(result, sizeof(*result));
        free(result);
    }
}

const char *
vantaq_measurement_result_get_claim_name(const struct vantaq_measurement_result *result) {
    static const char k_empty[] = "";

    return result ? result->claim_name : k_empty;
}

const char *vantaq_measurement_result_get_value(const struct vantaq_measurement_result *result) {
    static const char k_empty[] = "";

    return result ? result->value : k_empty;
}

const char *
vantaq_measurement_result_get_source_path(const struct vantaq_measurement_result *result) {
    static const char k_empty[] = "";

    return result ? result->source_path : k_empty;
}

vantaq_measurement_status_t
vantaq_measurement_result_get_status(const struct vantaq_measurement_result *result) {
    return result ? result->status : VANTAQ_MEASUREMENT_STATUS_ERROR;
}

vantaq_measurement_error_code_t
vantaq_measurement_result_get_error_code(const struct vantaq_measurement_result *result) {
    return result ? result->error_code : MEASUREMENT_INVALID;
}
