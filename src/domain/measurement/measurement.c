// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "domain/measurement/measurement.h"
#include "infrastructure/memory/zero_struct.h"

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
    if (value == NULL) {
        return VANTAQ_MEASUREMENT_MODEL_ERR_MISSING_FIELD;
    }
    if (value[0] == '\0') {
        return VANTAQ_MEASUREMENT_MODEL_ERR_MISSING_FIELD;
    }
    if (strlen(value) >= max_len) {
        return VANTAQ_MEASUREMENT_MODEL_ERR_FIELD_TOO_LONG;
    }
    return VANTAQ_MEASUREMENT_MODEL_OK;
}

static vantaq_measurement_model_err_t
validate_error_code(vantaq_measurement_error_code_t error_code) {
    switch (error_code) {
    case MEASUREMENT_OK:
    case MEASUREMENT_SOURCE_NOT_FOUND:
    case MEASUREMENT_READ_FAILED:
    case MEASUREMENT_HASH_FAILED:
    case MEASUREMENT_UNSUPPORTED_CLAIM:
        return VANTAQ_MEASUREMENT_MODEL_OK;
    default:
        return VANTAQ_MEASUREMENT_MODEL_ERR_INVALID_ARG;
    }
}

static vantaq_measurement_model_err_t
create_common(const char *claim_name, const char *source_path,
              struct vantaq_measurement_result **out_result,
              struct vantaq_measurement_result **created_result) {
    vantaq_measurement_model_err_t err = VANTAQ_MEASUREMENT_MODEL_OK;

    if (out_result == NULL || created_result == NULL) {
        return VANTAQ_MEASUREMENT_MODEL_ERR_INVALID_ARG;
    }

    *out_result     = NULL;
    *created_result = NULL;

    err = validate_required_text(claim_name, VANTAQ_MEASUREMENT_CLAIM_NAME_MAX);
    if (err != VANTAQ_MEASUREMENT_MODEL_OK) {
        return err;
    }

    err = validate_required_text(source_path, VANTAQ_MEASUREMENT_SOURCE_PATH_MAX);
    if (err != VANTAQ_MEASUREMENT_MODEL_OK) {
        return err;
    }

    *created_result = malloc(sizeof(struct vantaq_measurement_result));
    if (*created_result == NULL) {
        return VANTAQ_MEASUREMENT_MODEL_ERR_MALLOC_FAILED;
    }

    VANTAQ_ZERO_STRUCT(**created_result);
    strncpy((*created_result)->claim_name, claim_name, VANTAQ_MEASUREMENT_CLAIM_NAME_MAX - 1);
    strncpy((*created_result)->source_path, source_path, VANTAQ_MEASUREMENT_SOURCE_PATH_MAX - 1);

    return VANTAQ_MEASUREMENT_MODEL_OK;
}

vantaq_measurement_model_err_t
vantaq_measurement_result_create_success(const char *claim_name, const char *value,
                                         const char *source_path,
                                         struct vantaq_measurement_result **out_result) {
    vantaq_measurement_model_err_t err        = VANTAQ_MEASUREMENT_MODEL_OK;
    struct vantaq_measurement_result *result  = NULL;
    struct vantaq_measurement_result *created = NULL;

    err = create_common(claim_name, source_path, out_result, &created);
    if (err != VANTAQ_MEASUREMENT_MODEL_OK) {
        return err;
    }

    err = validate_required_text(value, VANTAQ_MEASUREMENT_VALUE_MAX);
    if (err != VANTAQ_MEASUREMENT_MODEL_OK) {
        goto cleanup;
    }

    strncpy(created->value, value, VANTAQ_MEASUREMENT_VALUE_MAX - 1);
    created->status     = VANTAQ_MEASUREMENT_STATUS_SUCCESS;
    created->error_code = MEASUREMENT_OK;

    result  = created;
    created = NULL;

cleanup:
    if (err == VANTAQ_MEASUREMENT_MODEL_OK) {
        *out_result = result;
    }
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
    struct vantaq_measurement_result *result  = NULL;
    struct vantaq_measurement_result *created = NULL;

    err = create_common(claim_name, source_path, out_result, &created);
    if (err != VANTAQ_MEASUREMENT_MODEL_OK) {
        return err;
    }

    err = validate_error_code(error_code);
    if (err != VANTAQ_MEASUREMENT_MODEL_OK) {
        goto cleanup;
    }
    if (error_code == MEASUREMENT_OK) {
        err = VANTAQ_MEASUREMENT_MODEL_ERR_INVALID_ARG;
        goto cleanup;
    }

    created->status     = VANTAQ_MEASUREMENT_STATUS_ERROR;
    created->error_code = error_code;

    result  = created;
    created = NULL;

cleanup:
    if (err == VANTAQ_MEASUREMENT_MODEL_OK) {
        *out_result = result;
    }
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
    return result ? result->claim_name : NULL;
}

const char *vantaq_measurement_result_get_value(const struct vantaq_measurement_result *result) {
    return result ? result->value : NULL;
}

const char *
vantaq_measurement_result_get_source_path(const struct vantaq_measurement_result *result) {
    return result ? result->source_path : NULL;
}

vantaq_measurement_status_t
vantaq_measurement_result_get_status(const struct vantaq_measurement_result *result) {
    return result ? result->status : VANTAQ_MEASUREMENT_STATUS_ERROR;
}

vantaq_measurement_error_code_t
vantaq_measurement_result_get_error_code(const struct vantaq_measurement_result *result) {
    return result ? result->error_code : MEASUREMENT_READ_FAILED;
}
