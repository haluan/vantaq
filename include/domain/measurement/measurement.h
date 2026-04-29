// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_DOMAIN_MEASUREMENT_MEASUREMENT_H
#define VANTAQ_DOMAIN_MEASUREMENT_MEASUREMENT_H

#include <stddef.h>

#define VANTAQ_MEASUREMENT_CLAIM_NAME_MAX 128
#define VANTAQ_MEASUREMENT_VALUE_MAX 512
#define VANTAQ_MEASUREMENT_SOURCE_PATH_MAX 256

typedef enum {
    VANTAQ_MEASUREMENT_STATUS_SUCCESS = 0,
    VANTAQ_MEASUREMENT_STATUS_ERROR   = 1
} vantaq_measurement_status_t;

typedef enum {
    MEASUREMENT_INVALID = -1,
    MEASUREMENT_OK = 0,
    MEASUREMENT_SOURCE_NOT_FOUND,
    MEASUREMENT_READ_FAILED,
    MEASUREMENT_PARSE_FAILED,
    MEASUREMENT_HASH_FAILED,
    MEASUREMENT_UNSUPPORTED_CLAIM
} vantaq_measurement_error_code_t;

typedef enum {
    VANTAQ_MEASUREMENT_MODEL_OK = 0,
    VANTAQ_MEASUREMENT_MODEL_ERR_INVALID_ARG,
    VANTAQ_MEASUREMENT_MODEL_ERR_MISSING_FIELD,
    VANTAQ_MEASUREMENT_MODEL_ERR_FIELD_TOO_LONG,
    VANTAQ_MEASUREMENT_MODEL_ERR_MALLOC_FAILED
} vantaq_measurement_model_err_t;

struct vantaq_measurement_result;

vantaq_measurement_model_err_t vantaq_measurement_result_create_success(
    const char *claim_name,
    const char *value,
    const char *source_path,
    struct vantaq_measurement_result **out_result);

vantaq_measurement_model_err_t vantaq_measurement_result_create_error(
    const char *claim_name,
    const char *source_path,
    vantaq_measurement_error_code_t error_code,
    struct vantaq_measurement_result **out_result);

void vantaq_measurement_result_destroy(struct vantaq_measurement_result *result);

const char *
vantaq_measurement_result_get_claim_name(const struct vantaq_measurement_result *result);
const char *vantaq_measurement_result_get_value(const struct vantaq_measurement_result *result);
const char *
vantaq_measurement_result_get_source_path(const struct vantaq_measurement_result *result);
vantaq_measurement_status_t
vantaq_measurement_result_get_status(const struct vantaq_measurement_result *result);
vantaq_measurement_error_code_t
vantaq_measurement_result_get_error_code(const struct vantaq_measurement_result *result);

#endif
