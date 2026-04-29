// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/linux_measurement/config_hash.h"
#include "domain/measurement/supported_claims.h"
#include "file_sha256_measurement.h"

#include <string.h>

#define VANTAQ_CONFIG_HASH_SHA256_VALUE_MIN_BYTES ((size_t)7 + (size_t)64 + (size_t)1)

_Static_assert(VANTAQ_MEASUREMENT_VALUE_MAX >= VANTAQ_CONFIG_HASH_SHA256_VALUE_MIN_BYTES,
               "VANTAQ_MEASUREMENT_VALUE_MAX too small for config_hash sha256 value");

static bool config_measurement_source_path_acceptable(const char *path) {
    /* Same rationale as firmware_hash: pseudo-filesystems are non-regular for stable hashing. */
    if (strncmp(path, "/proc/", 6) == 0) {
        return false;
    }
    if (strncmp(path, "/sys/", 5) == 0) {
        return false;
    }
    return true;
}

static enum vantaq_config_hash_status
map_file_status_to_config_status(enum vantaq_file_sha256_measure_status status) {
    switch (status) {
    case VANTAQ_FILE_SHA256_MEASURE_OK:
        return VANTAQ_CONFIG_HASH_OK;
    case VANTAQ_FILE_SHA256_MEASURE_ERR_INVALID_ARG:
        return VANTAQ_CONFIG_HASH_ERR_INVALID_ARG;
    case VANTAQ_FILE_SHA256_MEASURE_ERR_SOURCE_NOT_FOUND:
        return VANTAQ_CONFIG_HASH_ERR_SOURCE_NOT_FOUND;
    case VANTAQ_FILE_SHA256_MEASURE_ERR_READ_FAILED:
        return VANTAQ_CONFIG_HASH_ERR_READ_FAILED;
    case VANTAQ_FILE_SHA256_MEASURE_ERR_HASH_FAILED:
        return VANTAQ_CONFIG_HASH_ERR_HASH_FAILED;
    case VANTAQ_FILE_SHA256_MEASURE_ERR_FILE_TOO_LARGE:
        return VANTAQ_CONFIG_HASH_ERR_FILE_TOO_LARGE;
    case VANTAQ_FILE_SHA256_MEASURE_ERR_MODEL_FAILED:
    default:
        return VANTAQ_CONFIG_HASH_ERR_MODEL_FAILED;
    }
}

enum vantaq_config_hash_status
vantaq_config_hash_measure(const struct vantaq_runtime_config *config,
                           struct vantaq_measurement_result **out_result) {
    enum vantaq_file_sha256_measure_status status = VANTAQ_FILE_SHA256_MEASURE_OK;
    const char *config_path                       = NULL;
    size_t max_file_bytes                         = 0U;

    if (out_result == NULL || config == NULL) {
        return VANTAQ_CONFIG_HASH_ERR_INVALID_ARG;
    }
    *out_result = NULL;

    config_path    = vantaq_runtime_measurement_security_config_path(config);
    max_file_bytes = vantaq_runtime_measurement_max_file_bytes(config);
    if (config_path == NULL || config_path[0] == '\0' || max_file_bytes == 0U ||
        max_file_bytes > VANTAQ_MEASUREMENT_DEFAULT_MAX_FILE_BYTES) {
        return VANTAQ_CONFIG_HASH_ERR_INVALID_ARG;
    }
    if (!config_measurement_source_path_acceptable(config_path)) {
        return VANTAQ_CONFIG_HASH_ERR_INVALID_ARG;
    }

    status = vantaq_measure_sha256_file_to_result(config_path, max_file_bytes,
                                                  VANTAQ_CLAIM_CONFIG_HASH, out_result);
    return map_file_status_to_config_status(status);
}
