// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/linux_measurement/agent_integrity.h"
#include "domain/measurement/supported_claims.h"
#include "file_sha256_measurement.h"

#define VANTAQ_AGENT_INTEGRITY_SHA256_VALUE_MIN_BYTES ((size_t)7 + (size_t)64 + (size_t)1)

_Static_assert(VANTAQ_MEASUREMENT_VALUE_MAX >= VANTAQ_AGENT_INTEGRITY_SHA256_VALUE_MIN_BYTES,
               "VANTAQ_MEASUREMENT_VALUE_MAX too small for agent_integrity sha256 value");

static enum vantaq_agent_integrity_status
map_file_status_to_agent_status(enum vantaq_file_sha256_measure_status status) {
    switch (status) {
    case VANTAQ_FILE_SHA256_MEASURE_OK:
        return VANTAQ_AGENT_INTEGRITY_OK;
    case VANTAQ_FILE_SHA256_MEASURE_ERR_INVALID_ARG:
        return VANTAQ_AGENT_INTEGRITY_ERR_INVALID_ARG;
    case VANTAQ_FILE_SHA256_MEASURE_ERR_SOURCE_NOT_FOUND:
        return VANTAQ_AGENT_INTEGRITY_ERR_SOURCE_NOT_FOUND;
    case VANTAQ_FILE_SHA256_MEASURE_ERR_READ_FAILED:
        return VANTAQ_AGENT_INTEGRITY_ERR_READ_FAILED;
    case VANTAQ_FILE_SHA256_MEASURE_ERR_HASH_FAILED:
        return VANTAQ_AGENT_INTEGRITY_ERR_HASH_FAILED;
    case VANTAQ_FILE_SHA256_MEASURE_ERR_FILE_TOO_LARGE:
        return VANTAQ_AGENT_INTEGRITY_ERR_FILE_TOO_LARGE;
    case VANTAQ_FILE_SHA256_MEASURE_ERR_MODEL_FAILED:
    default:
        return VANTAQ_AGENT_INTEGRITY_ERR_MODEL_FAILED;
    }
}

enum vantaq_agent_integrity_status
vantaq_agent_integrity_measure(const struct vantaq_runtime_config *config,
                               struct vantaq_measurement_result **out_result) {
    enum vantaq_file_sha256_measure_status status = VANTAQ_FILE_SHA256_MEASURE_OK;
    const char *agent_path                        = NULL;
    size_t max_file_bytes                         = 0U;

    if (out_result == NULL || config == NULL) {
        return VANTAQ_AGENT_INTEGRITY_ERR_INVALID_ARG;
    }
    *out_result = NULL;

    agent_path     = vantaq_runtime_measurement_agent_binary_path(config);
    max_file_bytes = vantaq_runtime_measurement_max_file_bytes(config);
    if (agent_path == NULL || agent_path[0] == '\0' || max_file_bytes == 0U ||
        max_file_bytes > VANTAQ_MEASUREMENT_DEFAULT_MAX_FILE_BYTES) {
        return VANTAQ_AGENT_INTEGRITY_ERR_INVALID_ARG;
    }

    status = vantaq_measure_sha256_file_to_result(agent_path, max_file_bytes,
                                                  VANTAQ_CLAIM_AGENT_INTEGRITY, out_result);
    return map_file_status_to_agent_status(status);
}
