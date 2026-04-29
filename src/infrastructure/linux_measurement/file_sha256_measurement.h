// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_INFRASTRUCTURE_LINUX_MEASUREMENT_FILE_SHA256_MEASUREMENT_H
#define VANTAQ_INFRASTRUCTURE_LINUX_MEASUREMENT_FILE_SHA256_MEASUREMENT_H

#include "domain/measurement/measurement.h"

#include <stddef.h>

enum vantaq_file_sha256_measure_status {
    VANTAQ_FILE_SHA256_MEASURE_OK = 0,
    VANTAQ_FILE_SHA256_MEASURE_ERR_INVALID_ARG,
    VANTAQ_FILE_SHA256_MEASURE_ERR_SOURCE_NOT_FOUND,
    VANTAQ_FILE_SHA256_MEASURE_ERR_READ_FAILED,
    VANTAQ_FILE_SHA256_MEASURE_ERR_HASH_FAILED,
    VANTAQ_FILE_SHA256_MEASURE_ERR_FILE_TOO_LARGE,
    VANTAQ_FILE_SHA256_MEASURE_ERR_MODEL_FAILED,
};

enum vantaq_file_sha256_measure_status
vantaq_measure_sha256_file_to_result(const char *source_path, size_t max_file_bytes,
                                     const char *claim_name,
                                     struct vantaq_measurement_result **out_result);

#endif
