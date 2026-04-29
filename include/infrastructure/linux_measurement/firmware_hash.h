// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_INFRASTRUCTURE_LINUX_MEASUREMENT_FIRMWARE_HASH_H
#define VANTAQ_INFRASTRUCTURE_LINUX_MEASUREMENT_FIRMWARE_HASH_H

#include "domain/measurement/measurement.h"
#include "infrastructure/config_loader.h"

enum vantaq_firmware_hash_status {
    VANTAQ_FIRMWARE_HASH_OK = 0,
    VANTAQ_FIRMWARE_HASH_ERR_INVALID_ARG,
    VANTAQ_FIRMWARE_HASH_ERR_SOURCE_NOT_FOUND,
    VANTAQ_FIRMWARE_HASH_ERR_READ_FAILED,
    VANTAQ_FIRMWARE_HASH_ERR_HASH_FAILED,
    VANTAQ_FIRMWARE_HASH_ERR_FILE_TOO_LARGE,
    VANTAQ_FIRMWARE_HASH_ERR_MODEL_FAILED,
};

enum vantaq_firmware_hash_status
vantaq_firmware_hash_measure(const struct vantaq_runtime_config *config,
                             struct vantaq_measurement_result **out_result);

#endif
