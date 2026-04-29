// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_INFRASTRUCTURE_LINUX_MEASUREMENT_BOOT_STATE_H
#define VANTAQ_INFRASTRUCTURE_LINUX_MEASUREMENT_BOOT_STATE_H

#include "domain/measurement/measurement.h"
#include "infrastructure/config_loader.h"

enum vantaq_boot_state_status {
    VANTAQ_BOOT_STATE_OK = 0,
    VANTAQ_BOOT_STATE_ERR_INVALID_ARG,
    VANTAQ_BOOT_STATE_ERR_SOURCE_NOT_FOUND,
    VANTAQ_BOOT_STATE_ERR_READ_FAILED,
    VANTAQ_BOOT_STATE_ERR_PARSE_FAILED,
    VANTAQ_BOOT_STATE_ERR_FILE_TOO_LARGE,
    VANTAQ_BOOT_STATE_ERR_MODEL_FAILED,
};

enum vantaq_boot_state_status
vantaq_boot_state_measure(const struct vantaq_runtime_config *config,
                          struct vantaq_measurement_result **out_result);

#endif
