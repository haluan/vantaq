// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_INFRASTRUCTURE_LINUX_MEASUREMENT_AGENT_INTEGRITY_H
#define VANTAQ_INFRASTRUCTURE_LINUX_MEASUREMENT_AGENT_INTEGRITY_H

#include "domain/measurement/measurement.h"
#include "infrastructure/config_loader.h"

enum vantaq_agent_integrity_status {
    VANTAQ_AGENT_INTEGRITY_OK = 0,
    VANTAQ_AGENT_INTEGRITY_ERR_INVALID_ARG,
    VANTAQ_AGENT_INTEGRITY_ERR_SOURCE_NOT_FOUND,
    VANTAQ_AGENT_INTEGRITY_ERR_READ_FAILED,
    VANTAQ_AGENT_INTEGRITY_ERR_HASH_FAILED,
    VANTAQ_AGENT_INTEGRITY_ERR_FILE_TOO_LARGE,
    VANTAQ_AGENT_INTEGRITY_ERR_MODEL_FAILED,
};

enum vantaq_agent_integrity_status
vantaq_agent_integrity_measure(const struct vantaq_runtime_config *config,
                               struct vantaq_measurement_result **out_result);

#endif
