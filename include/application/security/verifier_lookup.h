// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_APPLICATION_SECURITY_VERIFIER_LOOKUP_H
#define VANTAQ_APPLICATION_SECURITY_VERIFIER_LOOKUP_H

#include "domain/verifier_access/verifier_policy.h"
#include "infrastructure/config_loader.h"

enum vantaq_verifier_status_code
vantaq_verifier_lookup_status(const struct vantaq_runtime_config *config, const char *verifier_id);

#endif
