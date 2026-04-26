// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_INFRASTRUCTURE_SUBNET_POLICY_H
#define VANTAQ_INFRASTRUCTURE_SUBNET_POLICY_H

#include "infrastructure/socket_peer.h"

#include <stddef.h>

enum vantaq_subnet_policy_status {
    VANTAQ_SUBNET_POLICY_STATUS_OK = 0,
    VANTAQ_SUBNET_POLICY_STATUS_INVALID_ARGUMENT,
};

enum vantaq_subnet_policy_decision {
    VANTAQ_SUBNET_POLICY_DECISION_ALLOW = 0,
    VANTAQ_SUBNET_POLICY_DECISION_DENY,
};

struct vantaq_subnet_policy_input {
    const char *method;
    const char *path;
    enum vantaq_peer_address_status peer_status;
    const char *peer_ipv4;
    const char *const *allowed_subnets;
    size_t allowed_subnets_count;
    int dev_allow_all_networks;
};

enum vantaq_subnet_policy_status
vantaq_subnet_policy_evaluate(const struct vantaq_subnet_policy_input *input,
                              enum vantaq_subnet_policy_decision *out_decision);
const char *vantaq_subnet_policy_status_text(enum vantaq_subnet_policy_status status);

#endif
