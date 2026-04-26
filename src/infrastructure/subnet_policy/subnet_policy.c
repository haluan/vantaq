// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/subnet_policy.h"

#include "domain/network_access/ipv4_cidr.h"

#include <stddef.h>
#include <string.h>

static int is_protected_verifier_get_request(const char *method, const char *path) {
    if (strcmp(method, "GET") != 0) {
        return 0;
    }

    if (strcmp(path, "/v1/health") == 0) {
        return 1;
    }

    if (strcmp(path, "/v1/device/identity") == 0) {
        return 1;
    }

    return 0;
}

enum vantaq_subnet_policy_status
vantaq_subnet_policy_evaluate(const struct vantaq_subnet_policy_input *input,
                              enum vantaq_subnet_policy_decision *out_decision) {
    size_t i;
    uint32_t peer_ipv4;
    enum vantaq_ipv4_cidr_status ip_status;

    if (input == NULL || out_decision == NULL || input->method == NULL || input->path == NULL) {
        return VANTAQ_SUBNET_POLICY_STATUS_INVALID_ARGUMENT;
    }

    if (!is_protected_verifier_get_request(input->method, input->path)) {
        *out_decision = VANTAQ_SUBNET_POLICY_DECISION_ALLOW;
        return VANTAQ_SUBNET_POLICY_STATUS_OK;
    }

    if (input->dev_allow_all_networks != 0) {
        *out_decision = VANTAQ_SUBNET_POLICY_DECISION_ALLOW;
        return VANTAQ_SUBNET_POLICY_STATUS_OK;
    }

    if (input->peer_status != VANTAQ_PEER_ADDRESS_STATUS_OK || input->peer_ipv4 == NULL ||
        input->peer_ipv4[0] == '\0') {
        *out_decision = VANTAQ_SUBNET_POLICY_DECISION_DENY;
        return VANTAQ_SUBNET_POLICY_STATUS_OK;
    }

    if (input->allowed_subnets_count == 0 || input->allowed_subnets == NULL) {
        *out_decision = VANTAQ_SUBNET_POLICY_DECISION_DENY;
        return VANTAQ_SUBNET_POLICY_STATUS_OK;
    }

    ip_status = vantaq_ipv4_parse_u32(input->peer_ipv4, &peer_ipv4);
    if (ip_status != VANTAQ_IPV4_CIDR_STATUS_OK) {
        *out_decision = VANTAQ_SUBNET_POLICY_DECISION_DENY;
        return VANTAQ_SUBNET_POLICY_STATUS_OK;
    }

    for (i = 0; i < input->allowed_subnets_count; i++) {
        struct vantaq_ipv4_cidr cidr;
        const char *cidr_text = input->allowed_subnets[i];

        if (cidr_text == NULL || cidr_text[0] == '\0') {
            *out_decision = VANTAQ_SUBNET_POLICY_DECISION_DENY;
            return VANTAQ_SUBNET_POLICY_STATUS_OK;
        }

        ip_status = vantaq_ipv4_cidr_parse(cidr_text, &cidr);
        if (ip_status != VANTAQ_IPV4_CIDR_STATUS_OK) {
            *out_decision = VANTAQ_SUBNET_POLICY_DECISION_DENY;
            return VANTAQ_SUBNET_POLICY_STATUS_OK;
        }

        if (vantaq_ipv4_cidr_match(cidr, peer_ipv4)) {
            *out_decision = VANTAQ_SUBNET_POLICY_DECISION_ALLOW;
            return VANTAQ_SUBNET_POLICY_STATUS_OK;
        }
    }

    *out_decision = VANTAQ_SUBNET_POLICY_DECISION_DENY;
    return VANTAQ_SUBNET_POLICY_STATUS_OK;
}

const char *vantaq_subnet_policy_status_text(enum vantaq_subnet_policy_status status) {
    switch (status) {
    case VANTAQ_SUBNET_POLICY_STATUS_OK:
        return "ok";
    case VANTAQ_SUBNET_POLICY_STATUS_INVALID_ARGUMENT:
        return "invalid argument";
    default:
        return "unknown";
    }
}
