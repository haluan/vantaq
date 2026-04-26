// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_DOMAIN_NETWORK_ACCESS_IPV4_CIDR_H
#define VANTAQ_DOMAIN_NETWORK_ACCESS_IPV4_CIDR_H

#include <stdbool.h>
#include <stdint.h>

struct vantaq_ipv4_cidr {
    uint32_t network;
    uint8_t prefix_len;
    uint32_t mask;
};

enum vantaq_ipv4_cidr_status {
    VANTAQ_IPV4_CIDR_STATUS_OK = 0,
    VANTAQ_IPV4_CIDR_STATUS_INVALID_ARGUMENT,
    VANTAQ_IPV4_CIDR_STATUS_INVALID_CIDR_FORMAT,
    VANTAQ_IPV4_CIDR_STATUS_INVALID_IPV4,
    VANTAQ_IPV4_CIDR_STATUS_INVALID_PREFIX,
};

enum vantaq_ipv4_cidr_status vantaq_ipv4_parse_u32(const char *ip_text, uint32_t *out_host_order);
enum vantaq_ipv4_cidr_status vantaq_ipv4_cidr_parse(const char *cidr_text,
                                                    struct vantaq_ipv4_cidr *out);
bool vantaq_ipv4_cidr_match(struct vantaq_ipv4_cidr cidr, uint32_t ip_host_order);
const char *vantaq_ipv4_cidr_status_text(enum vantaq_ipv4_cidr_status status);

#endif
