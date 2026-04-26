// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_DOMAIN_NETWORK_ACCESS_IPV4_CIDR_H
#define VANTAQ_DOMAIN_NETWORK_ACCESS_IPV4_CIDR_H

#include <stdbool.h>
#include <stdint.h>

typedef struct vantaq_ipv4_cidr vantaq_ipv4_cidr_t;

enum vantaq_ipv4_cidr_status {
    VANTAQ_IPV4_CIDR_STATUS_OK = 0,
    VANTAQ_IPV4_CIDR_STATUS_INVALID_ARGUMENT,
    VANTAQ_IPV4_CIDR_STATUS_INVALID_CIDR_FORMAT,
    VANTAQ_IPV4_CIDR_STATUS_INVALID_IPV4,
    VANTAQ_IPV4_CIDR_STATUS_INVALID_PREFIX,
    VANTAQ_IPV4_CIDR_STATUS_NON_CANONICAL,
};

enum vantaq_ipv4_cidr_status vantaq_ipv4_parse_u32(const char *ip_text, uint32_t *out_host_order);
enum vantaq_ipv4_cidr_status vantaq_ipv4_cidr_create(const char *cidr_text,
                                                     vantaq_ipv4_cidr_t **out);
void vantaq_ipv4_cidr_destroy(vantaq_ipv4_cidr_t *cidr);
bool vantaq_ipv4_cidr_match(const vantaq_ipv4_cidr_t *cidr, uint32_t ip_host_order);

uint8_t vantaq_ipv4_cidr_prefix_len(const vantaq_ipv4_cidr_t *cidr);
uint32_t vantaq_ipv4_cidr_mask(const vantaq_ipv4_cidr_t *cidr);
uint32_t vantaq_ipv4_cidr_network(const vantaq_ipv4_cidr_t *cidr);
const char *vantaq_ipv4_cidr_status_text(enum vantaq_ipv4_cidr_status status);

#endif
