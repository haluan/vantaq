// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "domain/network_access/ipv4_cidr.h"

#include <arpa/inet.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static uint32_t vantaq_ipv4_prefix_mask(uint8_t prefix_len) {
    if (prefix_len == 0) {
        return 0U;
    }
    if (prefix_len == 32) {
        return 0xFFFFFFFFU;
    }
    return 0xFFFFFFFFU << (32U - prefix_len);
}

enum vantaq_ipv4_cidr_status vantaq_ipv4_parse_u32(const char *ip_text, uint32_t *out_host_order) {
    struct in_addr addr;

    if (ip_text == NULL || out_host_order == NULL) {
        return VANTAQ_IPV4_CIDR_STATUS_INVALID_ARGUMENT;
    }

    if (inet_pton(AF_INET, ip_text, &addr) != 1) {
        return VANTAQ_IPV4_CIDR_STATUS_INVALID_IPV4;
    }

    *out_host_order = ntohl(addr.s_addr);
    return VANTAQ_IPV4_CIDR_STATUS_OK;
}

enum vantaq_ipv4_cidr_status vantaq_ipv4_cidr_parse(const char *cidr_text,
                                                    struct vantaq_ipv4_cidr *out) {
    const char *slash;
    const char *prefix_text;
    char ip_part[32];
    size_t ip_len;
    char *endptr;
    long prefix;
    uint32_t ip_host_order;
    enum vantaq_ipv4_cidr_status status;

    if (cidr_text == NULL || out == NULL) {
        return VANTAQ_IPV4_CIDR_STATUS_INVALID_ARGUMENT;
    }

    slash = strchr(cidr_text, '/');
    if (slash == NULL || slash == cidr_text || slash[1] == '\0' || strchr(slash + 1, '/') != NULL) {
        return VANTAQ_IPV4_CIDR_STATUS_INVALID_CIDR_FORMAT;
    }

    ip_len = (size_t)(slash - cidr_text);
    if (ip_len == 0 || ip_len >= sizeof(ip_part)) {
        return VANTAQ_IPV4_CIDR_STATUS_INVALID_CIDR_FORMAT;
    }

    memcpy(ip_part, cidr_text, ip_len);
    ip_part[ip_len] = '\0';

    status = vantaq_ipv4_parse_u32(ip_part, &ip_host_order);
    if (status != VANTAQ_IPV4_CIDR_STATUS_OK) {
        return status;
    }

    prefix_text = slash + 1;
    prefix      = strtol(prefix_text, &endptr, 10);
    if (*prefix_text == '\0' || *endptr != '\0' || prefix < 0 || prefix > 32 || prefix > LONG_MAX) {
        return VANTAQ_IPV4_CIDR_STATUS_INVALID_PREFIX;
    }

    out->prefix_len = (uint8_t)prefix;
    out->mask       = vantaq_ipv4_prefix_mask(out->prefix_len);
    out->network    = ip_host_order & out->mask;
    return VANTAQ_IPV4_CIDR_STATUS_OK;
}

bool vantaq_ipv4_cidr_match(struct vantaq_ipv4_cidr cidr, uint32_t ip_host_order) {
    return (ip_host_order & cidr.mask) == cidr.network;
}

const char *vantaq_ipv4_cidr_status_text(enum vantaq_ipv4_cidr_status status) {
    switch (status) {
    case VANTAQ_IPV4_CIDR_STATUS_OK:
        return "ok";
    case VANTAQ_IPV4_CIDR_STATUS_INVALID_ARGUMENT:
        return "invalid argument";
    case VANTAQ_IPV4_CIDR_STATUS_INVALID_CIDR_FORMAT:
        return "invalid cidr format";
    case VANTAQ_IPV4_CIDR_STATUS_INVALID_IPV4:
        return "invalid ipv4";
    case VANTAQ_IPV4_CIDR_STATUS_INVALID_PREFIX:
        return "invalid prefix";
    default:
        return "unknown";
    }
}
