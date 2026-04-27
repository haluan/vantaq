// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "domain/network_access/ipv4_cidr.h"
#include "infrastructure/memory/zero_struct.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>

struct vantaq_ipv4_cidr {
    uint32_t network;
    uint8_t prefix_len;
};

static uint32_t vantaq_ipv4_prefix_mask(uint8_t prefix_len) {
    if (prefix_len == 0) {
        return 0U;
    }
    if (prefix_len >= 32) {
        return 0xFFFFFFFFU;
    }
    return 0xFFFFFFFFU << (32U - prefix_len);
}

enum vantaq_ipv4_cidr_status vantaq_ipv4_parse_u32(const char *ip_text, uint32_t *out_host_order) {
    struct in_addr addr;

    if (out_host_order != NULL) {
        VANTAQ_ZERO_STRUCT(*out_host_order);
    }

    if (ip_text == NULL || out_host_order == NULL) {
        return VANTAQ_IPV4_CIDR_STATUS_INVALID_ARGUMENT;
    }

    if (inet_pton(AF_INET, ip_text, &addr) != 1) {
        return VANTAQ_IPV4_CIDR_STATUS_INVALID_IPV4;
    }

    *out_host_order = ntohl(addr.s_addr);
    return VANTAQ_IPV4_CIDR_STATUS_OK;
}

enum vantaq_ipv4_cidr_status vantaq_ipv4_cidr_create(const char *cidr_text,
                                                     vantaq_ipv4_cidr_t **out) {
    const char *slash;
    const char *prefix_text;
    char ip_part[32];
    size_t ip_len;
    char *endptr;
    long prefix;
    uint32_t ip_host_order;
    enum vantaq_ipv4_cidr_status status;
    vantaq_ipv4_cidr_t *obj = NULL;

    if (out != NULL) {
        *out = NULL;
    }

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
    errno       = 0;
    prefix      = strtol(prefix_text, &endptr, 10);
    if (errno == ERANGE || *prefix_text == '\0' || *endptr != '\0' || prefix < 0 || prefix > 32) {
        return VANTAQ_IPV4_CIDR_STATUS_INVALID_PREFIX;
    }

    obj = malloc(sizeof(vantaq_ipv4_cidr_t));
    if (obj == NULL) {
        return VANTAQ_IPV4_CIDR_STATUS_INVALID_ARGUMENT;
    }
    VANTAQ_ZERO_STRUCT(*obj);

    obj->prefix_len = (uint8_t)prefix;
    uint32_t mask   = vantaq_ipv4_prefix_mask(obj->prefix_len);

    if ((ip_host_order & ~mask) != 0) {
        free(obj);
        return VANTAQ_IPV4_CIDR_STATUS_NON_CANONICAL;
    }

    obj->network = ip_host_order & mask;

    *out = obj;
    return VANTAQ_IPV4_CIDR_STATUS_OK;
}

void vantaq_ipv4_cidr_destroy(vantaq_ipv4_cidr_t *cidr) { free(cidr); }

bool vantaq_ipv4_cidr_match(const vantaq_ipv4_cidr_t *cidr, uint32_t ip_host_order) {
    if (cidr == NULL) {
        return false;
    }
    // Robust check: re-calculate mask or at least ensure network is masked
    uint32_t mask = vantaq_ipv4_prefix_mask(cidr->prefix_len);
    return (ip_host_order & mask) == (cidr->network & mask);
}

uint8_t vantaq_ipv4_cidr_prefix_len(const vantaq_ipv4_cidr_t *cidr) {
    return cidr ? cidr->prefix_len : 0;
}

uint32_t vantaq_ipv4_cidr_mask(const vantaq_ipv4_cidr_t *cidr) {
    return cidr ? vantaq_ipv4_prefix_mask(cidr->prefix_len) : 0;
}

uint32_t vantaq_ipv4_cidr_network(const vantaq_ipv4_cidr_t *cidr) {
    return cidr ? cidr->network : 0;
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
    case VANTAQ_IPV4_CIDR_STATUS_NON_CANONICAL:
        return "non-canonical cidr (host bits set)";
    default:
        return "unknown";
    }
}
