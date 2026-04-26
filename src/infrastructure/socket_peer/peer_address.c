// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#define _POSIX_C_SOURCE 200809L

#include "infrastructure/socket_peer.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

enum vantaq_peer_address_status vantaq_peer_address_get_ipv4(int client_fd, char *out,
                                                             size_t out_len) {
    struct sockaddr_storage storage;
    struct sockaddr_in *peer_v4 = NULL;
    socklen_t addr_len          = sizeof(storage);
    const char *ntop_result;

    if (client_fd < 0 || out == NULL || out_len == 0) {
        return VANTAQ_PEER_ADDRESS_STATUS_INVALID_ARGUMENT;
    }

    out[0] = '\0';

    if (getpeername(client_fd, (struct sockaddr *)&storage, &addr_len) != 0) {
        return VANTAQ_PEER_ADDRESS_STATUS_GETPEERNAME_FAILED;
    }

    if (storage.ss_family != AF_INET) {
        return VANTAQ_PEER_ADDRESS_STATUS_UNSUPPORTED_FAMILY;
    }

    peer_v4     = (struct sockaddr_in *)&storage;
    ntop_result = inet_ntop(AF_INET, &peer_v4->sin_addr, out, out_len);
    if (ntop_result == NULL) {
        return VANTAQ_PEER_ADDRESS_STATUS_FORMAT_FAILED;
    }

    return VANTAQ_PEER_ADDRESS_STATUS_OK;
}

const char *vantaq_peer_address_status_text(enum vantaq_peer_address_status status) {
    switch (status) {
    case VANTAQ_PEER_ADDRESS_STATUS_OK:
        return "ok";
    case VANTAQ_PEER_ADDRESS_STATUS_INVALID_ARGUMENT:
        return "invalid argument";
    case VANTAQ_PEER_ADDRESS_STATUS_GETPEERNAME_FAILED:
        return "getpeername failed";
    case VANTAQ_PEER_ADDRESS_STATUS_UNSUPPORTED_FAMILY:
        return "unsupported address family";
    case VANTAQ_PEER_ADDRESS_STATUS_FORMAT_FAILED:
        return "address formatting failed";
    default:
        return "unknown";
    }
}
