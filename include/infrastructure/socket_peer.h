// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_INFRASTRUCTURE_SOCKET_PEER_H
#define VANTAQ_INFRASTRUCTURE_SOCKET_PEER_H

#include <stddef.h>

enum vantaq_peer_address_status {
    VANTAQ_PEER_ADDRESS_STATUS_OK = 0,
    VANTAQ_PEER_ADDRESS_STATUS_INVALID_ARGUMENT,
    VANTAQ_PEER_ADDRESS_STATUS_GETPEERNAME_FAILED,
    VANTAQ_PEER_ADDRESS_STATUS_UNSUPPORTED_FAMILY,
    VANTAQ_PEER_ADDRESS_STATUS_FORMAT_FAILED,
};

enum vantaq_peer_address_status vantaq_peer_address_get_ipv4(int client_fd, char *out,
                                                             size_t out_len);
const char *vantaq_peer_address_status_text(enum vantaq_peer_address_status status);

#endif
