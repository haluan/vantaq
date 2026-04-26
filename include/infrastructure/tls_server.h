// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_INFRASTRUCTURE_TLS_SERVER_H
#define VANTAQ_INFRASTRUCTURE_TLS_SERVER_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

enum vantaq_tls_server_status {
    VANTAQ_TLS_SERVER_STATUS_OK = 0,
    VANTAQ_TLS_SERVER_STATUS_INVALID_ARGUMENT,
    VANTAQ_TLS_SERVER_STATUS_INIT_ERROR,
    VANTAQ_TLS_SERVER_STATUS_CERT_LOAD_ERROR,
    VANTAQ_TLS_SERVER_STATUS_KEY_LOAD_ERROR,
    VANTAQ_TLS_SERVER_STATUS_CLIENT_CA_LOAD_ERROR,
    VANTAQ_TLS_SERVER_STATUS_CONTEXT_CONFIG_ERROR,
    VANTAQ_TLS_SERVER_STATUS_HANDSHAKE_ERROR,
    VANTAQ_TLS_SERVER_STATUS_IO_ERROR,
};

struct vantaq_tls_server_options {
    size_t cbSize;
    const char *server_cert_path;
    const char *server_key_path;
    const char *trusted_client_ca_path;
    bool require_client_cert;
};

struct vantaq_tls_server;
struct vantaq_tls_connection;

enum vantaq_tls_server_status
vantaq_tls_server_create(const struct vantaq_tls_server_options *options,
                         struct vantaq_tls_server **server_out);
void vantaq_tls_server_destroy(struct vantaq_tls_server *server);

enum vantaq_tls_server_status
vantaq_tls_server_handshake(struct vantaq_tls_server *server, int socket_fd,
                            struct vantaq_tls_connection **connection_out);

ssize_t vantaq_tls_connection_read(struct vantaq_tls_connection *connection, void *buf,
                                   size_t len);
ssize_t vantaq_tls_connection_write(struct vantaq_tls_connection *connection, const void *buf,
                                    size_t len);
void vantaq_tls_connection_destroy(struct vantaq_tls_connection *connection);

const char *vantaq_tls_server_status_text(enum vantaq_tls_server_status status);

#endif
