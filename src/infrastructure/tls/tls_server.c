// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/tls_server.h"

#include <errno.h>
#include <stdlib.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

struct vantaq_tls_server {
    SSL_CTX *ssl_ctx;
};

struct vantaq_tls_connection {
    SSL *ssl;
};

enum vantaq_tls_server_status
vantaq_tls_server_create(const struct vantaq_tls_server_options *options,
                         struct vantaq_tls_server **server_out) {
    struct vantaq_tls_server *server = NULL;
    SSL_CTX *ssl_ctx                 = NULL;
    int verify_mode;

    if (options == NULL || server_out == NULL ||
        options->cbSize < sizeof(struct vantaq_tls_server_options) ||
        options->server_cert_path == NULL || options->server_cert_path[0] == '\0' ||
        options->server_key_path == NULL || options->server_key_path[0] == '\0' ||
        options->trusted_client_ca_path == NULL || options->trusted_client_ca_path[0] == '\0') {
        return VANTAQ_TLS_SERVER_STATUS_INVALID_ARGUMENT;
    }

    *server_out = NULL;

    if (OPENSSL_init_ssl(0, NULL) != 1) {
        return VANTAQ_TLS_SERVER_STATUS_INIT_ERROR;
    }

    ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (ssl_ctx == NULL) {
        return VANTAQ_TLS_SERVER_STATUS_INIT_ERROR;
    }

    if (SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION) != 1) {
        SSL_CTX_free(ssl_ctx);
        return VANTAQ_TLS_SERVER_STATUS_CONTEXT_CONFIG_ERROR;
    }

    if (SSL_CTX_use_certificate_file(ssl_ctx, options->server_cert_path, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ssl_ctx);
        return VANTAQ_TLS_SERVER_STATUS_CERT_LOAD_ERROR;
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, options->server_key_path, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ssl_ctx);
        return VANTAQ_TLS_SERVER_STATUS_KEY_LOAD_ERROR;
    }

    if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
        SSL_CTX_free(ssl_ctx);
        return VANTAQ_TLS_SERVER_STATUS_KEY_LOAD_ERROR;
    }

    if (SSL_CTX_load_verify_locations(ssl_ctx, options->trusted_client_ca_path, NULL) != 1) {
        SSL_CTX_free(ssl_ctx);
        return VANTAQ_TLS_SERVER_STATUS_CLIENT_CA_LOAD_ERROR;
    }

    verify_mode = SSL_VERIFY_PEER;
    if (options->require_client_cert) {
        verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    }
    SSL_CTX_set_verify(ssl_ctx, verify_mode, NULL);
    SSL_CTX_set_verify_depth(ssl_ctx, 4);

    server = (struct vantaq_tls_server *)calloc(1, sizeof(*server));
    if (server == NULL) {
        SSL_CTX_free(ssl_ctx);
        return VANTAQ_TLS_SERVER_STATUS_INIT_ERROR;
    }

    server->ssl_ctx = ssl_ctx;
    *server_out     = server;
    return VANTAQ_TLS_SERVER_STATUS_OK;
}

void vantaq_tls_server_destroy(struct vantaq_tls_server *server) {
    if (server == NULL) {
        return;
    }

    if (server->ssl_ctx != NULL) {
        SSL_CTX_free(server->ssl_ctx);
    }

    free(server);
}

enum vantaq_tls_server_status
vantaq_tls_server_handshake(struct vantaq_tls_server *server, int socket_fd,
                            struct vantaq_tls_connection **connection_out) {
    struct vantaq_tls_connection *connection = NULL;
    SSL *ssl                                 = NULL;

    if (server == NULL || connection_out == NULL || socket_fd < 0 || server->ssl_ctx == NULL) {
        return VANTAQ_TLS_SERVER_STATUS_INVALID_ARGUMENT;
    }

    *connection_out = NULL;

    ssl = SSL_new(server->ssl_ctx);
    if (ssl == NULL) {
        return VANTAQ_TLS_SERVER_STATUS_INIT_ERROR;
    }

    if (SSL_set_fd(ssl, socket_fd) != 1) {
        SSL_free(ssl);
        return VANTAQ_TLS_SERVER_STATUS_INIT_ERROR;
    }

    if (SSL_accept(ssl) != 1) {
        SSL_free(ssl);
        return VANTAQ_TLS_SERVER_STATUS_HANDSHAKE_ERROR;
    }

    connection = (struct vantaq_tls_connection *)calloc(1, sizeof(*connection));
    if (connection == NULL) {
        SSL_free(ssl);
        return VANTAQ_TLS_SERVER_STATUS_INIT_ERROR;
    }

    connection->ssl = ssl;
    *connection_out = connection;
    return VANTAQ_TLS_SERVER_STATUS_OK;
}

ssize_t vantaq_tls_connection_read(struct vantaq_tls_connection *connection, void *buf,
                                   size_t len) {
    int rc;
    int ssl_error;

    if (connection == NULL || connection->ssl == NULL || buf == NULL) {
        errno = EINVAL;
        return -1;
    }

    rc = SSL_read(connection->ssl, buf, (int)len);
    if (rc > 0) {
        return (ssize_t)rc;
    }

    ssl_error = SSL_get_error(connection->ssl, rc);
    if (ssl_error == SSL_ERROR_ZERO_RETURN) {
        return 0;
    }
    if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
        errno = EAGAIN;
        return -1;
    }
    if (ssl_error == SSL_ERROR_SYSCALL && errno != 0) {
        return -1;
    }

    errno = EIO;
    return -1;
}

ssize_t vantaq_tls_connection_write(struct vantaq_tls_connection *connection, const void *buf,
                                    size_t len) {
    int rc;
    int ssl_error;

    if (connection == NULL || connection->ssl == NULL || buf == NULL) {
        errno = EINVAL;
        return -1;
    }

    rc = SSL_write(connection->ssl, buf, (int)len);
    if (rc > 0) {
        return (ssize_t)rc;
    }

    ssl_error = SSL_get_error(connection->ssl, rc);
    if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
        errno = EAGAIN;
        return -1;
    }
    if (ssl_error == SSL_ERROR_SYSCALL && errno != 0) {
        return -1;
    }

    errno = EIO;
    return -1;
}

bool vantaq_tls_connection_peer_cert_verified(const struct vantaq_tls_connection *connection) {
    X509 *peer_certificate;
    long verify_result;

    if (connection == NULL || connection->ssl == NULL) {
        return false;
    }

    peer_certificate = SSL_get_peer_certificate(connection->ssl);
    if (peer_certificate == NULL) {
        return false;
    }

    X509_free(peer_certificate);

    verify_result = SSL_get_verify_result(connection->ssl);
    return verify_result == X509_V_OK;
}

void vantaq_tls_connection_destroy(struct vantaq_tls_connection *connection) {
    if (connection == NULL) {
        return;
    }

    if (connection->ssl != NULL) {
        (void)SSL_shutdown(connection->ssl);
        SSL_free(connection->ssl);
    }

    free(connection);
}

const char *vantaq_tls_server_status_text(enum vantaq_tls_server_status status) {
    switch (status) {
    case VANTAQ_TLS_SERVER_STATUS_OK:
        return "ok";
    case VANTAQ_TLS_SERVER_STATUS_INVALID_ARGUMENT:
        return "invalid argument";
    case VANTAQ_TLS_SERVER_STATUS_INIT_ERROR:
        return "tls init error";
    case VANTAQ_TLS_SERVER_STATUS_CERT_LOAD_ERROR:
        return "tls server certificate load error";
    case VANTAQ_TLS_SERVER_STATUS_KEY_LOAD_ERROR:
        return "tls server key load error";
    case VANTAQ_TLS_SERVER_STATUS_CLIENT_CA_LOAD_ERROR:
        return "tls client ca load error";
    case VANTAQ_TLS_SERVER_STATUS_CONTEXT_CONFIG_ERROR:
        return "tls context config error";
    case VANTAQ_TLS_SERVER_STATUS_HANDSHAKE_ERROR:
        return "tls handshake error";
    case VANTAQ_TLS_SERVER_STATUS_IO_ERROR:
        return "tls io error";
    default:
        return "unknown";
    }
}
