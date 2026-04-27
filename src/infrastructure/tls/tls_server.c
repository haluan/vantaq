// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/tls_server.h"

#include <errno.h>
#include <stdlib.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

struct vantaq_tls_server {
    SSL_CTX *ssl_ctx;
    const struct vantaq_tls_ops *ops;
};

struct vantaq_tls_connection {
    SSL *ssl;
    const struct vantaq_tls_ops *ops;
};

/* Default VTable implementation using real OpenSSL */
static void *default_ssl_ctx_new(void) { return SSL_CTX_new(TLS_server_method()); }
static void default_ssl_ctx_free(void *ctx) { SSL_CTX_free((SSL_CTX *)ctx); }
static int default_ssl_ctx_use_certificate_file(void *ctx, const char *file, int type) {
    return SSL_CTX_use_certificate_file((SSL_CTX *)ctx, file, type);
}
static int default_ssl_ctx_use_PrivateKey_file(void *ctx, const char *file, int type) {
    return SSL_CTX_use_PrivateKey_file((SSL_CTX *)ctx, file, type);
}
static int default_ssl_ctx_check_private_key(void *ctx) {
    return SSL_CTX_check_private_key((SSL_CTX *)ctx);
}
static int default_ssl_ctx_load_verify_locations(void *ctx, const char *cafile,
                                                 const char *capath) {
    return SSL_CTX_load_verify_locations((SSL_CTX *)ctx, cafile, capath);
}
static void *default_ssl_new(void *ctx) { return SSL_new((SSL_CTX *)ctx); }
static void default_ssl_free(void *ssl) { SSL_free((SSL *)ssl); }
static int default_ssl_set_fd(void *ssl, int fd) { return SSL_set_fd((SSL *)ssl, fd); }
static int default_ssl_accept(void *ssl) { return SSL_accept((SSL *)ssl); }
static int default_ssl_shutdown(void *ssl) { return SSL_shutdown((SSL *)ssl); }
static int default_ssl_read(void *ssl, void *buf, int num) {
    return SSL_read((SSL *)ssl, buf, num);
}
static int default_ssl_write(void *ssl, const void *buf, int num) {
    return SSL_write((SSL *)ssl, buf, num);
}
static int default_ssl_get_error(void *ssl, int ret) { return SSL_get_error((SSL *)ssl, ret); }
static struct x509_st *default_ssl_get_peer_certificate(void *ssl) {
    return (struct x509_st *)SSL_get_peer_certificate((SSL *)ssl);
}
static long default_ssl_get_verify_result(void *ssl) { return SSL_get_verify_result((SSL *)ssl); }
static void *default_cert_get_ext_d2i(struct x509_st *x, int nid, int *crit, int *idx) {
    return X509_get_ext_d2i((X509 *)x, nid, crit, idx);
}
static void default_sans_free(void *sk, void (*free_func)(void *)) {
    sk_GENERAL_NAME_pop_free((STACK_OF(GENERAL_NAME) *)sk, (sk_GENERAL_NAME_freefunc)free_func);
}
static int default_sans_count(const void *sk) {
    return sk_GENERAL_NAME_num((const STACK_OF(GENERAL_NAME) *)sk);
}
static void *default_sans_get(const void *sk, int idx) {
    return sk_GENERAL_NAME_value((const STACK_OF(GENERAL_NAME) *)sk, idx);
}
static const unsigned char *default_asn1_get_data(const void *as) {
    return ASN1_STRING_get0_data((const ASN1_STRING *)as);
}
static int default_asn1_get_len(const void *as) {
    return ASN1_STRING_length((const ASN1_STRING *)as);
}

static const struct vantaq_tls_ops g_default_ops = {
    .ssl_ctx_new                   = default_ssl_ctx_new,
    .ssl_ctx_free                  = default_ssl_ctx_free,
    .ssl_ctx_use_certificate_file  = default_ssl_ctx_use_certificate_file,
    .ssl_ctx_use_PrivateKey_file   = default_ssl_ctx_use_PrivateKey_file,
    .ssl_ctx_check_private_key     = default_ssl_ctx_check_private_key,
    .ssl_ctx_load_verify_locations = default_ssl_ctx_load_verify_locations,
    .ssl_new                       = default_ssl_new,
    .ssl_free                      = default_ssl_free,
    .ssl_set_fd                    = default_ssl_set_fd,
    .ssl_accept                    = default_ssl_accept,
    .ssl_shutdown                  = default_ssl_shutdown,
    .ssl_read                      = default_ssl_read,
    .ssl_write                     = default_ssl_write,
    .ssl_get_error                 = default_ssl_get_error,
    .ssl_get_peer_certificate      = default_ssl_get_peer_certificate,
    .ssl_get_verify_result         = default_ssl_get_verify_result,

    .cert_get_ext_d2i = default_cert_get_ext_d2i,
    .sans_free        = default_sans_free,
    .sans_count       = default_sans_count,
    .sans_get         = default_sans_get,
    .asn1_get_data    = default_asn1_get_data,
    .asn1_get_len     = default_asn1_get_len,
};

enum vantaq_tls_server_status
vantaq_tls_server_create(const struct vantaq_tls_server_options *options,
                         const struct vantaq_tls_ops *ops, struct vantaq_tls_server **server_out) {
    struct vantaq_tls_server *server = NULL;
    SSL_CTX *ssl_ctx                 = NULL;
    int verify_mode;
    enum vantaq_tls_server_status status = VANTAQ_TLS_SERVER_STATUS_OK;

    if (options == NULL || server_out == NULL ||
        options->cbSize < sizeof(struct vantaq_tls_server_options) ||
        options->server_cert_path == NULL || options->server_cert_path[0] == '\0' ||
        options->server_key_path == NULL || options->server_key_path[0] == '\0' ||
        options->trusted_client_ca_path == NULL || options->trusted_client_ca_path[0] == '\0') {
        return VANTAQ_TLS_SERVER_STATUS_INVALID_ARGUMENT;
    }

    if (ops == NULL) {
        ops = &g_default_ops;
    }

    *server_out = NULL;

    if (OPENSSL_init_ssl(0, NULL) != 1) {
        return VANTAQ_TLS_SERVER_STATUS_INIT_ERROR;
    }

    ssl_ctx = (SSL_CTX *)ops->ssl_ctx_new();
    if (ssl_ctx == NULL) {
        return VANTAQ_TLS_SERVER_STATUS_INIT_ERROR;
    }

    if (options->disable_session_resumption) {
        SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_OFF);
    }

    if (options->cipher_list != NULL) {
        if (SSL_CTX_set_cipher_list(ssl_ctx, options->cipher_list) != 1) {
            status = VANTAQ_TLS_SERVER_STATUS_CONTEXT_CONFIG_ERROR;
            goto cleanup;
        }
    } else {
        if (SSL_CTX_set_cipher_list(
                ssl_ctx, "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-"
                         "AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384") != 1) {
            status = VANTAQ_TLS_SERVER_STATUS_CONTEXT_CONFIG_ERROR;
            goto cleanup;
        }
    }

    if (options->tls13_ciphersuites != NULL) {
        if (SSL_CTX_set_ciphersuites(ssl_ctx, options->tls13_ciphersuites) != 1) {
            status = VANTAQ_TLS_SERVER_STATUS_CONTEXT_CONFIG_ERROR;
            goto cleanup;
        }
    }

    if (SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION) != 1) {
        status = VANTAQ_TLS_SERVER_STATUS_CONTEXT_CONFIG_ERROR;
        goto cleanup;
    }

    if (ops->ssl_ctx_use_certificate_file(ssl_ctx, options->server_cert_path, SSL_FILETYPE_PEM) !=
        1) {
        status = VANTAQ_TLS_SERVER_STATUS_CERT_LOAD_ERROR;
        goto cleanup;
    }

    if (ops->ssl_ctx_use_PrivateKey_file(ssl_ctx, options->server_key_path, SSL_FILETYPE_PEM) !=
        1) {
        status = VANTAQ_TLS_SERVER_STATUS_KEY_LOAD_ERROR;
        goto cleanup;
    }

    if (ops->ssl_ctx_check_private_key(ssl_ctx) != 1) {
        status = VANTAQ_TLS_SERVER_STATUS_KEY_LOAD_ERROR;
        goto cleanup;
    }

    if (ops->ssl_ctx_load_verify_locations(ssl_ctx, options->trusted_client_ca_path, NULL) != 1) {
        status = VANTAQ_TLS_SERVER_STATUS_CLIENT_CA_LOAD_ERROR;
        goto cleanup;
    }

    /* Enable CRL checking if crl_path is provided */
    if (options->crl_path != NULL && options->crl_path[0] != '\0') {
        X509_STORE *store = SSL_CTX_get_cert_store(ssl_ctx);
        if (X509_STORE_load_locations(store, options->crl_path, NULL) != 1) {
            status = VANTAQ_TLS_SERVER_STATUS_CONTEXT_CONFIG_ERROR;
            goto cleanup;
        }
        X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
    }

    verify_mode = SSL_VERIFY_PEER;
    if (options->require_client_cert) {
        verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    }
    SSL_CTX_set_verify(ssl_ctx, verify_mode, NULL);
    SSL_CTX_set_verify_depth(ssl_ctx, options->verify_depth > 0 ? options->verify_depth : 4);

    server = (struct vantaq_tls_server *)calloc(1, sizeof(*server));
    if (server == NULL) {
        status = VANTAQ_TLS_SERVER_STATUS_INIT_ERROR;
        goto cleanup;
    }

    server->ssl_ctx = ssl_ctx;
    server->ops     = ops;
    *server_out     = server;
    return VANTAQ_TLS_SERVER_STATUS_OK;

cleanup:
    if (ssl_ctx != NULL) {
        ops->ssl_ctx_free(ssl_ctx);
    }
    return status;
}

void vantaq_tls_server_destroy(struct vantaq_tls_server *server) {
    if (server == NULL) {
        return;
    }

    if (server->ssl_ctx != NULL) {
        server->ops->ssl_ctx_free(server->ssl_ctx);
    }

    free(server);
}

enum vantaq_tls_server_status
vantaq_tls_server_handshake(struct vantaq_tls_server *server, int socket_fd,
                            struct vantaq_tls_connection **connection_out) {
    struct vantaq_tls_connection *connection = NULL;
    SSL *ssl                                 = NULL;
    int rc;
    enum vantaq_tls_server_status status = VANTAQ_TLS_SERVER_STATUS_HANDSHAKE_ERROR;

    if (server == NULL || connection_out == NULL || socket_fd < 0 || server->ssl_ctx == NULL) {
        return VANTAQ_TLS_SERVER_STATUS_INVALID_ARGUMENT;
    }

    *connection_out = NULL;

    ssl = (SSL *)server->ops->ssl_new(server->ssl_ctx);
    if (ssl == NULL) {
        return VANTAQ_TLS_SERVER_STATUS_INIT_ERROR;
    }

    if (server->ops->ssl_set_fd(ssl, socket_fd) != 1) {
        status = VANTAQ_TLS_SERVER_STATUS_INIT_ERROR;
        goto cleanup;
    }

    ERR_clear_error();

    rc = server->ops->ssl_accept(ssl);
    if (rc != 1) {
        int ssl_err = server->ops->ssl_get_error(ssl, rc);
        if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
            status = VANTAQ_TLS_SERVER_STATUS_HANDSHAKE_WANT_RETRY;
        } else {
            status = VANTAQ_TLS_SERVER_STATUS_HANDSHAKE_ERROR;
        }
        goto cleanup;
    }

    connection = (struct vantaq_tls_connection *)calloc(1, sizeof(*connection));
    if (connection == NULL) {
        status = VANTAQ_TLS_SERVER_STATUS_INIT_ERROR;
        goto cleanup;
    }

    connection->ssl = ssl;
    connection->ops = server->ops;
    *connection_out = connection;
    return VANTAQ_TLS_SERVER_STATUS_OK;

cleanup:
    if (ssl != NULL) {
        server->ops->ssl_free(ssl);
    }
    if (connection != NULL) {
        free(connection);
    }
    return status;
}

ssize_t vantaq_tls_connection_read(struct vantaq_tls_connection *connection, void *buf,
                                   size_t len) {
    int rc;
    int ssl_error;

    if (connection == NULL || connection->ssl == NULL || buf == NULL) {
        errno = EINVAL;
        return -1;
    }

    /* Guard against integer truncation or zero-length operations */
    if (len == 0 || len > (size_t)INT_MAX) {
        errno = EINVAL;
        return -1;
    }

    rc = connection->ops->ssl_read(connection->ssl, buf, (int)len);
    if (rc > 0) {
        return (ssize_t)rc;
    }

    ssl_error = connection->ops->ssl_get_error(connection->ssl, rc);
    if (ssl_error == SSL_ERROR_ZERO_RETURN) {
        return 0;
    }
    if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
        errno = EAGAIN;
        return -1;
    }
    /**
     * Note on portability:
     * OpenSSL < 3.0 reports unexpected EOF as SSL_ERROR_SYSCALL with errno == 0.
     * OpenSSL >= 3.0 reports it as SSL_ERROR_ZERO_RETURN.
     * We explicitly check for errno != 0 here to distinguish fatal syscall errors.
     */
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

    /* Guard against integer truncation or zero-length operations */
    if (len == 0 || len > (size_t)INT_MAX) {
        errno = EINVAL;
        return -1;
    }

    rc = connection->ops->ssl_write(connection->ssl, buf, (int)len);
    if (rc > 0) {
        return (ssize_t)rc;
    }

    ssl_error = connection->ops->ssl_get_error(connection->ssl, rc);
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
    X509 *peer_certificate = NULL;
    bool verified          = false;

    if (connection == NULL || connection->ssl == NULL) {
        return false;
    }

    peer_certificate = (X509 *)connection->ops->ssl_get_peer_certificate(connection->ssl);
    if (peer_certificate == NULL) {
        return false;
    }

    /* Check Extended Key Usage (EKU) for clientAuth
     * X509_check_purpose returns 1 if the certificate is intended for the purpose.
     */
    if (X509_check_purpose(peer_certificate, X509_PURPOSE_SSL_CLIENT, 0) != 1) {
        goto cleanup;
    }

    if (connection->ops->ssl_get_verify_result(connection->ssl) != X509_V_OK) {
        goto cleanup;
    }

    verified = true;

cleanup:
    if (peer_certificate != NULL) {
        X509_free(peer_certificate);
    }
    return verified;
}

struct x509_st *
vantaq_tls_connection_get_peer_certificate(const struct vantaq_tls_connection *connection) {
    if (connection == NULL || connection->ssl == NULL) {
        return NULL;
    }
    return connection->ops->ssl_get_peer_certificate(connection->ssl);
}

void vantaq_tls_connection_free_peer_certificate(struct x509_st *cert) {
    if (cert != NULL) {
        X509_free((X509 *)cert);
    }
}

const struct vantaq_tls_ops *
vantaq_tls_connection_get_ops(const struct vantaq_tls_connection *connection) {
    if (connection == NULL) {
        return &g_default_ops;
    }
    return connection->ops;
}

void vantaq_tls_connection_destroy(struct vantaq_tls_connection *connection) {
    if (connection == NULL) {
        return;
    }

    if (connection->ssl != NULL) {
        /* Attempt bidirectional clean shutdown (S-3, D-3) */
        if (connection->ops->ssl_shutdown(connection->ssl) == 0) {
            (void)connection->ops->ssl_shutdown(connection->ssl);
        }
        connection->ops->ssl_free(connection->ssl);
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
    case VANTAQ_TLS_SERVER_STATUS_HANDSHAKE_WANT_RETRY:
        return "tls handshake want retry";
    case VANTAQ_TLS_SERVER_STATUS_IO_ERROR:
        return "tls io error";
    default:
        return "unknown";
    }
}

const struct vantaq_tls_ops *vantaq_tls_ops_default(void) { return &g_default_ops; }
