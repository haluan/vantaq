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
    VANTAQ_TLS_SERVER_STATUS_HANDSHAKE_WANT_RETRY,
    VANTAQ_TLS_SERVER_STATUS_IO_ERROR,
};

struct vantaq_tls_server_options {
    size_t cbSize;
    const char *server_cert_path;
    const char *server_key_path;
    const char *trusted_client_ca_path;
    bool require_client_cert;

    /**
     * Security configuration (TLS hardening)
     *
     * Note on forward compatibility: Fields added in future versions will be
     * ignored by older binary versions of this library. The documented default
     * values will apply.
     */
    const char *cipher_list;         /* TLS 1.2 ciphers (e.g., "ECDHE+AESGCM") */
    const char *tls13_ciphersuites;  /* TLS 1.3 ciphersuites */
    int verify_depth;                /* Max chain depth */
    bool disable_session_resumption; /* True to force re-verification */
    const char *crl_path;            /* Path to CRL file (PEM) */
};

struct vantaq_tls_ops {
    void *(*ssl_ctx_new)(void);
    void (*ssl_ctx_free)(void *ctx);
    int (*ssl_ctx_use_certificate_file)(void *ctx, const char *file, int type);
    int (*ssl_ctx_use_PrivateKey_file)(void *ctx, const char *file, int type);
    int (*ssl_ctx_check_private_key)(void *ctx);
    int (*ssl_ctx_load_verify_locations)(void *ctx, const char *cafile, const char *capath);
    void *(*ssl_new)(void *ctx);
    void (*ssl_free)(void *ssl);
    int (*ssl_set_fd)(void *ssl, int fd);
    int (*ssl_accept)(void *ssl);
    int (*ssl_shutdown)(void *ssl);
    int (*ssl_read)(void *ssl, void *buf, int num);
    int (*ssl_write)(void *ssl, const void *buf, int num);
    int (*ssl_get_error)(void *ssl, int ret);
    struct x509_st *(*ssl_get_peer_certificate)(void *ssl);
    long (*ssl_get_verify_result)(void *ssl);

    /* X.509 Certificate and Extension Accessors (Mockable) */
    void *(*cert_get_ext_d2i)(struct x509_st *x, int nid, int *crit, int *idx);
    void (*sans_free)(void *sk, void (*free_func)(void *));
    int (*sans_count)(const void *sk);
    void *(*sans_get)(const void *sk, int idx);
    const unsigned char *(*asn1_get_data)(const void *as);
    int (*asn1_get_len)(const void *as);
};

struct vantaq_tls_server;
struct vantaq_tls_connection;
struct x509_st; /* Forward decl for X509 to avoid including openssl headers here */

/**
 * Initialize a new TLS server context.
 *
 * Thread Safety: This function is thread-safe. Multiple servers can be created
 * and destroyed concurrently. Once created, the struct vantaq_tls_server is read-only
 * and can be used for concurrent handshakes across multiple threads.
 */
enum vantaq_tls_server_status
vantaq_tls_server_create(const struct vantaq_tls_server_options *options,
                         const struct vantaq_tls_ops *ops, /* NULL for default OpenSSL */
                         struct vantaq_tls_server **server_out);
void vantaq_tls_server_destroy(struct vantaq_tls_server *server);

/**
 * Perform a TLS handshake on an existing socket.
 *
 * socket_fd: The caller is responsible for ensuring socket_fd is a valid, open
 * descriptor. If the fd was recycled from a closed connection, the handshake will
 * be attempted on the new socket.
 */
enum vantaq_tls_server_status
vantaq_tls_server_handshake(struct vantaq_tls_server *server, int socket_fd,
                            struct vantaq_tls_connection **connection_out);

ssize_t vantaq_tls_connection_read(struct vantaq_tls_connection *connection, void *buf, size_t len);
ssize_t vantaq_tls_connection_write(struct vantaq_tls_connection *connection, const void *buf,
                                    size_t len);
bool vantaq_tls_connection_peer_cert_verified(const struct vantaq_tls_connection *connection);
struct x509_st *
vantaq_tls_connection_get_peer_certificate(const struct vantaq_tls_connection *connection);
void vantaq_tls_connection_free_peer_certificate(struct x509_st *cert);
const struct vantaq_tls_ops *
vantaq_tls_connection_get_ops(const struct vantaq_tls_connection *connection);
void vantaq_tls_connection_destroy(struct vantaq_tls_connection *connection);

const char *vantaq_tls_server_status_text(enum vantaq_tls_server_status status);
const struct vantaq_tls_ops *vantaq_tls_ops_default(void);

#endif
