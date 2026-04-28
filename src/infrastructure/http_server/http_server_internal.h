// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_INFRASTRUCTURE_HTTP_SERVER_HTTP_SERVER_INTERNAL_H
#define VANTAQ_INFRASTRUCTURE_HTTP_SERVER_HTTP_SERVER_INTERNAL_H

#include "application/security/verifier_context.h"
#include "infrastructure/http_server.h"
#include <sys/socket.h>
#include <time.h>

struct vantaq_http_connection {
    int fd;
    struct vantaq_tls_connection *tls_connection;
};

struct vantaq_http_health_context {
    const struct vantaq_runtime_config *runtime_config;
    const char *service_name;
    const char *service_version;
    const char *device_id;
    const char *device_model;
    const char *device_serial_number;
    const char *device_manufacturer;
    const char *device_firmware_version;
    const char *const *supported_claims;
    size_t supported_claims_count;
    const char *const *signature_algorithms;
    size_t signature_algorithms_count;
    const char *const *evidence_formats;
    size_t evidence_formats_count;
    const char *const *challenge_modes;
    size_t challenge_modes_count;
    const char *const *storage_modes;
    size_t storage_modes_count;
    const char *const *allowed_subnets;
    size_t allowed_subnets_count;
    bool dev_allow_all_networks;
    struct vantaq_audit_log *audit_log;
    struct vantaq_challenge_store *challenge_store;
    const vantaq_device_key_t *device_key;
    size_t challenge_ttl_seconds;
    struct timespec started_at;
    vantaq_http_log_fn err_logger;
    void *io_ctx;
};

struct vantaq_challenge_store;

struct vantaq_http_request_context {
    char peer_ipv4[16]; // INET_ADDRSTRLEN
    bool peer_ip_ok;
    int peer_status; // enum vantaq_peer_address_status
    char request_id[32];
    struct vantaq_verifier_auth_context verifier_auth;
};

// Internal helpers shared across route files
int vantaq_http_send_status_response(struct vantaq_http_connection *connection, int status_code);
int vantaq_http_write_all(struct vantaq_http_connection *connection, const char *buf, size_t len);

int log_text(vantaq_http_log_fn logger, void *ctx, const char *text);

int send_verifier_metadata_response(struct vantaq_http_connection *connection,
                                    const struct vantaq_http_health_context *ctx,
                                    const struct vantaq_http_request_context *req_ctx,
                                    const char *target_verifier_id);

int send_post_challenge_response(struct vantaq_http_connection *connection,
                                 const struct vantaq_http_health_context *ctx,
                                 const struct vantaq_http_request_context *req_ctx,
                                 const char *request_body);

int send_post_evidence_response(struct vantaq_http_connection *connection,
                                const struct vantaq_http_health_context *ctx,
                                const struct vantaq_http_request_context *req_ctx,
                                const char *request_body);

#endif
