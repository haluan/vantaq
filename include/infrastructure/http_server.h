// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_INFRASTRUCTURE_HTTP_SERVER_H
#define VANTAQ_INFRASTRUCTURE_HTTP_SERVER_H

#include <stdbool.h>
#include <stddef.h>

typedef int (*vantaq_http_log_fn)(void *ctx, const char *text);
typedef struct vantaq_device_key_t vantaq_device_key_t;
struct vantaq_latest_evidence_store;

enum vantaq_http_server_status {
    VANTAQ_HTTP_SERVER_STATUS_OK = 0,
    VANTAQ_HTTP_SERVER_STATUS_INVALID_ARGUMENT,
    VANTAQ_HTTP_SERVER_STATUS_BIND_ERROR,
    VANTAQ_HTTP_SERVER_STATUS_LISTEN_ERROR,
    VANTAQ_HTTP_SERVER_STATUS_TLS_INIT_ERROR,
    VANTAQ_HTTP_SERVER_STATUS_RUNTIME_ERROR,
};

#include "infrastructure/config_loader.h"

struct vantaq_http_server_options {
    size_t cbSize;
    const struct vantaq_runtime_config *runtime_config;
    const char *listen_host;
    int listen_port;
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
    const char *audit_log_path;
    size_t audit_log_max_bytes;
    bool tls_enabled;
    const char *tls_server_cert_path;
    const char *tls_server_key_path;
    const char *tls_trusted_client_ca_path;
    bool tls_require_client_cert;
    struct vantaq_challenge_store *challenge_store;
    struct vantaq_latest_evidence_store *latest_evidence_store;
    const vantaq_device_key_t *device_key;
    size_t challenge_ttl_seconds;
    vantaq_http_log_fn write_out;
    vantaq_http_log_fn write_err;
    void *io_ctx;
};

/*
 * Runs the HTTP server loop in single-threaded mode. Each client connection is
 * handled synchronously to completion before the next accept() iteration.
 *
 * This design provides strict resource isolation and predictable stack usage
 * for embedded environments, but means one slow client can block the server.
 * Intended for low-concurrency, trusted-network administrative interfaces.
 */
enum vantaq_http_server_status vantaq_http_server_run(const struct vantaq_http_server_options *options);
const char *vantaq_http_server_status_text(enum vantaq_http_server_status status);

#endif
