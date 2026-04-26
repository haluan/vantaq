// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_INFRASTRUCTURE_HTTP_SERVER_H
#define VANTAQ_INFRASTRUCTURE_HTTP_SERVER_H

typedef void (*vantaq_http_log_fn)(void *ctx, const char *text);

enum vantaq_http_server_status {
    VANTAQ_HTTP_SERVER_STATUS_OK = 0,
    VANTAQ_HTTP_SERVER_STATUS_INVALID_ARGUMENT,
    VANTAQ_HTTP_SERVER_STATUS_BIND_ERROR,
    VANTAQ_HTTP_SERVER_STATUS_LISTEN_ERROR,
    VANTAQ_HTTP_SERVER_STATUS_RUNTIME_ERROR,
};

struct vantaq_http_server_options {
    const char *listen_host;
    int listen_port;
    const char *service_name;
    const char *service_version;
    const char *device_id;
    const char *device_model;
    const char *device_serial_number;
    const char *device_manufacturer;
    const char *device_firmware_version;
    vantaq_http_log_fn write_out;
    vantaq_http_log_fn write_err;
    void *io_ctx;
};

enum vantaq_http_server_status vantaq_http_server_run(const struct vantaq_http_server_options *options);
const char *vantaq_http_server_status_text(enum vantaq_http_server_status status);

#endif
