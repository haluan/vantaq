// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/security/get_verifier_metadata.h"
#include "http_server_internal.h"
#include <stdio.h>
#include <string.h>

#define VANTAQ_VERIFIER_METADATA_JSON_BUF_SIZE (VANTAQ_MAX_LIST_ITEMS * 1024 + 1024)

static int append_str(char *buf, size_t size, size_t *used, const char *str) {
    int n = snprintf(buf + *used, size - *used, "\"%s\"", str);
    if (n < 0 || (size_t)n >= size - *used)
        return -1;
    *used += (size_t)n;
    return 0;
}

static int append_array(char *buf, size_t size, size_t *used, const char *key,
                        const char *const *items, size_t count) {
    size_t i;
    int n = snprintf(buf + *used, size - *used, ",\"%s\":[", key);
    if (n < 0 || (size_t)n >= size - *used)
        return -1;
    *used += (size_t)n;

    for (i = 0; i < count; i++) {
        if (append_str(buf, size, used, items[i]) != 0)
            return -1;
        if (i < count - 1) {
            n = snprintf(buf + *used, size - *used, ",");
            if (n < 0 || (size_t)n >= size - *used)
                return -1;
            *used += (size_t)n;
        }
    }

    n = snprintf(buf + *used, size - *used, "]");
    if (n < 0 || (size_t)n >= size - *used)
        return -1;
    *used += (size_t)n;
    return 0;
}

int send_verifier_metadata_response(struct vantaq_http_connection *connection,
                                    const struct vantaq_http_health_context *ctx,
                                    const struct vantaq_http_request_context *req_ctx,
                                    const char *target_verifier_id) {
    struct vantaq_verifier_metadata_dto dto;
    enum vantaq_verifier_metadata_status status;
    char json[VANTAQ_VERIFIER_METADATA_JSON_BUF_SIZE];
    char response[VANTAQ_VERIFIER_METADATA_JSON_BUF_SIZE + 512];
    size_t used = 0;
    int n;

    status = vantaq_get_verifier_metadata(ctx->runtime_config, &req_ctx->verifier_auth.identity,
                                          target_verifier_id, &dto);

    if (status == VANTAQ_VERIFIER_METADATA_NOT_FOUND) {
        return vantaq_http_send_status_response(connection, 404);
    } else if (status == VANTAQ_VERIFIER_METADATA_FORBIDDEN) {
        return vantaq_http_send_status_response(connection, 403);
    } else if (status != VANTAQ_VERIFIER_METADATA_OK) {
        return vantaq_http_send_status_response(connection, 500);
    }

    // Manual JSON construction
    n = snprintf(json + used, sizeof(json) - used, "{\"verifier_id\":");
    if (n < 0)
        return -1;
    used += (size_t)n;
    if (append_str(json, sizeof(json), &used, dto.verifier_id) != 0)
        return -1;

    n = snprintf(json + used, sizeof(json) - used, ",\"status\":");
    if (n < 0)
        return -1;
    used += (size_t)n;
    if (append_str(json, sizeof(json), &used, dto.status) != 0)
        return -1;

    if (append_array(json, sizeof(json), &used, "roles", dto.roles, dto.roles_count) != 0)
        return -1;
    if (append_array(json, sizeof(json), &used, "allowed_apis", dto.allowed_apis,
                     dto.allowed_apis_count) != 0)
        return -1;

    n = snprintf(json + used, sizeof(json) - used, "}\n");
    if (n < 0)
        return -1;
    used += (size_t)n;

    n = snprintf(response, sizeof(response),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: application/json\r\n"
                 "Content-Length: %zu\r\n"
                 "Connection: close\r\n"
                 "\r\n"
                 "%s",
                 used, json);
    if (n < 0 || (size_t)n >= sizeof(response))
        return -1;

    return vantaq_http_write_all(connection, response, (size_t)n);
}
