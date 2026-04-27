// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/security/get_verifier_metadata.h"
#include "http_server_internal.h"
#include "infrastructure/audit_log.h"
#include "infrastructure/memory/zero_struct.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VANTAQ_VERIFIER_METADATA_JSON_BUF_SIZE (VANTAQ_MAX_LIST_ITEMS * 1024 + 1024)

/**
 * JSON string escaping to prevent injection.
 * Escapes '"', '\', and control characters.
 */
static int append_json_str(char *buf, size_t size, size_t *used, const char *str) {
    size_t i;
    int n;

    if (str == NULL) {
        str = "";
    }

    n = snprintf(buf + *used, size - *used, "\"");
    if (n < 0 || (size_t)n >= size - *used)
        return -1;
    *used += (size_t)n;

    for (i = 0; str[i] != '\0'; i++) {
        const char *esc = NULL;
        switch (str[i]) {
        case '\"':
            esc = "\\\"";
            break;
        case '\\':
            esc = "\\\\";
            break;
        case '\b':
            esc = "\\b";
            break;
        case '\f':
            esc = "\\f";
            break;
        case '\n':
            esc = "\\n";
            break;
        case '\r':
            esc = "\\r";
            break;
        case '\t':
            esc = "\\t";
            break;
        default:
            if ((unsigned char)str[i] < 32) {
                /* Control character escaping */
                n = snprintf(buf + *used, size - *used, "\\u%04x", (unsigned int)str[i]);
            } else {
                n = snprintf(buf + *used, size - *used, "%c", str[i]);
            }
            break;
        }

        if (esc != NULL) {
            n = snprintf(buf + *used, size - *used, "%s", esc);
        }

        if (n < 0 || (size_t)n >= size - *used)
            return -1;
        *used += (size_t)n;
    }

    n = snprintf(buf + *used, size - *used, "\"");
    if (n < 0 || (size_t)n >= size - *used)
        return -1;
    *used += (size_t)n;

    return 0;
}

static int append_json_array(char *buf, size_t size, size_t *used, const char *key,
                             const void *items, size_t item_size, size_t count) {
    size_t i;
    int n;

    n = snprintf(buf + *used, size - *used, ",\"%s\":[", key);
    if (n < 0 || (size_t)n >= size - *used)
        return -1;
    *used += (size_t)n;

    for (i = 0; i < count; i++) {
        const char *item = (const char *)items + (i * item_size);
        if (append_json_str(buf, size, used, item) != 0)
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

/**
 * Audit logging for metadata access.
 */
static void audit_metadata_read(const struct vantaq_http_health_context *ctx,
                                const struct vantaq_http_request_context *req_ctx,
                                const char *target_id, const char *result, const char *reason) {
    struct vantaq_audit_event event;
    if (!ctx->audit_log) {
        return;
    }

    VANTAQ_ZERO_STRUCT(event);
    event.cbSize                 = sizeof(event);
    event.time_utc_epoch_seconds = time(NULL);
    event.source_ip              = req_ctx->peer_ipv4;
    event.method                 = "GET";
    event.path                   = target_id; /* Log the target verifier as the path */
    event.result                 = result;
    event.reason                 = reason;
    event.verifier_id            = req_ctx->verifier_auth.identity.id;
    event.request_id             = req_ctx->request_id;

    vantaq_audit_log_append(ctx->audit_log, &event);
}

int send_verifier_metadata_response(struct vantaq_http_connection *connection,
                                    const struct vantaq_http_health_context *ctx,
                                    const struct vantaq_http_request_context *req_ctx,
                                    const char *target_verifier_id) {
    struct vantaq_verifier_metadata_dto dto;
    enum vantaq_verifier_metadata_status status;
    char *json     = NULL;
    char *response = NULL;
    size_t used    = 0;
    int n;
    int ret = -1;

    /* Heap allocation to prevent stack overflow on concurrent threads */
    json     = malloc(VANTAQ_VERIFIER_METADATA_JSON_BUF_SIZE);
    response = malloc(VANTAQ_VERIFIER_METADATA_JSON_BUF_SIZE + 512);
    if (json == NULL || response == NULL) {
        (void)log_text(ctx->err_logger, ctx->io_ctx,
                       "http server: failed to allocate metadata buffers\n");
        (void)vantaq_http_send_status_response(connection, 500);
        goto cleanup;
    }

    VANTAQ_VERIFIER_METADATA_DTO_INIT(dto);

    status = vantaq_get_verifier_metadata(ctx->runtime_config, &req_ctx->verifier_auth.identity,
                                          target_verifier_id, &dto);

    if (status == VANTAQ_VERIFIER_METADATA_NOT_FOUND) {
        audit_metadata_read(ctx, req_ctx, target_verifier_id, "FAILURE", "NOT_FOUND");
        ret = vantaq_http_send_status_response(connection, 404);
        goto cleanup;
    } else if (status == VANTAQ_VERIFIER_METADATA_UNAUTHORIZED) {
        audit_metadata_read(ctx, req_ctx, target_verifier_id, "FAILURE", "UNAUTHORIZED");
        ret = vantaq_http_send_status_response(connection, 401);
        goto cleanup;
    } else if (status == VANTAQ_VERIFIER_METADATA_FORBIDDEN) {
        audit_metadata_read(ctx, req_ctx, target_verifier_id, "FAILURE", "FORBIDDEN");
        ret = vantaq_http_send_status_response(connection, 403);
        goto cleanup;
    } else if (status != VANTAQ_VERIFIER_METADATA_OK) {
        audit_metadata_read(ctx, req_ctx, target_verifier_id, "FAILURE", "INTERNAL_ERROR");
        ret = vantaq_http_send_status_response(connection, 500);
        goto cleanup;
    }

    audit_metadata_read(ctx, req_ctx, target_verifier_id, "SUCCESS", NULL);

    /* Safe snprintf with truncation guards */
    n = snprintf(json + used, VANTAQ_VERIFIER_METADATA_JSON_BUF_SIZE - used, "{\"verifier_id\":");
    if (n < 0 || (size_t)n >= VANTAQ_VERIFIER_METADATA_JSON_BUF_SIZE - used)
        goto internal_error;
    used += (size_t)n;
    if (append_json_str(json, VANTAQ_VERIFIER_METADATA_JSON_BUF_SIZE, &used, dto.verifier_id) != 0)
        goto internal_error;

    n = snprintf(json + used, VANTAQ_VERIFIER_METADATA_JSON_BUF_SIZE - used, ",\"status\":");
    if (n < 0 || (size_t)n >= VANTAQ_VERIFIER_METADATA_JSON_BUF_SIZE - used)
        goto internal_error;
    used += (size_t)n;
    if (append_json_str(json, VANTAQ_VERIFIER_METADATA_JSON_BUF_SIZE, &used, dto.status) != 0)
        goto internal_error;

    if (append_json_array(json, VANTAQ_VERIFIER_METADATA_JSON_BUF_SIZE, &used, "roles", dto.roles,
                          sizeof(dto.roles[0]), dto.roles_count) != 0)
        goto internal_error;
    if (append_json_array(json, VANTAQ_VERIFIER_METADATA_JSON_BUF_SIZE, &used, "allowed_apis",
                          dto.allowed_apis, sizeof(dto.allowed_apis[0]),
                          dto.allowed_apis_count) != 0)
        goto internal_error;

    n = snprintf(json + used, VANTAQ_VERIFIER_METADATA_JSON_BUF_SIZE - used, "}\n");
    if (n < 0 || (size_t)n >= VANTAQ_VERIFIER_METADATA_JSON_BUF_SIZE - used)
        goto internal_error;
    used += (size_t)n;

    n = snprintf(response, VANTAQ_VERIFIER_METADATA_JSON_BUF_SIZE + 512,
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: application/json\r\n"
                 "Content-Length: %zu\r\n"
                 "Connection: close\r\n"
                 "\r\n"
                 "%s",
                 used, json);
    if (n < 0 || (size_t)n >= VANTAQ_VERIFIER_METADATA_JSON_BUF_SIZE + 512)
        goto internal_error;

    ret = vantaq_http_write_all(connection, response, (size_t)n);
    goto cleanup;

internal_error:
    (void)log_text(ctx->err_logger, ctx->io_ctx,
                   "http server: failed to serialize metadata response\n");
    ret = vantaq_http_send_status_response(connection, 500);

cleanup:
    free(json);
    free(response);
    return ret;
}
