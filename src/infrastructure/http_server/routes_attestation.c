// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/attestation_challenge/create_challenge.h"
#include "http_server_internal.h"
#include "infrastructure/audit_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void audit_challenge_creation(const struct vantaq_http_health_context *ctx,
                                     const struct vantaq_http_request_context *req_ctx,
                                     const char *result, const char *reason) {
    struct vantaq_audit_event event;
    if (!ctx->audit_log) {
        return;
    }

    memset(&event, 0, sizeof(event));
    event.cbSize                 = sizeof(event);
    event.time_utc_epoch_seconds = time(NULL);
    event.source_ip              = req_ctx->peer_ipv4;
    event.method                 = "POST";
    event.path                   = "/v1/attestation/challenge";
    event.result                 = result;
    event.reason                 = reason;
    event.verifier_id            = req_ctx->verifier_auth.identity.id;
    event.request_id             = req_ctx->request_id;

    vantaq_audit_log_append(ctx->audit_log, &event);
}

#define VANTAQ_CHALLENGE_JSON_BUF_SIZE 1024

int send_post_challenge_response(struct vantaq_http_connection *connection,
                                 const struct vantaq_http_health_context *ctx,
                                 const struct vantaq_http_request_context *req_ctx,
                                 const char *request_body) {
    struct vantaq_challenge *challenge = NULL;
    enum vantaq_create_challenge_status status;
    char json[VANTAQ_CHALLENGE_JSON_BUF_SIZE];
    char response[VANTAQ_CHALLENGE_JSON_BUF_SIZE + 256];
    char purpose[64] = "remote_attestation";
    long ttl         = (long)ctx->challenge_ttl_seconds;
    int n;
    const char *body_start;
    const char *ttl_pos;

    // Basic body parsing (skipping headers)
    body_start = strstr(request_body, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
    } else {
        body_start = request_body;
    }

    // Check purpose (simplified for MVP)
    if (strstr(body_start, "\"purpose\"") == NULL) {
        audit_challenge_creation(ctx, req_ctx, "denied", "missing_purpose");
        return vantaq_http_send_status_response(connection, 400);
    }

    // Do not accept verifier_id from request body (prevent spoofing)
    if (strstr(body_start, "\"verifier_id\"") != NULL) {
        audit_challenge_creation(ctx, req_ctx, "denied", "spoofed_verifier_id");
        return vantaq_http_send_status_response(connection, 400);
    }

    // Parse requested_ttl_seconds if present
    ttl_pos = strstr(body_start, "\"requested_ttl_seconds\"");
    if (ttl_pos != NULL) {
        long requested_ttl = 0;
        const char *val    = strchr(ttl_pos, ':');
        if (val != NULL) {
            requested_ttl = atol(val + 1);
            if (requested_ttl <= 0) {
                audit_challenge_creation(ctx, req_ctx, "denied", "invalid_ttl");
                return vantaq_http_send_status_response(connection, 400);
            }
            if (requested_ttl < ttl) {
                ttl = requested_ttl;
            }
        }
    }

    // Call application service
    status = vantaq_create_challenge(ctx->challenge_store, req_ctx->verifier_auth.identity.id,
                                     purpose, ttl, &challenge);
    if (status != VANTAQ_CREATE_CHALLENGE_STATUS_OK) {
        audit_challenge_creation(ctx, req_ctx, "denied", "internal_error");
        return vantaq_http_send_status_response(connection, 500);
    }

    audit_challenge_creation(ctx, req_ctx, "allowed", "ok");

    // Construct response JSON
    n = snprintf(json, sizeof(json),
                 "{\"challenge_id\":\"%s\",\"nonce\":\"%s\",\"verifier_id\":\"%s\",\"purpose\":\"%"
                 "s\",\"expires_in_seconds\":%ld}\n",
                 vantaq_challenge_get_id(challenge), vantaq_challenge_get_nonce_hex(challenge),
                 vantaq_challenge_get_verifier_id(challenge),
                 vantaq_challenge_get_purpose(challenge), ttl);

    if (n < 0 || (size_t)n >= sizeof(json)) {
        return -1;
    }

    n = snprintf(response, sizeof(response),
                 "HTTP/1.1 201 Created\r\n"
                 "Content-Type: application/json\r\n"
                 "Content-Length: %d\r\n"
                 "Connection: close\r\n"
                 "\r\n"
                 "%s",
                 n, json);

    if (n < 0 || (size_t)n >= sizeof(response)) {
        return -1;
    }

    return vantaq_http_write_all(connection, response, (size_t)strlen(response));
}
