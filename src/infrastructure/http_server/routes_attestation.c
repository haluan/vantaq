// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/attestation_challenge/create_challenge.h"
#include "http_server_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    long ttl         = 30;
    int n;
    const char *body_start;

    // Basic body parsing (skipping headers)
    body_start = strstr(request_body, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
    } else {
        body_start = request_body;
    }

    // Check purpose (simplified for MVP)
    if (strstr(body_start, "\"purpose\"") == NULL) {
        return vantaq_http_send_status_response(connection, 400);
    }

    // Do not accept verifier_id from request body (prevent spoofing)
    if (strstr(body_start, "\"verifier_id\"") != NULL) {
        return vantaq_http_send_status_response(connection, 400);
    }

    // Call application service
    status = vantaq_create_challenge(ctx->challenge_store, req_ctx->verifier_auth.identity.id,
                                     purpose, ttl, &challenge);

    if (status != VANTAQ_CREATE_CHALLENGE_STATUS_OK) {
        return vantaq_http_send_status_response(connection, 500);
    }

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
