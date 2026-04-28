// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/attestation_challenge/create_challenge.h"
#include "application/evidence/create_evidence.h"
#include "http_server_internal.h"
#include "infrastructure/audit_log.h"
#include "infrastructure/memory/zero_struct.h"
#include "json_utils.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Static assertion to ensure buffer is large enough for all fields at maximum length + JSON
 * overhead */
#define EXPECTED_MAX_JSON                                                                          \
    (VANTAQ_CHALLENGE_ID_MAX + VANTAQ_NONCE_HEX_MAX + VANTAQ_VERIFIER_ID_MAX +                     \
     VANTAQ_PURPOSE_MAX + 128)
#define VANTAQ_CHALLENGE_JSON_BUF_SIZE 1024
static_assert(VANTAQ_CHALLENGE_JSON_BUF_SIZE > EXPECTED_MAX_JSON,
              "JSON buffer too small for maximum field sizes");

#define VANTAQ_EVIDENCE_JSON_BUF_SIZE 4096
#define VANTAQ_MAX_CLAIMS_COUNT 16

static void audit_challenge_creation(const struct vantaq_http_health_context *ctx,
                                     const struct vantaq_http_request_context *req_ctx,
                                     const char *result, const char *reason) {
    struct vantaq_audit_event event;
    if (!ctx || !req_ctx || !ctx->audit_log) {
        return;
    }

    VANTAQ_ZERO_STRUCT(event);
    event.cbSize                 = sizeof(event);
    event.time_utc_epoch_seconds = time(NULL);
    event.source_ip              = req_ctx->peer_ipv4;
    event.method                 = "POST";
    event.path                   = "/v1/attestation/challenge";
    event.result                 = result;
    event.reason                 = reason;
    event.verifier_id            = req_ctx->verifier_auth.identity.id;
    event.request_id             = req_ctx->request_id;

    /* S-5: Log failures to stderr if audit log write fails */
    if (vantaq_audit_log_append(ctx->audit_log, &event) != VANTAQ_AUDIT_LOG_STATUS_OK) {
        fprintf(stderr, "VANTAQ: Failed to write audit event for challenge creation (%s: %s)\n",
                result, reason);
    }
}

static void audit_evidence_creation(const struct vantaq_http_health_context *ctx,
                                    const struct vantaq_http_request_context *req_ctx,
                                    const char *result, const char *reason) {
    struct vantaq_audit_event event;
    if (!ctx || !req_ctx || !ctx->audit_log) {
        return;
    }

    VANTAQ_ZERO_STRUCT(event);
    event.cbSize                 = sizeof(event);
    event.time_utc_epoch_seconds = time(NULL);
    event.source_ip              = req_ctx->peer_ipv4;
    event.method                 = "POST";
    event.path                   = "/v1/attestation/evidence";
    event.result                 = result;
    event.reason                 = reason;
    event.verifier_id            = req_ctx->verifier_auth.identity.id;
    event.request_id             = req_ctx->request_id;

    if (vantaq_audit_log_append(ctx->audit_log, &event) != VANTAQ_AUDIT_LOG_STATUS_OK) {
        fprintf(stderr, "VANTAQ: Failed to write audit event for evidence creation (%s: %s)\n",
                result, reason);
    }
}

int send_post_challenge_response(struct vantaq_http_connection *connection,
                                 const struct vantaq_http_health_context *ctx,
                                 const struct vantaq_http_request_context *req_ctx,
                                 const char *request_body) {
    /* Robust NULL guards for all inputs */
    if (!connection || !ctx || !req_ctx || !request_body)
        return -1;

    struct vantaq_challenge *challenge = NULL;
    enum vantaq_create_challenge_status status;
    char json[VANTAQ_CHALLENGE_JSON_BUF_SIZE];
    char response[VANTAQ_CHALLENGE_JSON_BUF_SIZE + 256];
    char purpose[VANTAQ_PURPOSE_MAX];
    long ttl = (long)ctx->challenge_ttl_seconds;
    int n;
    const char *body_start;
    int result = -1;

    /* Skip HTTP headers to reach JSON body */
    body_start = strstr(request_body, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
    } else {
        body_start = request_body;
    }

    /* Use robust JSON extraction instead of strstr */
    if (!vantaq_json_extract_str(body_start, "purpose", purpose, sizeof(purpose))) {
        audit_challenge_creation(ctx, req_ctx, "denied", "missing_purpose");
        return vantaq_http_send_status_response(connection, 400);
    }

    /* Prevent spoofing of verifier_id from request body */
    char spoofed_id[16];
    if (vantaq_json_extract_str(body_start, "verifier_id", spoofed_id, sizeof(spoofed_id))) {
        audit_challenge_creation(ctx, req_ctx, "denied", "spoofed_verifier_id");
        return vantaq_http_send_status_response(connection, 400);
    }

    /* Safe TTL parsing with strtol-based helper */
    long requested_ttl;
    if (vantaq_json_extract_long(body_start, "requested_ttl_seconds", &requested_ttl)) {
        if (requested_ttl <= 0) {
            audit_challenge_creation(ctx, req_ctx, "denied", "invalid_ttl");
            return vantaq_http_send_status_response(connection, 400);
        }
        if (requested_ttl < ttl) {
            ttl = requested_ttl;
        }
    }

    /* Call application service */
    status = vantaq_create_challenge(ctx->challenge_store, req_ctx->verifier_auth.identity.id,
                                     purpose, ttl, &challenge);
    if (status != VANTAQ_CREATE_CHALLENGE_STATUS_OK) {
        const char *reason = "internal_error";
        int http_status    = 500;

        if (status == VANTAQ_CREATE_CHALLENGE_STATUS_ERROR_INVALID_ARGS) {
            reason      = "invalid_arguments";
            http_status = 400;
        } else if (status == VANTAQ_CREATE_CHALLENGE_STATUS_ERROR_STORE_QUOTA) {
            reason      = "verifier_quota_exceeded";
            http_status = 429;
        } else if (status == VANTAQ_CREATE_CHALLENGE_STATUS_ERROR_STORE_FULL) {
            reason      = "system_capacity_exceeded";
            http_status = 503;
        }

        audit_challenge_creation(ctx, req_ctx, "denied", reason);
        return vantaq_http_send_status_response(connection, http_status);
    }

    /* JSON escape all string fields in the response */
    char esc_id[VANTAQ_CHALLENGE_ID_MAX * 2];
    char esc_nonce[VANTAQ_NONCE_HEX_MAX * 2];
    char esc_v_id[VANTAQ_VERIFIER_ID_MAX * 2];
    char esc_purpose[VANTAQ_PURPOSE_MAX * 2];

    if (vantaq_json_escape_str(vantaq_challenge_get_id(challenge), esc_id, sizeof(esc_id)) == 0 ||
        vantaq_json_escape_str(vantaq_challenge_get_nonce_hex(challenge), esc_nonce,
                               sizeof(esc_nonce)) == 0 ||
        vantaq_json_escape_str(vantaq_challenge_get_verifier_id(challenge), esc_v_id,
                               sizeof(esc_v_id)) == 0 ||
        vantaq_json_escape_str(vantaq_challenge_get_purpose(challenge), esc_purpose,
                               sizeof(esc_purpose)) == 0) {
        goto cleanup;
    }

    n = snprintf(json, sizeof(json),
                 "{\"challenge_id\":\"%s\",\"nonce\":\"%s\",\"verifier_id\":\"%s\","
                 "\"purpose\":\"%s\",\"expires_in_seconds\":%ld}\n",
                 esc_id, esc_nonce, esc_v_id, esc_purpose, ttl);

    /* Handle truncation and resource cleanup */
    if (n < 0 || (size_t)n >= sizeof(json)) {
        goto cleanup;
    }

    /* Correct Content-Length formatting with %zu */
    n = snprintf(response, sizeof(response),
                 "HTTP/1.1 201 Created\r\n"
                 "Content-Type: application/json\r\n"
                 "Content-Length: %zu\r\n"
                 "Connection: close\r\n"
                 "\r\n"
                 "%s",
                 (size_t)n, json);

    if (n < 0 || (size_t)n >= sizeof(response)) {
        goto cleanup;
    }

    /* Only log "allowed" once we know the response is fully constructed and ready to send */
    audit_challenge_creation(ctx, req_ctx, "allowed", "ok");
    result = vantaq_http_write_all(connection, response, (size_t)strlen(response));

cleanup:
    /* Ensure challenge domain object is freed if we didn't successfully send it */
    /* Note: if result == 0 (success), the challenge is in the store and valid.
       Actually, vantaq_create_challenge already put it in the store.
       If snprintf failed, we should probably remove it from the store to avoid leaking slots (S-4).
     */
    if (result != 0 && challenge != NULL) {
        vantaq_challenge_store_remove(ctx->challenge_store, vantaq_challenge_get_id(challenge));
        /* The above destroy the challenge internally in the store implementation I wrote. */
    }
    return result;
}

int send_post_evidence_response(struct vantaq_http_connection *connection,
                                const struct vantaq_http_health_context *ctx,
                                const struct vantaq_http_request_context *req_ctx,
                                const char *request_body) {
    if (!connection || !ctx || !req_ctx || !request_body)
        return -1;

    struct vantaq_create_evidence_req req;
    struct vantaq_create_evidence_res res;
    char challenge_id[VANTAQ_CHALLENGE_ID_MAX];
    char nonce[VANTAQ_NONCE_HEX_MAX];
    char json[VANTAQ_EVIDENCE_JSON_BUF_SIZE];
    char response[VANTAQ_EVIDENCE_JSON_BUF_SIZE + 512];
    const char *body_start;
    int result = -1;

    VANTAQ_ZERO_STRUCT(req);
    VANTAQ_ZERO_STRUCT(res);

    body_start = strstr(request_body, "\r\n\r\n");
    body_start = body_start ? body_start + 4 : request_body;

    if (!vantaq_json_extract_str(body_start, "challenge_id", challenge_id, sizeof(challenge_id)) ||
        !vantaq_json_extract_str(body_start, "nonce", nonce, sizeof(nonce))) {
        audit_evidence_creation(ctx, req_ctx, "denied", "missing_required_fields");
        return vantaq_http_send_status_response(connection, 400);
    }

    req.challenge_id = challenge_id;
    req.nonce        = nonce;
    // Note: claims are hardcoded in the application service for now as per spec.

    vantaq_app_evidence_err_t app_err = vantaq_app_create_evidence(
        ctx->challenge_store, ctx->latest_evidence_store, ctx->device_key,
        req_ctx->verifier_auth.identity.id, &req, (int64_t)time(NULL), &res);

    if (app_err != VANTAQ_APP_EVIDENCE_OK) {
        const char *reason = "internal_error";
        int http_status    = 500;

        switch (app_err) {
        case VANTAQ_APP_EVIDENCE_ERR_CHALLENGE_NOT_FOUND:
            reason      = "challenge_not_found";
            http_status = 404;
            break;
        case VANTAQ_APP_EVIDENCE_ERR_CHALLENGE_EXPIRED:
            reason      = "challenge_expired";
            http_status = 409;
            break;
        case VANTAQ_APP_EVIDENCE_ERR_CHALLENGE_USED:
            reason      = "CHALLENGE_ALREADY_USED";
            http_status = 409;
            break;
        case VANTAQ_APP_EVIDENCE_ERR_NONCE_MISMATCH:
            reason      = "NONCE_MISMATCH";
            http_status = 409;
            break;
        case VANTAQ_APP_EVIDENCE_ERR_VERIFIER_MISMATCH:
            reason      = "VERIFIER_MISMATCH";
            http_status = 403;
            break;
        case VANTAQ_APP_EVIDENCE_ERR_SIGNING_FAILED:
            reason      = "SIGNING_FAILED";
            http_status = 500;
            break;
        default:
            break;
        }

        audit_evidence_creation(ctx, req_ctx, "denied", reason);

        /* Return JSON error response to meet integration test requirements */
        char error_json[512];
        char error_response[1024];
        int error_json_n = snprintf(error_json, sizeof(error_json),
                                    "{\"error\":{\"code\":\"%s\",\"request_id\":\"%s\"}}\n", reason,
                                    req_ctx->request_id);
        if (error_json_n <= 0 || (size_t)error_json_n >= sizeof(error_json)) {
            return vantaq_http_send_status_response(connection, http_status);
        }

        int error_resp_n = snprintf(error_response, sizeof(error_response),
                                    "HTTP/1.1 %d %s\r\n"
                                    "Content-Type: application/json\r\n"
                                    "Content-Length: %d\r\n"
                                    "Connection: close\r\n"
                                    "\r\n"
                                    "%s",
                                    http_status, (http_status == 409) ? "Conflict" : "Error",
                                    error_json_n, error_json);

        if (error_resp_n <= 0 || (size_t)error_resp_n >= sizeof(error_response)) {
            return vantaq_http_send_status_response(connection, http_status);
        }

        return vantaq_http_write_all(connection, error_response, (size_t)error_resp_n);
    }

    // Success - Construct JSON
    char esc_ev_id[VANTAQ_MAX_FIELD_LEN * 2];
    char esc_dev_id[VANTAQ_MAX_FIELD_LEN * 2];

    vantaq_json_escape_str(vantaq_evidence_get_evidence_id(res.evidence), esc_ev_id,
                           sizeof(esc_ev_id));
    vantaq_json_escape_str(vantaq_evidence_get_device_id(res.evidence), esc_dev_id,
                           sizeof(esc_dev_id));

    int n =
        snprintf(json, sizeof(json),
                 "{\"evidence_id\":\"%s\",\"device_id\":\"%s\",\"verifier_id\":\"%s\","
                 "\"challenge_id\":\"%s\",\"nonce\":\"%s\",\"purpose\":\"%s\","
                 "\"timestamp\":%ld,\"claims\":%s,\"signature_algorithm\":\"%s\","
                 "\"signature\":\"%s\"}\n",
                 esc_ev_id, esc_dev_id, vantaq_evidence_get_verifier_id(res.evidence),
                 vantaq_evidence_get_challenge_id(res.evidence),
                 vantaq_evidence_get_nonce(res.evidence), vantaq_evidence_get_purpose(res.evidence),
                 (long)vantaq_evidence_get_issued_at_unix(res.evidence),
                 vantaq_evidence_get_claims(res.evidence),
                 vantaq_evidence_get_signature_alg(res.evidence), res.signature_b64);

    if (n < 0 || (size_t)n >= sizeof(json)) {
        vantaq_create_evidence_res_free(&res);
        return vantaq_http_send_status_response(connection, 500);
    }

    n = snprintf(response, sizeof(response),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: application/json\r\n"
                 "Content-Length: %zu\r\n"
                 "Connection: close\r\n"
                 "\r\n"
                 "%s",
                 (size_t)n, json);

    if (n < 0 || (size_t)n >= sizeof(response)) {
        vantaq_create_evidence_res_free(&res);
        return vantaq_http_send_status_response(connection, 500);
    }

    audit_evidence_creation(ctx, req_ctx, "allowed", "ok");
    result = vantaq_http_write_all(connection, response, (size_t)strlen(response));

    vantaq_create_evidence_res_free(&res);
    return result;
}
