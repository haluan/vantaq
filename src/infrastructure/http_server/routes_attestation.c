// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/attestation_challenge/create_challenge.h"
#include "application/evidence/create_evidence.h"
#include "http_server_internal.h"
#include "infrastructure/audit_log.h"
#include "infrastructure/memory/zero_struct.h"
#include "json_utils.h"

#include <assert.h>
#include <ctype.h>
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
/* evidence_id, device_id, verifier_id, challenge_id, nonce, purpose, signature_alg, signature,
 * claims payload, timestamp and JSON punctuation */
#define EXPECTED_MAX_EVIDENCE_JSON                                                                 \
    (VANTAQ_EVIDENCE_ID_MAX + VANTAQ_DEVICE_ID_MAX + VANTAQ_VERIFIER_ID_MAX +                      \
     VANTAQ_CHALLENGE_ID_MAX + VANTAQ_NONCE_MAX + VANTAQ_PURPOSE_MAX + VANTAQ_SIGNATURE_ALG_MAX +  \
     VANTAQ_SIGNATURE_MAX + VANTAQ_CLAIMS_MAX + 256)
static_assert(VANTAQ_EVIDENCE_JSON_BUF_SIZE > EXPECTED_MAX_EVIDENCE_JSON,
              "Evidence JSON buffer too small for maximum field sizes");

/* Enforce a practical lower bound to reduce self-inflicted expiry races. */
#define VANTAQ_CHALLENGE_MIN_TTL_SECONDS 5L

static const char *extract_json_body_start(const char *request_body) {
    const char *body_start;

    if (request_body == NULL) {
        return NULL;
    }
    body_start = strstr(request_body, "\r\n\r\n");
    if (body_start != NULL) {
        return body_start + 4;
    }

    while (*request_body != '\0' && isspace((unsigned char)*request_body)) {
        request_body++;
    }
    if (*request_body == '{') {
        return request_body;
    }
    return NULL;
}

static void audit_route_event(const struct vantaq_http_health_context *ctx,
                              const struct vantaq_http_request_context *req_ctx, const char *path,
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
    event.path                   = path;
    event.result                 = result;
    event.reason                 = reason;
    event.verifier_id            = req_ctx->verifier_auth.identity.id;
    event.request_id             = req_ctx->request_id;

    /* S-5: Log failures to stderr if audit log write fails */
    (void)vantaq_audit_log_append(ctx->audit_log, &event);
}

static void audit_challenge_creation(const struct vantaq_http_health_context *ctx,
                                     const struct vantaq_http_request_context *req_ctx,
                                     const char *result, const char *reason) {
    audit_route_event(ctx, req_ctx, "/v1/attestation/challenge", result, reason);
}

static void audit_evidence_creation(const struct vantaq_http_health_context *ctx,
                                    const struct vantaq_http_request_context *req_ctx,
                                    const char *result, const char *reason) {
    audit_route_event(ctx, req_ctx, "/v1/attestation/evidence", result, reason);
}

static int send_json_error_response(struct vantaq_http_connection *connection, int http_status,
                                    const char *code, const char *request_id) {
    char error_json[512];
    char response[1024];
    char esc_code[128];
    char esc_request_id[128];
    int error_json_n;
    int response_n;
    const char *status_text;

    if (connection == NULL || code == NULL || request_id == NULL) {
        return -1;
    }
    if (vantaq_json_escape_str(code, esc_code, sizeof(esc_code)) == 0 ||
        vantaq_json_escape_str(request_id, esc_request_id, sizeof(esc_request_id)) == 0) {
        return vantaq_http_send_status_response(connection, http_status);
    }

    error_json_n =
        snprintf(error_json, sizeof(error_json),
                 "{\"error\":{\"code\":\"%s\",\"request_id\":\"%s\"}}\n", esc_code, esc_request_id);
    if (error_json_n <= 0 || (size_t)error_json_n >= sizeof(error_json)) {
        return vantaq_http_send_status_response(connection, http_status);
    }

    status_text = (http_status == 409) ? "Conflict" : "Error";
    response_n  = snprintf(response, sizeof(response),
                           "HTTP/1.1 %d %s\r\n"
                           "Content-Type: application/json\r\n"
                           "Content-Length: %zu\r\n"
                           "Connection: close\r\n"
                           "\r\n"
                           "%s",
                           http_status, status_text, (size_t)error_json_n, error_json);
    if (response_n <= 0 || (size_t)response_n >= sizeof(response)) {
        return vantaq_http_send_status_response(connection, http_status);
    }

    return vantaq_http_write_all(connection, response, (size_t)response_n);
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

    /* Skip HTTP headers to reach JSON body */
    body_start = extract_json_body_start(request_body);
    if (body_start == NULL) {
        audit_challenge_creation(ctx, req_ctx, "denied", "invalid_body_format");
        return vantaq_http_send_status_response(connection, 400);
    }

    /* Use robust JSON extraction instead of strstr */
    if (!vantaq_json_extract_str(body_start, "purpose", purpose, sizeof(purpose))) {
        audit_challenge_creation(ctx, req_ctx, "denied", "missing_purpose");
        return vantaq_http_send_status_response(connection, 400);
    }

    /* Prevent spoofing of verifier_id from request body */
    char spoofed_id[VANTAQ_VERIFIER_ID_MAX];
    if (vantaq_json_extract_str(body_start, "verifier_id", spoofed_id, sizeof(spoofed_id))) {
        audit_challenge_creation(ctx, req_ctx, "denied", "spoofed_verifier_id");
        return vantaq_http_send_status_response(connection, 400);
    }

    /* Safe TTL parsing with strtol-based helper */
    long requested_ttl;
    if (vantaq_json_extract_long(body_start, "requested_ttl_seconds", &requested_ttl)) {
        if (requested_ttl < VANTAQ_CHALLENGE_MIN_TTL_SECONDS) {
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
        return send_json_error_response(connection, http_status, reason, req_ctx->request_id);
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
        (void)vantaq_challenge_store_remove(ctx->challenge_store,
                                            vantaq_challenge_get_id(challenge));
        return -1;
    }

    n = snprintf(json, sizeof(json),
                 "{\"challenge_id\":\"%s\",\"nonce\":\"%s\",\"verifier_id\":\"%s\","
                 "\"purpose\":\"%s\",\"expires_in_seconds\":%ld}\n",
                 esc_id, esc_nonce, esc_v_id, esc_purpose, ttl);

    /* Handle truncation and resource cleanup */
    if (n < 0 || (size_t)n >= sizeof(json)) {
        (void)vantaq_challenge_store_remove(ctx->challenge_store,
                                            vantaq_challenge_get_id(challenge));
        return -1;
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
        (void)vantaq_challenge_store_remove(ctx->challenge_store,
                                            vantaq_challenge_get_id(challenge));
        return -1;
    }

    /* Only log "allowed" once we know the response is fully constructed and ready to send */
    audit_challenge_creation(ctx, req_ctx, "allowed", "ok");
    if (vantaq_http_write_all(connection, response, (size_t)n) != 0) {
        (void)vantaq_challenge_store_remove(ctx->challenge_store,
                                            vantaq_challenge_get_id(challenge));
        return -1;
    }
    return 0;
}

int send_post_evidence_response(struct vantaq_http_connection *connection,
                                const struct vantaq_http_health_context *ctx,
                                const struct vantaq_http_request_context *req_ctx,
                                const char *request_body) {
    if (!connection || !ctx || !req_ctx || !request_body)
        return -1;

    struct vantaq_create_evidence_req req;
    struct vantaq_create_evidence_res res;
    char (*claims_storage)[VANTAQ_MAX_FIELD_LEN] = NULL;
    const char *claim_ptrs[VANTAQ_EVIDENCE_MAX_CLAIMS_PER_REQUEST];
    size_t claims_count = 0;
    bool claims_present = false;
    vantaq_app_evidence_err_t app_err;
    const char *body_start;
    int result         = -1;
    int http_status    = 500;
    const char *reason = "internal_error";

    VANTAQ_ZERO_STRUCT(req);
    VANTAQ_ZERO_STRUCT(res);

    body_start = extract_json_body_start(request_body);
    if (body_start == NULL) {
        audit_evidence_creation(ctx, req_ctx, "denied", "invalid_body_format");
        return send_json_error_response(connection, 400, "invalid_body_format",
                                        req_ctx->request_id);
    }

    claims_storage = calloc(VANTAQ_EVIDENCE_MAX_CLAIMS_PER_REQUEST, sizeof(*claims_storage));
    if (claims_storage == NULL) {
        return send_json_error_response(connection, 500, "internal_error", req_ctx->request_id);
    }

    {
        char challenge_id[VANTAQ_CHALLENGE_ID_MAX];
        char nonce[VANTAQ_NONCE_HEX_MAX];

        if (!vantaq_json_extract_str(body_start, "challenge_id", challenge_id,
                                     sizeof(challenge_id)) ||
            !vantaq_json_extract_str(body_start, "nonce", nonce, sizeof(nonce))) {
            audit_evidence_creation(ctx, req_ctx, "denied", "missing_required_fields");
            result = send_json_error_response(connection, 400, "missing_required_fields",
                                              req_ctx->request_id);
            goto cleanup;
        }

        req.challenge_id = challenge_id;
        req.nonce        = nonce;
        req.device_id    = ctx->device_id;
    }
    req.claims       = NULL;
    req.claims_count = 0;

    if (!vantaq_json_extract_str_array(
            body_start, "claims", (char *)claims_storage, sizeof(claims_storage[0]),
            VANTAQ_EVIDENCE_MAX_CLAIMS_PER_REQUEST, &claims_count, &claims_present)) {
        audit_evidence_creation(ctx, req_ctx, "denied", "invalid_claims");
        return send_json_error_response(connection, 400, "invalid_claims", req_ctx->request_id);
    }

    if (claims_present) {
        size_t i;
        for (i = 0; i < claims_count; i++) {
            claim_ptrs[i] = claims_storage[i];
        }
        req.claims       = claim_ptrs;
        req.claims_count = claims_count;
    }

    struct vantaq_app_evidence_context app_ctx;
    VANTAQ_ZERO_STRUCT(app_ctx);
    app_ctx.store             = ctx->challenge_store;
    app_ctx.latest_store      = ctx->latest_evidence_store;
    app_ctx.runtime_config    = ctx->runtime_config;
    app_ctx.device_key        = ctx->device_key;
    app_ctx.current_time_unix = (int64_t)time(NULL);

    app_err = vantaq_app_create_evidence(&app_ctx, req_ctx->verifier_auth.identity.id, &req, &res);

    if (app_err != VANTAQ_APP_EVIDENCE_OK) {
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
            reason      = "challenge_already_used";
            http_status = 409;
            break;
        case VANTAQ_APP_EVIDENCE_ERR_NONCE_MISMATCH:
            reason      = "nonce_mismatch";
            http_status = 409;
            break;
        case VANTAQ_APP_EVIDENCE_ERR_VERIFIER_MISMATCH:
            reason      = "verifier_mismatch";
            http_status = 403;
            break;
        case VANTAQ_APP_EVIDENCE_ERR_SIGNING_FAILED:
            reason      = "signing_failed";
            http_status = 500;
            break;
        case VANTAQ_APP_EVIDENCE_ERR_INVALID_CLAIMS:
            reason      = "invalid_claims";
            http_status = 400;
            break;
        case VANTAQ_APP_EVIDENCE_ERR_UNSUPPORTED_CLAIM:
            reason      = "unsupported_claim";
            http_status = 400;
            break;
        case VANTAQ_APP_EVIDENCE_ERR_CLAIM_NOT_ALLOWED:
            reason      = "claim_not_allowed";
            http_status = 403;
            break;
        case VANTAQ_APP_EVIDENCE_ERR_MEASUREMENT_SOURCE_NOT_FOUND:
            reason      = "measurement_source_not_found";
            http_status = 404;
            break;
        case VANTAQ_APP_EVIDENCE_ERR_MEASUREMENT_READ_FAILED:
            reason      = "measurement_read_failed";
            http_status = 500;
            break;
        case VANTAQ_APP_EVIDENCE_ERR_MEASUREMENT_HASH_FAILED:
            reason      = "measurement_hash_failed";
            http_status = 500;
            break;
        case VANTAQ_APP_EVIDENCE_ERR_MEASUREMENT_PARSE_FAILED:
            reason      = "measurement_parse_failed";
            http_status = 400;
            break;
        default:
            break;
        }

        audit_evidence_creation(ctx, req_ctx, "denied", reason);

        result = send_json_error_response(connection, http_status, reason, req_ctx->request_id);
        goto cleanup;
    }

    // Success - Construct JSON
    {
        char esc_ev_id[VANTAQ_EVIDENCE_ID_MAX * 2];
        char esc_dev_id[VANTAQ_DEVICE_ID_MAX * 2];
        char esc_ver_id[VANTAQ_VERIFIER_ID_MAX * 2];
        char esc_ch_id[VANTAQ_CHALLENGE_ID_MAX * 2];
        char esc_nonce[VANTAQ_NONCE_MAX * 2];
        char esc_purpose[VANTAQ_PURPOSE_MAX * 2];
        char esc_sig_alg[VANTAQ_SIGNATURE_ALG_MAX * 2];
        char esc_sig[VANTAQ_SIGNATURE_MAX * 2];

        if (vantaq_json_escape_str(vantaq_evidence_get_evidence_id(res.evidence), esc_ev_id,
                                   sizeof(esc_ev_id)) == 0 ||
            vantaq_json_escape_str(vantaq_evidence_get_device_id(res.evidence), esc_dev_id,
                                   sizeof(esc_dev_id)) == 0 ||
            vantaq_json_escape_str(vantaq_evidence_get_verifier_id(res.evidence), esc_ver_id,
                                   sizeof(esc_ver_id)) == 0 ||
            vantaq_json_escape_str(vantaq_evidence_get_challenge_id(res.evidence), esc_ch_id,
                                   sizeof(esc_ch_id)) == 0 ||
            vantaq_json_escape_str(vantaq_evidence_get_nonce(res.evidence), esc_nonce,
                                   sizeof(esc_nonce)) == 0 ||
            vantaq_json_escape_str(vantaq_evidence_get_purpose(res.evidence), esc_purpose,
                                   sizeof(esc_purpose)) == 0 ||
            vantaq_json_escape_str(vantaq_evidence_get_signature_alg(res.evidence), esc_sig_alg,
                                   sizeof(esc_sig_alg)) == 0 ||
            vantaq_json_escape_str(res.signature_b64, esc_sig, sizeof(esc_sig)) == 0) {
            result =
                send_json_error_response(connection, 500, "internal_error", req_ctx->request_id);
            goto cleanup;
        }

        const char *claims_json = vantaq_evidence_get_claims(res.evidence);
        if (claims_json == NULL) {
            result =
                send_json_error_response(connection, 500, "internal_error", req_ctx->request_id);
            goto cleanup;
        }

        char json[VANTAQ_EVIDENCE_JSON_BUF_SIZE];
        int n = snprintf(json, sizeof(json),
                         "{\"evidence_id\":\"%s\",\"device_id\":\"%s\",\"verifier_id\":\"%s\","
                         "\"challenge_id\":\"%s\",\"nonce\":\"%s\",\"purpose\":\"%s\","
                         "\"timestamp\":%ld,\"claims\":%s,\"signature_algorithm\":\"%s\","
                         "\"signature\":\"%s\"}\n",
                         esc_ev_id, esc_dev_id, esc_ver_id, esc_ch_id, esc_nonce, esc_purpose,
                         (long)vantaq_evidence_get_issued_at_unix(res.evidence), claims_json,
                         esc_sig_alg, esc_sig);

        if (n < 0 || (size_t)n >= sizeof(json)) {
            result =
                send_json_error_response(connection, 500, "internal_error", req_ctx->request_id);
            goto cleanup;
        }

        char response[VANTAQ_EVIDENCE_JSON_BUF_SIZE + 512];
        n = snprintf(response, sizeof(response),
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Type: application/json\r\n"
                     "Content-Length: %zu\r\n"
                     "Connection: close\r\n"
                     "\r\n"
                     "%s",
                     (size_t)n, json);

        if (n < 0 || (size_t)n >= sizeof(response)) {
            result =
                send_json_error_response(connection, 500, "internal_error", req_ctx->request_id);
            goto cleanup;
        }

        audit_evidence_creation(ctx, req_ctx, "allowed", "ok");
        result = vantaq_http_write_all(connection, response, (size_t)n);
    }

cleanup:
    free(claims_storage);
    vantaq_create_evidence_res_free(&res);
    return result;
}

int send_get_latest_evidence_response(struct vantaq_http_connection *connection,
                                      const struct vantaq_http_health_context *ctx,
                                      const struct vantaq_http_request_context *req_ctx) {
    if (!connection || !ctx || !req_ctx)
        return -1;

    if (ctx->latest_evidence_store == NULL) {
        return vantaq_http_send_status_response(connection, 501);
    }

    struct vantaq_evidence *evidence = NULL;
    char *signature_b64              = NULL;
    char json[VANTAQ_EVIDENCE_JSON_BUF_SIZE];
    char response[VANTAQ_EVIDENCE_JSON_BUF_SIZE + 512];
    char esc_ev_id[VANTAQ_EVIDENCE_ID_MAX * 2];
    char esc_dev_id[VANTAQ_DEVICE_ID_MAX * 2];
    char esc_ver_id[VANTAQ_VERIFIER_ID_MAX * 2];
    char esc_ch_id[VANTAQ_CHALLENGE_ID_MAX * 2];
    char esc_nonce[VANTAQ_NONCE_MAX * 2];
    char esc_purpose[VANTAQ_PURPOSE_MAX * 2];
    char esc_sig_alg[VANTAQ_SIGNATURE_ALG_MAX * 2];
    char esc_sig[VANTAQ_SIGNATURE_MAX * 2];
    int result = -1;

    vantaq_latest_evidence_err_t err = vantaq_latest_evidence_store_get(
        ctx->latest_evidence_store, req_ctx->verifier_auth.identity.id, &evidence, &signature_b64);

    if (err != VANTAQ_LATEST_EVIDENCE_OK) {
        if (err == VANTAQ_LATEST_EVIDENCE_ERR_NOT_FOUND) {
            return vantaq_http_send_status_response(connection, 404);
        }
        return vantaq_http_send_status_response(connection, 500);
    }

    // JSON escape strings
    if (vantaq_json_escape_str(vantaq_evidence_get_evidence_id(evidence), esc_ev_id,
                               sizeof(esc_ev_id)) == 0 ||
        vantaq_json_escape_str(vantaq_evidence_get_device_id(evidence), esc_dev_id,
                               sizeof(esc_dev_id)) == 0 ||
        vantaq_json_escape_str(vantaq_evidence_get_verifier_id(evidence), esc_ver_id,
                               sizeof(esc_ver_id)) == 0 ||
        vantaq_json_escape_str(vantaq_evidence_get_challenge_id(evidence), esc_ch_id,
                               sizeof(esc_ch_id)) == 0 ||
        vantaq_json_escape_str(vantaq_evidence_get_nonce(evidence), esc_nonce, sizeof(esc_nonce)) ==
            0 ||
        vantaq_json_escape_str(vantaq_evidence_get_purpose(evidence), esc_purpose,
                               sizeof(esc_purpose)) == 0 ||
        vantaq_json_escape_str(vantaq_evidence_get_signature_alg(evidence), esc_sig_alg,
                               sizeof(esc_sig_alg)) == 0 ||
        vantaq_json_escape_str(signature_b64, esc_sig, sizeof(esc_sig)) == 0) {
        result = vantaq_http_send_status_response(connection, 500);
        goto cleanup;
    }

    const char *claims_json = vantaq_evidence_get_claims(evidence);
    if (claims_json == NULL) {
        result = vantaq_http_send_status_response(connection, 500);
        goto cleanup;
    }

    int n = snprintf(json, sizeof(json),
                     "{\"evidence_id\":\"%s\",\"device_id\":\"%s\",\"verifier_id\":\"%s\","
                     "\"challenge_id\":\"%s\",\"nonce\":\"%s\",\"purpose\":\"%s\","
                     "\"timestamp\":%ld,\"claims\":%s,\"signature_algorithm\":\"%s\","
                     "\"signature\":\"%s\"}\n",
                     esc_ev_id, esc_dev_id, esc_ver_id, esc_ch_id, esc_nonce, esc_purpose,
                     (long)vantaq_evidence_get_issued_at_unix(evidence), claims_json, esc_sig_alg,
                     esc_sig);

    if (n < 0 || (size_t)n >= sizeof(json)) {
        result = vantaq_http_send_status_response(connection, 500);
        goto cleanup;
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
        result = vantaq_http_send_status_response(connection, 500);
        goto cleanup;
    }

    result = vantaq_http_write_all(connection, response, (size_t)n);

cleanup:
    if (evidence != NULL) {
        vantaq_evidence_destroy(evidence);
    }
    free(signature_b64);
    return result;
}
