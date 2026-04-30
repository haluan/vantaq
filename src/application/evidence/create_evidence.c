// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/evidence/create_evidence.h"
#include "domain/attestation_challenge/challenge.h"
#include "domain/evidence/evidence_canonical.h"
#include "domain/measurement/measurement.h"
#include "domain/measurement/supported_claims.h"
#include "infrastructure/crypto/evidence_signer.h"
#include "infrastructure/linux_measurement/agent_integrity.h"
#include "infrastructure/linux_measurement/boot_state.h"
#include "infrastructure/linux_measurement/config_hash.h"
#include "infrastructure/linux_measurement/firmware_hash.h"
#include "infrastructure/memory/zero_struct.h"

#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SIGNATURE_ALG "ECDSA-P256-SHA256"

/**
 * Compare bounded C strings without strcmp-style early exit on first differing byte (timing
 * oracle). Both strings must be NUL-terminated with strlen <= max_len; otherwise comparison fails.
 */
static bool constant_time_bounded_cstring_equal(const char *lhs, const char *rhs, size_t max_len) {
    size_t lhs_len    = 0U;
    size_t rhs_len    = 0U;
    unsigned char bad = 0U;
    size_t i          = 0U;

    if (lhs == NULL || rhs == NULL) {
        return false;
    }

    lhs_len = strnlen(lhs, max_len + 1U);
    rhs_len = strnlen(rhs, max_len + 1U);

    bad |= (unsigned char)(lhs_len != rhs_len);
    bad |= (unsigned char)(lhs_len > max_len);
    bad |= (unsigned char)(rhs_len > max_len);

    for (i = 0U; i < max_len; i++) {
        unsigned char lc = (unsigned char)((i < lhs_len) ? lhs[i] : 0);
        unsigned char rc = (unsigned char)((i < rhs_len) ? rhs[i] : 0);
        bad |= (unsigned char)(lc ^ rc);
    }

    return bad == 0U;
}

static bool parse_boot_state_claim_value(const char *value, char *secure_boot,
                                         size_t secure_boot_size, char *boot_mode,
                                         size_t boot_mode_size) {
    bool ok           = false;
    bool has_secure   = false;
    bool has_mode     = false;
    bool has_rollback = false;
    char *copy        = NULL;
    char *token_ctx   = NULL;
    char *token       = NULL;
    char *equal_sign  = NULL;
    const char *key;
    const char *val;

    if (value == NULL || secure_boot == NULL || boot_mode == NULL || secure_boot_size == 0 ||
        boot_mode_size == 0) {
        return false;
    }

    secure_boot[0] = '\0';
    boot_mode[0]   = '\0';

    copy = strdup(value);
    if (copy == NULL) {
        goto cleanup;
    }

    token = strtok_r(copy, ";", &token_ctx);
    while (token != NULL) {
        equal_sign = strchr(token, '=');
        if (equal_sign == NULL) {
            if (token[0] != '\0') {
                goto cleanup;
            }
            token = strtok_r(NULL, ";", &token_ctx);
            continue;
        }
        {
            *equal_sign = '\0';
            key         = token;
            val         = equal_sign + 1;

            if (strcmp(key, VANTAQ_BOOT_STATE_KEY_SECURE_BOOT) == 0) {
                if (has_secure || val[0] == '\0' || strlen(val) >= secure_boot_size) {
                    goto cleanup;
                }
                memcpy(secure_boot, val, strlen(val) + 1U);
                has_secure = true;
            } else if (strcmp(key, VANTAQ_BOOT_STATE_KEY_BOOT_MODE) == 0) {
                if (has_mode || val[0] == '\0' || strlen(val) >= boot_mode_size) {
                    goto cleanup;
                }
                memcpy(boot_mode, val, strlen(val) + 1U);
                has_mode = true;
            } else if (strcmp(key, VANTAQ_BOOT_STATE_KEY_ROLLBACK_DETECTED) == 0) {
                if (has_rollback || val[0] == '\0') {
                    goto cleanup;
                }
                has_rollback = true;
            } else {
                /* Reject unknown or malformed keys (addresses E5). */
                goto cleanup;
            }
        }

        token = strtok_r(NULL, ";", &token_ctx);
    }

    ok = has_secure && has_mode;

cleanup:
    free(copy);
    return ok;
}

static bool is_claim_allowed(const struct vantaq_runtime_config *runtime_config,
                             const char *claim) {
    size_t count;
    size_t i;

    count = vantaq_runtime_capability_count(runtime_config, VANTAQ_CAPABILITY_SUPPORTED_CLAIMS);
    for (i = 0; i < count; i++) {
        const char *allowed =
            vantaq_runtime_capability_item(runtime_config, VANTAQ_CAPABILITY_SUPPORTED_CLAIMS, i);
        size_t allowed_len = 0U;
        size_t claim_len   = 0U;

        if (allowed == NULL) {
            continue;
        }

        allowed_len = strnlen(allowed, VANTAQ_SUPPORTED_CLAIM_NAME_MAX + 1U);
        claim_len   = strnlen(claim, VANTAQ_SUPPORTED_CLAIM_NAME_MAX + 1U);
        if (allowed_len <= VANTAQ_SUPPORTED_CLAIM_NAME_MAX &&
            claim_len <= VANTAQ_SUPPORTED_CLAIM_NAME_MAX && allowed_len == claim_len &&
            CRYPTO_memcmp(allowed, claim, claim_len) == 0) {
            return true;
        }
    }
    return false;
}

static vantaq_app_evidence_err_t
validate_claims_selection(const struct vantaq_runtime_config *runtime_config,
                          const struct vantaq_create_evidence_req *req) {
    size_t i;
    size_t j;

    if (req->claims_count > VANTAQ_EVIDENCE_MAX_CLAIMS_PER_REQUEST) {
        return VANTAQ_APP_EVIDENCE_ERR_INVALID_CLAIMS;
    }
    if (req->claims_count == 0U) {
        return VANTAQ_APP_EVIDENCE_ERR_INVALID_CLAIMS;
    }
    if (req->claims == NULL) {
        return VANTAQ_APP_EVIDENCE_ERR_INVALID_CLAIMS;
    }

    /* O(n²) comparison is capped by VANTAQ_EVIDENCE_MAX_CLAIMS_PER_REQUEST (8), making it
     * computationally safe (addresses E3). */
    for (i = 0; i < req->claims_count; i++) {
        const char *claim = req->claims[i];
        if (claim == NULL || claim[0] == '\0') {
            return VANTAQ_APP_EVIDENCE_ERR_INVALID_CLAIMS;
        }

        for (j = i + 1; j < req->claims_count; j++) {
            if (req->claims[j] == NULL || req->claims[j][0] == '\0') {
                return VANTAQ_APP_EVIDENCE_ERR_INVALID_CLAIMS;
            }
            size_t len_i = strnlen(claim, VANTAQ_SUPPORTED_CLAIM_NAME_MAX + 1U);
            size_t len_j = strnlen(req->claims[j], VANTAQ_SUPPORTED_CLAIM_NAME_MAX + 1U);

            if (len_i <= VANTAQ_SUPPORTED_CLAIM_NAME_MAX &&
                len_j <= VANTAQ_SUPPORTED_CLAIM_NAME_MAX && len_i == len_j &&
                CRYPTO_memcmp(claim, req->claims[j], len_i) == 0) {
                return VANTAQ_APP_EVIDENCE_ERR_INVALID_CLAIMS;
            }
        }

        if (!vantaq_supported_claim_is_known(claim)) {
            return VANTAQ_APP_EVIDENCE_ERR_UNSUPPORTED_CLAIM;
        }
        if (!is_claim_allowed(runtime_config, claim)) {
            return VANTAQ_APP_EVIDENCE_ERR_CLAIM_NOT_ALLOWED;
        }
    }

    return VANTAQ_APP_EVIDENCE_OK;
}

static vantaq_app_evidence_err_t
build_claims_json(const struct vantaq_runtime_config *runtime_config,
                  const struct vantaq_create_evidence_req *req, char **out_claims_json) {
    vantaq_app_evidence_err_t app_err                    = VANTAQ_APP_EVIDENCE_ERR_INTERNAL;
    struct vantaq_measurement_result *measurement_result = NULL;
    enum vantaq_firmware_hash_status firmware_measurement_status;
    enum vantaq_config_hash_status config_measurement_status;
    enum vantaq_agent_integrity_status agent_integrity_measurement_status;
    enum vantaq_boot_state_status boot_state_measurement_status;
    const char *firmware_value = NULL;
    const char *config_value   = NULL;
    const char *agent_integrity_value;
    const char *boot_state_value;
    const char *model;
    const char *serial_number;
    char boot_state_secure_boot[VANTAQ_MEASUREMENT_VALUE_MAX];
    char boot_state_mode[VANTAQ_MEASUREMENT_VALUE_MAX];
    bool include_device_identity = false;
    bool include_firmware_hash   = false;
    bool include_config_hash     = false;
    bool include_agent_integrity = false;
    bool include_boot_state      = false;
    bool first                   = true;
    size_t i;
    int n;
    size_t used = 0;
    char claims_buf[VANTAQ_CLAIMS_MAX];

    if (runtime_config == NULL || req == NULL || out_claims_json == NULL) {
        return VANTAQ_APP_EVIDENCE_ERR_INVALID_ARG;
    }
    *out_claims_json = NULL;

    for (i = 0; i < req->claims_count; i++) {
        if (strcmp(req->claims[i], VANTAQ_CLAIM_DEVICE_IDENTITY) == 0) {
            include_device_identity = true;
        } else if (strcmp(req->claims[i], VANTAQ_CLAIM_FIRMWARE_HASH) == 0) {
            include_firmware_hash = true;
        } else if (strcmp(req->claims[i], VANTAQ_CLAIM_CONFIG_HASH) == 0) {
            include_config_hash = true;
        } else if (strcmp(req->claims[i], VANTAQ_CLAIM_AGENT_INTEGRITY) == 0) {
            include_agent_integrity = true;
        } else if (strcmp(req->claims[i], VANTAQ_CLAIM_BOOT_STATE) == 0) {
            include_boot_state = true;
        }
    }

    claims_buf[0] = '{';
    claims_buf[1] = '\0';
    used          = 1;

    if (include_device_identity) {
        model         = vantaq_runtime_device_model(runtime_config);
        serial_number = vantaq_runtime_device_serial_number(runtime_config);
        if (model == NULL || model[0] == '\0' || serial_number == NULL ||
            serial_number[0] == '\0') {
            app_err = VANTAQ_APP_EVIDENCE_ERR_INTERNAL;
            goto cleanup;
        }

        n = snprintf(claims_buf + used, sizeof(claims_buf) - used,
                     "%s\"device_identity\":{\"model\":\"%s\",\"serial_number\":\"%s\"}",
                     first ? "" : ",", model, serial_number);
        if (n < 0 || (size_t)n >= sizeof(claims_buf) - used) {
            app_err = VANTAQ_APP_EVIDENCE_ERR_CLAIMS_TOO_LARGE;
            goto cleanup;
        }
        used += (size_t)n;
        first = false;
    }

    if (include_firmware_hash) {
        firmware_measurement_status =
            vantaq_firmware_hash_measure(runtime_config, &measurement_result);
        if (firmware_measurement_status == VANTAQ_FIRMWARE_HASH_ERR_SOURCE_NOT_FOUND) {
            app_err = VANTAQ_APP_EVIDENCE_ERR_MEASUREMENT_SOURCE_NOT_FOUND;
            goto cleanup;
        }
        if (firmware_measurement_status == VANTAQ_FIRMWARE_HASH_ERR_HASH_FAILED) {
            app_err = VANTAQ_APP_EVIDENCE_ERR_MEASUREMENT_HASH_FAILED;
            goto cleanup;
        }
        if (firmware_measurement_status != VANTAQ_FIRMWARE_HASH_OK || measurement_result == NULL) {
            app_err = VANTAQ_APP_EVIDENCE_ERR_MEASUREMENT_READ_FAILED;
            goto cleanup;
        }

        firmware_value = vantaq_measurement_result_get_value(measurement_result);
        if (firmware_value == NULL || firmware_value[0] == '\0') {
            app_err = VANTAQ_APP_EVIDENCE_ERR_MEASUREMENT_READ_FAILED;
            goto cleanup;
        }

        n = snprintf(claims_buf + used, sizeof(claims_buf) - used, "%s\"firmware_hash\":\"%s\"",
                     first ? "" : ",", firmware_value);
        if (n < 0 || (size_t)n >= sizeof(claims_buf) - used) {
            app_err = VANTAQ_APP_EVIDENCE_ERR_CLAIMS_TOO_LARGE;
            goto cleanup;
        }
        used += (size_t)n;
        first = false;

        vantaq_measurement_result_destroy(measurement_result);
        measurement_result = NULL;
    }

    if (include_config_hash) {
        config_measurement_status = vantaq_config_hash_measure(runtime_config, &measurement_result);
        if (config_measurement_status == VANTAQ_CONFIG_HASH_ERR_SOURCE_NOT_FOUND) {
            app_err = VANTAQ_APP_EVIDENCE_ERR_MEASUREMENT_SOURCE_NOT_FOUND;
            goto cleanup;
        }
        if (config_measurement_status == VANTAQ_CONFIG_HASH_ERR_HASH_FAILED) {
            app_err = VANTAQ_APP_EVIDENCE_ERR_MEASUREMENT_HASH_FAILED;
            goto cleanup;
        }
        if (config_measurement_status != VANTAQ_CONFIG_HASH_OK || measurement_result == NULL) {
            app_err = VANTAQ_APP_EVIDENCE_ERR_MEASUREMENT_READ_FAILED;
            goto cleanup;
        }

        config_value = vantaq_measurement_result_get_value(measurement_result);
        if (config_value == NULL || config_value[0] == '\0') {
            app_err = VANTAQ_APP_EVIDENCE_ERR_MEASUREMENT_READ_FAILED;
            goto cleanup;
        }

        n = snprintf(claims_buf + used, sizeof(claims_buf) - used, "%s\"config_hash\":\"%s\"",
                     first ? "" : ",", config_value);
        if (n < 0 || (size_t)n >= sizeof(claims_buf) - used) {
            app_err = VANTAQ_APP_EVIDENCE_ERR_CLAIMS_TOO_LARGE;
            goto cleanup;
        }
        used += (size_t)n;
        first = false;

        vantaq_measurement_result_destroy(measurement_result);
        measurement_result = NULL;
    }

    if (include_agent_integrity) {
        agent_integrity_measurement_status =
            vantaq_agent_integrity_measure(runtime_config, &measurement_result);
        if (agent_integrity_measurement_status == VANTAQ_AGENT_INTEGRITY_ERR_SOURCE_NOT_FOUND) {
            app_err = VANTAQ_APP_EVIDENCE_ERR_MEASUREMENT_SOURCE_NOT_FOUND;
            goto cleanup;
        }
        if (agent_integrity_measurement_status == VANTAQ_AGENT_INTEGRITY_ERR_HASH_FAILED) {
            app_err = VANTAQ_APP_EVIDENCE_ERR_MEASUREMENT_HASH_FAILED;
            goto cleanup;
        }
        if (agent_integrity_measurement_status != VANTAQ_AGENT_INTEGRITY_OK ||
            measurement_result == NULL) {
            app_err = VANTAQ_APP_EVIDENCE_ERR_MEASUREMENT_READ_FAILED;
            goto cleanup;
        }

        agent_integrity_value = vantaq_measurement_result_get_value(measurement_result);
        if (agent_integrity_value == NULL || agent_integrity_value[0] == '\0') {
            app_err = VANTAQ_APP_EVIDENCE_ERR_MEASUREMENT_READ_FAILED;
            goto cleanup;
        }

        n = snprintf(claims_buf + used, sizeof(claims_buf) - used, "%s\"agent_integrity\":\"%s\"",
                     first ? "" : ",", agent_integrity_value);
        if (n < 0 || (size_t)n >= sizeof(claims_buf) - used) {
            app_err = VANTAQ_APP_EVIDENCE_ERR_CLAIMS_TOO_LARGE;
            goto cleanup;
        }
        used += (size_t)n;
        first = false;

        vantaq_measurement_result_destroy(measurement_result);
        measurement_result = NULL;
    }

    if (include_boot_state) {
        boot_state_measurement_status =
            vantaq_boot_state_measure(runtime_config, &measurement_result);
        if (boot_state_measurement_status == VANTAQ_BOOT_STATE_ERR_SOURCE_NOT_FOUND) {
            app_err = VANTAQ_APP_EVIDENCE_ERR_MEASUREMENT_SOURCE_NOT_FOUND;
            goto cleanup;
        }
        if (boot_state_measurement_status != VANTAQ_BOOT_STATE_OK || measurement_result == NULL) {
            if (measurement_result != NULL && vantaq_measurement_result_get_error_code(
                                                  measurement_result) == MEASUREMENT_PARSE_FAILED) {
                app_err = VANTAQ_APP_EVIDENCE_ERR_MEASUREMENT_PARSE_FAILED;
            } else {
                app_err = VANTAQ_APP_EVIDENCE_ERR_MEASUREMENT_READ_FAILED;
            }
            goto cleanup;
        }

        boot_state_value = vantaq_measurement_result_get_value(measurement_result);
        if (boot_state_value == NULL || boot_state_value[0] == '\0') {
            app_err = VANTAQ_APP_EVIDENCE_ERR_MEASUREMENT_READ_FAILED;
            goto cleanup;
        }
        if (!parse_boot_state_claim_value(boot_state_value, boot_state_secure_boot,
                                          sizeof(boot_state_secure_boot), boot_state_mode,
                                          sizeof(boot_state_mode))) {
            app_err = VANTAQ_APP_EVIDENCE_ERR_MEASUREMENT_READ_FAILED;
            goto cleanup;
        }

        n = snprintf(claims_buf + used, sizeof(claims_buf) - used,
                     "%s\"boot_state\":{\"secure_boot\":\"%s\",\"boot_mode\":\"%s\"}",
                     first ? "" : ",", boot_state_secure_boot, boot_state_mode);
        if (n < 0 || (size_t)n >= sizeof(claims_buf) - used) {
            app_err = VANTAQ_APP_EVIDENCE_ERR_CLAIMS_TOO_LARGE;
            goto cleanup;
        }
        used += (size_t)n;
        first = false;

        vantaq_measurement_result_destroy(measurement_result);
        measurement_result = NULL;
    }

    n = snprintf(claims_buf + used, sizeof(claims_buf) - used, "}");
    if (n < 0 || (size_t)n >= sizeof(claims_buf) - used) {
        app_err = VANTAQ_APP_EVIDENCE_ERR_CLAIMS_TOO_LARGE;
        goto cleanup;
    }

    *out_claims_json = strdup(claims_buf);
    if (*out_claims_json == NULL) {
        app_err = VANTAQ_APP_EVIDENCE_ERR_MALLOC_FAILED;
        goto cleanup;
    }

    app_err = VANTAQ_APP_EVIDENCE_OK;

cleanup:
    vantaq_measurement_result_destroy(measurement_result);
    vantaq_explicit_bzero(claims_buf, sizeof(claims_buf));
    vantaq_explicit_bzero(boot_state_secure_boot, sizeof(boot_state_secure_boot));
    vantaq_explicit_bzero(boot_state_mode, sizeof(boot_state_mode));
    return app_err;
}

vantaq_app_evidence_err_t vantaq_app_create_evidence(const struct vantaq_app_evidence_context *ctx,
                                                     const char *verifier_id,
                                                     const struct vantaq_create_evidence_req *req,
                                                     struct vantaq_create_evidence_res *out_res) {
    vantaq_app_evidence_err_t app_err  = VANTAQ_APP_EVIDENCE_ERR_INTERNAL;
    struct vantaq_challenge *challenge = NULL;
    struct vantaq_evidence *evidence   = NULL;
    char *canonical_buf                = NULL;
    size_t canonical_len               = 0;
    char *sig_b64                      = NULL;
    char *claims_json                  = NULL;

    if (!ctx || !ctx->store || !ctx->runtime_config || !ctx->device_key || !verifier_id || !req ||
        !out_res) {
        app_err = VANTAQ_APP_EVIDENCE_ERR_INVALID_ARG;
        goto cleanup;
    }

    /* Device ID validation (addresses E4). */
    if (!req->device_id || req->device_id[0] == '\0' ||
        strnlen(req->device_id, VANTAQ_DEVICE_ID_MAX) >= VANTAQ_DEVICE_ID_MAX) {
        app_err = VANTAQ_APP_EVIDENCE_ERR_INVALID_ARG;
        goto cleanup;
    }

    // 1. Find challenge without consuming it yet (prevent TOCTOU later)
    // Note: current_time_unix is in seconds, store expects ms.
    // NOTE: This uses the wall-clock time passed via ctx->current_time_unix.
    // Backwards clock adjustments may affect TTL enforcement (addresses E2).
    enum vantaq_challenge_store_status store_status = vantaq_challenge_store_find_and_consume(
        ctx->store, req->challenge_id, ctx->current_time_unix * 1000, false, &challenge);

    if (store_status == VANTAQ_CHALLENGE_STORE_ERROR_NOT_FOUND) {
        app_err = VANTAQ_APP_EVIDENCE_ERR_CHALLENGE_NOT_FOUND;
        goto cleanup;
    } else if (store_status == VANTAQ_CHALLENGE_STORE_ERROR_EXPIRED) {
        app_err = VANTAQ_APP_EVIDENCE_ERR_CHALLENGE_EXPIRED;
        goto cleanup;
    } else if (store_status != VANTAQ_CHALLENGE_STORE_OK) {
        app_err = VANTAQ_APP_EVIDENCE_ERR_INTERNAL;
        goto cleanup;
    }

    // Double check used status (reject already used challenge)
    if (vantaq_challenge_is_used(challenge)) {
        app_err = VANTAQ_APP_EVIDENCE_ERR_CHALLENGE_USED;
        goto cleanup;
    }

    // 2. Validate challenge properties (fixed-length scan avoids strcmp timing leak).
    if (!constant_time_bounded_cstring_equal(vantaq_challenge_get_nonce_hex(challenge), req->nonce,
                                             VANTAQ_NONCE_HEX_MAX - 1U)) {
        app_err = VANTAQ_APP_EVIDENCE_ERR_NONCE_MISMATCH;
        goto cleanup;
    }

    if (!constant_time_bounded_cstring_equal(vantaq_challenge_get_verifier_id(challenge),
                                             verifier_id, VANTAQ_VERIFIER_ID_MAX - 1U)) {
        app_err = VANTAQ_APP_EVIDENCE_ERR_VERIFIER_MISMATCH;
        goto cleanup;
    }

    app_err = validate_claims_selection(ctx->runtime_config, req);
    if (app_err != VANTAQ_APP_EVIDENCE_OK) {
        goto cleanup;
    }

    app_err = build_claims_json(ctx->runtime_config, req, &claims_json);
    if (app_err != VANTAQ_APP_EVIDENCE_OK) {
        goto cleanup;
    }

    // 3. Build Evidence Domain Object
    char ev_id[VANTAQ_EVIDENCE_ID_MAX];
    snprintf(ev_id, sizeof(ev_id), "%s", req->challenge_id);

    /* Domain API now supports update_signature, so we avoid fragility of placeholder double
     * creation (addresses D3). */
    vantaq_evidence_err_t ev_err = vantaq_evidence_create(
        ev_id, req->device_id, verifier_id, req->challenge_id, req->nonce, "remote_attestation",
        ctx->current_time_unix, claims_json, SIGNATURE_ALG, "sig-placeholder", &evidence);

    if (ev_err != VANTAQ_EVIDENCE_OK) {
        app_err = (ev_err == VANTAQ_EVIDENCE_ERR_MALLOC_FAILED)
                      ? VANTAQ_APP_EVIDENCE_ERR_MALLOC_FAILED
                      : VANTAQ_APP_EVIDENCE_ERR_INTERNAL;
        goto cleanup;
    }

    // 4. Canonical Serialization
    ev_err = vantaq_evidence_serialize_canonical(evidence, &canonical_buf, &canonical_len);
    if (ev_err != VANTAQ_EVIDENCE_OK) {
        app_err = VANTAQ_APP_EVIDENCE_ERR_INTERNAL;
        goto cleanup;
    }

    // 5. Sign the payload
    vantaq_signer_err_t sign_err = vantaq_evidence_sign(ctx->device_key, SIGNATURE_ALG,
                                                        canonical_buf, canonical_len, &sig_b64);
    if (sign_err != VANTAQ_SIGNER_OK) {
        app_err = VANTAQ_APP_EVIDENCE_ERR_SIGNING_FAILED;
        goto cleanup;
    }

    // 6. Update evidence with the finalized signature.
    ev_err = vantaq_evidence_update_signature(evidence, sig_b64);
    if (ev_err != VANTAQ_EVIDENCE_OK) {
        app_err = (ev_err == VANTAQ_EVIDENCE_ERR_MALLOC_FAILED)
                      ? VANTAQ_APP_EVIDENCE_ERR_MALLOC_FAILED
                      : VANTAQ_APP_EVIDENCE_ERR_INTERNAL;
        goto cleanup;
    }

    // 7. After successful signing, atomically mark the challenge as used.
    // If another thread already marked it used while we were signing, we fail here.
    if (vantaq_challenge_is_expired(challenge, ctx->current_time_unix * 1000)) {
        app_err = VANTAQ_APP_EVIDENCE_ERR_CHALLENGE_EXPIRED;
        goto cleanup;
    }
    if (!vantaq_challenge_mark_used(challenge)) {
        app_err = VANTAQ_APP_EVIDENCE_ERR_CHALLENGE_USED;
        goto cleanup;
    }

    // 8. Success
    out_res->evidence      = evidence;
    out_res->signature_b64 = sig_b64;
    evidence               = NULL; // Transferred ownership
    sig_b64                = NULL; // Transferred ownership
    app_err                = VANTAQ_APP_EVIDENCE_OK;

cleanup:
    if (evidence)
        vantaq_evidence_destroy(evidence);
    if (canonical_buf)
        vantaq_evidence_canonical_destroy(canonical_buf);
    if (sig_b64)
        vantaq_signature_b64_destroy(sig_b64);
    if (claims_json)
        free(claims_json);
    return app_err;
}

void vantaq_create_evidence_res_free(struct vantaq_create_evidence_res *res) {
    if (res) {
        if (res->evidence)
            vantaq_evidence_destroy(res->evidence);
        if (res->signature_b64)
            vantaq_signature_b64_destroy(res->signature_b64);
        res->evidence      = NULL;
        res->signature_b64 = NULL;
    }
}
