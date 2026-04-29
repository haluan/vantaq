// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/evidence/create_evidence.h"
#include "domain/evidence/evidence_canonical.h"
#include "infrastructure/crypto/evidence_signer.h"
#include "infrastructure/linux_measurement/agent_integrity.h"
#include "infrastructure/linux_measurement/config_hash.h"
#include "infrastructure/linux_measurement/firmware_hash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SIGNATURE_ALG "ECDSA-P256-SHA256"
#define CLAIM_DEVICE_IDENTITY "device_identity"
#define CLAIM_FIRMWARE_HASH "firmware_hash"
#define CLAIM_CONFIG_HASH "config_hash"
#define CLAIM_AGENT_INTEGRITY "agent_integrity"
#define CLAIM_BOOT_STATE "boot_state"

static bool is_known_claim(const char *claim) {
    return strcmp(claim, CLAIM_DEVICE_IDENTITY) == 0 || strcmp(claim, CLAIM_FIRMWARE_HASH) == 0 ||
           strcmp(claim, CLAIM_CONFIG_HASH) == 0 || strcmp(claim, CLAIM_AGENT_INTEGRITY) == 0 ||
           strcmp(claim, CLAIM_BOOT_STATE) == 0;
}

static bool is_claim_allowed(const struct vantaq_runtime_config *runtime_config,
                             const char *claim) {
    size_t count;
    size_t i;

    count = vantaq_runtime_capability_count(runtime_config, VANTAQ_CAPABILITY_SUPPORTED_CLAIMS);
    for (i = 0; i < count; i++) {
        const char *allowed =
            vantaq_runtime_capability_item(runtime_config, VANTAQ_CAPABILITY_SUPPORTED_CLAIMS, i);
        if (allowed != NULL && strcmp(allowed, claim) == 0) {
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
    if (req->claims_count > 0 && req->claims == NULL) {
        return VANTAQ_APP_EVIDENCE_ERR_INVALID_CLAIMS;
    }

    for (i = 0; i < req->claims_count; i++) {
        const char *claim = req->claims[i];
        if (claim == NULL || claim[0] == '\0') {
            return VANTAQ_APP_EVIDENCE_ERR_INVALID_CLAIMS;
        }

        for (j = i + 1; j < req->claims_count; j++) {
            if (req->claims[j] == NULL || req->claims[j][0] == '\0') {
                return VANTAQ_APP_EVIDENCE_ERR_INVALID_CLAIMS;
            }
            if (strcmp(claim, req->claims[j]) == 0) {
                return VANTAQ_APP_EVIDENCE_ERR_INVALID_CLAIMS;
            }
        }

        if (!is_known_claim(claim)) {
            return VANTAQ_APP_EVIDENCE_ERR_UNSUPPORTED_CLAIM;
        }
        if (!is_claim_allowed(runtime_config, claim)) {
            return VANTAQ_APP_EVIDENCE_ERR_CLAIM_NOT_ALLOWED;
        }

        if (strcmp(claim, CLAIM_BOOT_STATE) == 0) {
            return VANTAQ_APP_EVIDENCE_ERR_UNSUPPORTED_CLAIM;
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
    const char *firmware_value = NULL;
    const char *config_value   = NULL;
    const char *agent_integrity_value;
    const char *model;
    const char *serial_number;
    bool include_device_identity = false;
    bool include_firmware_hash   = false;
    bool include_config_hash     = false;
    bool include_agent_integrity = false;
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
        if (strcmp(req->claims[i], CLAIM_DEVICE_IDENTITY) == 0) {
            include_device_identity = true;
        } else if (strcmp(req->claims[i], CLAIM_FIRMWARE_HASH) == 0) {
            include_firmware_hash = true;
        } else if (strcmp(req->claims[i], CLAIM_CONFIG_HASH) == 0) {
            include_config_hash = true;
        } else if (strcmp(req->claims[i], CLAIM_AGENT_INTEGRITY) == 0) {
            include_agent_integrity = true;
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
            app_err = VANTAQ_APP_EVIDENCE_ERR_MALLOC_FAILED;
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
            app_err = VANTAQ_APP_EVIDENCE_ERR_MALLOC_FAILED;
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
            app_err = VANTAQ_APP_EVIDENCE_ERR_MALLOC_FAILED;
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
            app_err = VANTAQ_APP_EVIDENCE_ERR_MALLOC_FAILED;
            goto cleanup;
        }
        used += (size_t)n;
        first = false;

        vantaq_measurement_result_destroy(measurement_result);
        measurement_result = NULL;
    }

    n = snprintf(claims_buf + used, sizeof(claims_buf) - used, "}");
    if (n < 0 || (size_t)n >= sizeof(claims_buf) - used) {
        app_err = VANTAQ_APP_EVIDENCE_ERR_MALLOC_FAILED;
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
    return app_err;
}

vantaq_app_evidence_err_t vantaq_app_create_evidence(
    struct vantaq_challenge_store *store, struct vantaq_latest_evidence_store *latest_store,
    const struct vantaq_runtime_config *runtime_config, const vantaq_device_key_t *device_key,
    const char *verifier_id, const struct vantaq_create_evidence_req *req,
    int64_t current_time_unix, struct vantaq_create_evidence_res *out_res) {
    if (!store || !runtime_config || !device_key || !verifier_id || !req || !out_res) {
        return VANTAQ_APP_EVIDENCE_ERR_INVALID_ARG;
    }

    vantaq_app_evidence_err_t app_err  = VANTAQ_APP_EVIDENCE_ERR_INTERNAL;
    struct vantaq_challenge *challenge = NULL;
    struct vantaq_evidence *evidence   = NULL;
    char *canonical_buf                = NULL;
    size_t canonical_len               = 0;
    char *sig_b64                      = NULL;
    char *claims_json                  = NULL;

    // 1. Find challenge without consuming it yet (prevent TOCTOU later)
    // Note: current_time_unix is in seconds, store expects ms.
    enum vantaq_challenge_store_status store_status = vantaq_challenge_store_find_and_consume(
        store, req->challenge_id, current_time_unix * 1000, false, &challenge);

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

    // 2. Validate challenge properties
    if (strcmp(vantaq_challenge_get_nonce_hex(challenge), req->nonce) != 0) {
        app_err = VANTAQ_APP_EVIDENCE_ERR_NONCE_MISMATCH;
        goto cleanup;
    }

    if (strcmp(vantaq_challenge_get_verifier_id(challenge), verifier_id) != 0) {
        app_err = VANTAQ_APP_EVIDENCE_ERR_VERIFIER_MISMATCH;
        goto cleanup;
    }

    app_err = validate_claims_selection(runtime_config, req);
    if (app_err != VANTAQ_APP_EVIDENCE_OK) {
        goto cleanup;
    }

    app_err = build_claims_json(runtime_config, req, &claims_json);
    if (app_err != VANTAQ_APP_EVIDENCE_OK) {
        goto cleanup;
    }
    if (!req->device_id) {
        app_err = VANTAQ_APP_EVIDENCE_ERR_INVALID_ARG;
        goto cleanup;
    }

    // 3. Build Evidence Domain Object
    char ev_id[VANTAQ_EVIDENCE_ID_MAX];
    snprintf(ev_id, sizeof(ev_id), "%s", req->challenge_id);

    vantaq_evidence_err_t ev_err = vantaq_evidence_create(
        ev_id, req->device_id, verifier_id, req->challenge_id, req->nonce, "remote_attestation",
        current_time_unix, claims_json, SIGNATURE_ALG, "sig-placeholder", &evidence);

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
    vantaq_signer_err_t sign_err =
        vantaq_evidence_sign(device_key, SIGNATURE_ALG, canonical_buf, canonical_len, &sig_b64);
    if (sign_err != VANTAQ_SIGNER_OK) {
        app_err = VANTAQ_APP_EVIDENCE_ERR_SIGNING_FAILED;
        goto cleanup;
    }

    // Re-create evidence with the finalized signature so domain object and response stay
    // consistent.
    vantaq_evidence_destroy(evidence);
    evidence = NULL;
    ev_err   = vantaq_evidence_create(ev_id, req->device_id, verifier_id, req->challenge_id,
                                      req->nonce, "remote_attestation", current_time_unix,
                                      claims_json, SIGNATURE_ALG, sig_b64, &evidence);
    if (ev_err != VANTAQ_EVIDENCE_OK) {
        app_err = (ev_err == VANTAQ_EVIDENCE_ERR_MALLOC_FAILED)
                      ? VANTAQ_APP_EVIDENCE_ERR_MALLOC_FAILED
                      : VANTAQ_APP_EVIDENCE_ERR_INTERNAL;
        goto cleanup;
    }

    // 6. After successful signing, atomically mark the challenge as used.
    // If another thread already marked it used while we were signing, we fail here.
    if (!vantaq_challenge_mark_used(challenge)) {
        app_err = VANTAQ_APP_EVIDENCE_ERR_CHALLENGE_USED;
        goto cleanup;
    }

    // 7. Store latest evidence in memory if store provided
    if (latest_store) {
        if (vantaq_latest_evidence_store_put(latest_store, verifier_id, evidence, sig_b64) !=
            VANTAQ_LATEST_EVIDENCE_OK) {
            app_err = VANTAQ_APP_EVIDENCE_ERR_INTERNAL;
            goto cleanup;
        }
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
    // challenge is borrowed from store, do not destroy here (check store ownership rules)
    // Looking at challenge_store.h, it says "(borrowed)".
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
