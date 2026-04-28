// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/evidence/create_evidence.h"
#include "domain/evidence/evidence_canonical.h"
#include "infrastructure/crypto/evidence_signer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MOCK_CLAIMS                                                                                \
    "{\"device_identity\":{\"model\":\"edge-gateway-v1\",\"serial_number\":\"SN-001\"},\"agent_"   \
    "integrity\":\"mock-agent-integrity-v1\"}"
#define MOCK_DEVICE_ID "edge-gw-001"
#define SIGNATURE_ALG "ECDSA-P256-SHA256"

vantaq_app_evidence_err_t vantaq_app_create_evidence(struct vantaq_challenge_store *store,
                                                     const vantaq_device_key_t *device_key,
                                                     const char *verifier_id,
                                                     const struct vantaq_create_evidence_req *req,
                                                     int64_t current_time_unix,
                                                     struct vantaq_create_evidence_res *out_res) {
    if (!store || !device_key || !verifier_id || !req || !out_res) {
        return VANTAQ_APP_EVIDENCE_ERR_INVALID_ARG;
    }

    vantaq_app_evidence_err_t app_err  = VANTAQ_APP_EVIDENCE_ERR_INTERNAL;
    struct vantaq_challenge *challenge = NULL;
    struct vantaq_evidence *evidence   = NULL;
    char *canonical_buf                = NULL;
    size_t canonical_len               = 0;
    char *sig_b64                      = NULL;

    // 1. Find and consume challenge (Atomic lookup and mark-used)
    // Note: current_time_unix is in seconds, store expects ms.
    enum vantaq_challenge_store_status store_status = vantaq_challenge_store_find_and_consume(
        store, req->challenge_id, current_time_unix * 1000, true, &challenge);

    if (store_status == VANTAQ_CHALLENGE_STORE_ERROR_NOT_FOUND) {
        return VANTAQ_APP_EVIDENCE_ERR_CHALLENGE_NOT_FOUND;
    } else if (store_status == VANTAQ_CHALLENGE_STORE_ERROR_EXPIRED) {
        return VANTAQ_APP_EVIDENCE_ERR_CHALLENGE_EXPIRED;
    } else if (store_status != VANTAQ_CHALLENGE_STORE_OK) {
        return VANTAQ_APP_EVIDENCE_ERR_INTERNAL;
    }

    // Double check used status (although find_and_consume with consume=true should handle it)
    // If it was already used, store_status would likely not be OK depending on implementation.
    // In this codebase, vantaq_challenge_is_used is checked.

    // 2. Validate challenge properties
    if (strcmp(vantaq_challenge_get_nonce_hex(challenge), req->nonce) != 0) {
        app_err = VANTAQ_APP_EVIDENCE_ERR_NONCE_MISMATCH;
        goto cleanup;
    }

    if (strcmp(vantaq_challenge_get_verifier_id(challenge), verifier_id) != 0) {
        app_err = VANTAQ_APP_EVIDENCE_ERR_VERIFIER_MISMATCH;
        goto cleanup;
    }

    // 3. Build Evidence Domain Object
    char ev_id[32];
    snprintf(ev_id, sizeof(ev_id), "ev-%06ld", (long)(current_time_unix % 1000000));

    vantaq_evidence_err_t ev_err = vantaq_evidence_create(
        ev_id, MOCK_DEVICE_ID, verifier_id, req->challenge_id, req->nonce, "remote_attestation",
        current_time_unix, MOCK_CLAIMS, SIGNATURE_ALG, "pending-signature", &evidence);

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

    // 6. Success
    out_res->evidence      = evidence;
    out_res->signature_b64 = sig_b64;
    evidence               = NULL; // Transferred ownership
    sig_b64                = NULL; // Transferred ownership
    app_err                = VANTAQ_APP_EVIDENCE_OK;

cleanup:
    if (evidence)
        vantaq_evidence_destroy(evidence);
    if (canonical_buf)
        vantaq_evidence_canonical_free(canonical_buf);
    if (sig_b64)
        vantaq_signature_b64_free(sig_b64);
    // challenge is borrowed from store, do not destroy here (check store ownership rules)
    // Looking at challenge_store.h, it says "(borrowed)".
    return app_err;
}

void vantaq_create_evidence_res_free(struct vantaq_create_evidence_res *res) {
    if (res) {
        if (res->evidence)
            vantaq_evidence_destroy(res->evidence);
        if (res->signature_b64)
            vantaq_signature_b64_free(res->signature_b64);
        res->evidence      = NULL;
        res->signature_b64 = NULL;
    }
}
