// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/evidence/create_evidence.h"
#include "domain/evidence/evidence_canonical.h"
#include "infrastructure/crypto/evidence_signer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SIGNATURE_ALG "ECDSA-P256-SHA256"

static size_t escaped_json_len(const char *s) {
    size_t n = 0;
    for (; *s; ++s) {
        if (*s == '"' || *s == '\\') {
            n += 2;
        } else {
            n += 1;
        }
    }
    return n;
}

static void append_escaped_json(char *dst, size_t *offset, const char *s) {
    while (*s) {
        if (*s == '"' || *s == '\\') {
            dst[(*offset)++] = '\\';
        }
        dst[(*offset)++] = *s++;
    }
}

static vantaq_app_evidence_err_t build_claims_json(const struct vantaq_create_evidence_req *req,
                                                   char **out_claims_json) {
    if (!req || !out_claims_json) {
        return VANTAQ_APP_EVIDENCE_ERR_INVALID_ARG;
    }
    if (req->claims_count == 0) {
        *out_claims_json = strdup("{}");
        return *out_claims_json ? VANTAQ_APP_EVIDENCE_OK : VANTAQ_APP_EVIDENCE_ERR_MALLOC_FAILED;
    }
    if (!req->claims) {
        return VANTAQ_APP_EVIDENCE_ERR_INVALID_ARG;
    }

    size_t total = strlen("{\"claims\":[") + strlen("]}") + 1;
    for (size_t i = 0; i < req->claims_count; ++i) {
        if (!req->claims[i]) {
            return VANTAQ_APP_EVIDENCE_ERR_INVALID_ARG;
        }
        total += 2 + escaped_json_len(req->claims[i]); // surrounding quotes + escaped content
        if (i + 1 < req->claims_count) {
            total += 1; // comma
        }
    }

    char *json = malloc(total);
    if (!json) {
        return VANTAQ_APP_EVIDENCE_ERR_MALLOC_FAILED;
    }

    size_t off = 0;
    memcpy(json + off, "{\"claims\":[", strlen("{\"claims\":["));
    off += strlen("{\"claims\":[");
    for (size_t i = 0; i < req->claims_count; ++i) {
        json[off++] = '"';
        append_escaped_json(json, &off, req->claims[i]);
        json[off++] = '"';
        if (i + 1 < req->claims_count) {
            json[off++] = ',';
        }
    }
    json[off++] = ']';
    json[off++] = '}';
    json[off]   = '\0';

    *out_claims_json = json;
    return VANTAQ_APP_EVIDENCE_OK;
}

vantaq_app_evidence_err_t
vantaq_app_create_evidence(struct vantaq_challenge_store *store,
                           struct vantaq_latest_evidence_store *latest_store,
                           const vantaq_device_key_t *device_key, const char *verifier_id,
                           const struct vantaq_create_evidence_req *req, int64_t current_time_unix,
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

    app_err = build_claims_json(req, &claims_json);
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
