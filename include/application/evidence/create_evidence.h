// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_APPLICATION_EVIDENCE_CREATE_EVIDENCE_H
#define VANTAQ_APPLICATION_EVIDENCE_CREATE_EVIDENCE_H

#include "application/evidence/latest_evidence_store.h"
#include "domain/attestation_challenge/challenge_store.h"
#include "domain/evidence/evidence.h"
#include "infrastructure/crypto/device_key_loader.h"
#include <stdint.h>

typedef enum {
    VANTAQ_APP_EVIDENCE_OK = 0,
    VANTAQ_APP_EVIDENCE_ERR_INVALID_ARG = 1,
    VANTAQ_APP_EVIDENCE_ERR_CHALLENGE_NOT_FOUND = 2,
    VANTAQ_APP_EVIDENCE_ERR_CHALLENGE_EXPIRED = 3,
    VANTAQ_APP_EVIDENCE_ERR_CHALLENGE_USED = 4,
    VANTAQ_APP_EVIDENCE_ERR_NONCE_MISMATCH = 5,
    VANTAQ_APP_EVIDENCE_ERR_VERIFIER_MISMATCH = 6,
    VANTAQ_APP_EVIDENCE_ERR_SIGNING_FAILED = 7,
    VANTAQ_APP_EVIDENCE_ERR_MALLOC_FAILED = 8,
    VANTAQ_APP_EVIDENCE_ERR_INTERNAL = 9
} vantaq_app_evidence_err_t;

struct vantaq_create_evidence_req {
    const char *challenge_id;
    const char *nonce;
    const char *device_id;
    const char **claims;
    size_t claims_count;
};

struct vantaq_create_evidence_res {
    struct vantaq_evidence *evidence;
    char *signature_b64;
};

/**
 * @brief Orchestrate evidence creation: validate challenge, build evidence, and sign it.
 */
vantaq_app_evidence_err_t vantaq_app_create_evidence(
    struct vantaq_challenge_store *store,
    struct vantaq_latest_evidence_store *latest_store,
    const vantaq_device_key_t *device_key,
    const char *verifier_id,
    const struct vantaq_create_evidence_req *req,
    int64_t current_time_unix,
    struct vantaq_create_evidence_res *out_res
);

/**
 * @brief Free the response structure.
 */
void vantaq_create_evidence_res_free(struct vantaq_create_evidence_res *res);

#endif
