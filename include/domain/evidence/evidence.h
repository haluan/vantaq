// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_DOMAIN_EVIDENCE_EVIDENCE_H
#define VANTAQ_DOMAIN_EVIDENCE_EVIDENCE_H

#include <stddef.h>
#include <stdint.h>

#define VANTAQ_EVIDENCE_ID_MAX 64
#define VANTAQ_DEVICE_ID_MAX 128
#define VANTAQ_VERIFIER_ID_MAX 128
#define VANTAQ_CHALLENGE_ID_MAX 64
#define VANTAQ_NONCE_MAX 65
#define VANTAQ_PURPOSE_MAX 64
#define VANTAQ_CLAIMS_MAX 2048
#define VANTAQ_SIGNATURE_ALG_MAX 64
#define VANTAQ_SIGNATURE_MAX 512

typedef enum {
    VANTAQ_EVIDENCE_OK = 0,
    VANTAQ_EVIDENCE_ERR_INVALID_ARG = 1,
    VANTAQ_EVIDENCE_ERR_MALLOC_FAILED = 2,
    VANTAQ_EVIDENCE_ERR_MISSING_FIELD = 3
} vantaq_evidence_err_t;

struct vantaq_evidence;

/**
 * @brief Create a signed evidence domain object.
 * 
 * @param evidence_id Unique ID for the evidence.
 * @param device_id Device identifier.
 * @param verifier_id Verifier identifier.
 * @param challenge_id Challenge identifier this evidence responds to.
 * @param nonce Nonce from the challenge.
 * @param purpose Purpose of attestation (e.g., "remote_attestation").
 * @param issued_at_unix Issuance timestamp.
 * @param claims JSON serialized claims.
 * @param signature_alg Signature algorithm used.
 * @param signature Base64 encoded signature.
 * @param out_evidence Pointer to hold the created evidence object.
 * @return vantaq_evidence_err_t Status code.
 */
vantaq_evidence_err_t vantaq_evidence_create(
    const char *evidence_id,
    const char *device_id,
    const char *verifier_id,
    const char *challenge_id,
    const char *nonce,
    const char *purpose,
    int64_t issued_at_unix,
    const char *claims,
    const char *signature_alg,
    const char *signature,
    struct vantaq_evidence **out_evidence
);

/**
 * @brief Destroy an evidence object.
 */
void vantaq_evidence_destroy(struct vantaq_evidence *evidence);

/**
 * @brief Getters for evidence fields.
 */
const char *vantaq_evidence_get_evidence_id(const struct vantaq_evidence *evidence);
const char *vantaq_evidence_get_device_id(const struct vantaq_evidence *evidence);
const char *vantaq_evidence_get_verifier_id(const struct vantaq_evidence *evidence);
const char *vantaq_evidence_get_challenge_id(const struct vantaq_evidence *evidence);
const char *vantaq_evidence_get_nonce(const struct vantaq_evidence *evidence);
const char *vantaq_evidence_get_purpose(const struct vantaq_evidence *evidence);
int64_t vantaq_evidence_get_issued_at_unix(const struct vantaq_evidence *evidence);
const char *vantaq_evidence_get_claims(const struct vantaq_evidence *evidence);
const char *vantaq_evidence_get_signature_alg(const struct vantaq_evidence *evidence);
const char *vantaq_evidence_get_signature(const struct vantaq_evidence *evidence);

#endif
