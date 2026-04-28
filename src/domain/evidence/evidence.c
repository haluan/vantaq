// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "domain/evidence/evidence.h"

#include <stdlib.h>
#include <string.h>

#define ER_ZERO_STRUCT(s) memset(&(s), 0, sizeof(s))

struct vantaq_evidence {
    char evidence_id[VANTAQ_EVIDENCE_ID_MAX];
    char device_id[VANTAQ_DEVICE_ID_MAX];
    char verifier_id[VANTAQ_VERIFIER_ID_MAX];
    char challenge_id[VANTAQ_CHALLENGE_ID_MAX];
    char nonce[VANTAQ_NONCE_MAX];
    char purpose[VANTAQ_PURPOSE_MAX];
    int64_t issued_at_unix;
    char claims[VANTAQ_CLAIMS_MAX];
    char signature_alg[VANTAQ_SIGNATURE_ALG_MAX];
    char signature[VANTAQ_SIGNATURE_MAX];
};

static vantaq_evidence_err_t validate_fields(const char *evidence_id, const char *device_id,
                                             const char *verifier_id, const char *challenge_id,
                                             const char *nonce, const char *purpose,
                                             const char *claims, const char *signature_alg,
                                             const char *signature) {
    if (!evidence_id || strlen(evidence_id) == 0 || !device_id || strlen(device_id) == 0 ||
        !verifier_id || strlen(verifier_id) == 0 || !challenge_id || strlen(challenge_id) == 0 ||
        !nonce || strlen(nonce) == 0 || !purpose || strlen(purpose) == 0 || !claims ||
        strlen(claims) == 0 || !signature_alg || strlen(signature_alg) == 0 || !signature ||
        strlen(signature) == 0) {
        return VANTAQ_EVIDENCE_ERR_MISSING_FIELD;
    }
    return VANTAQ_EVIDENCE_OK;
}

vantaq_evidence_err_t vantaq_evidence_create(const char *evidence_id, const char *device_id,
                                             const char *verifier_id, const char *challenge_id,
                                             const char *nonce, const char *purpose,
                                             int64_t issued_at_unix, const char *claims,
                                             const char *signature_alg, const char *signature,
                                             struct vantaq_evidence **out_evidence) {
    if (!out_evidence) {
        return VANTAQ_EVIDENCE_ERR_INVALID_ARG;
    }

    vantaq_evidence_err_t err = validate_fields(evidence_id, device_id, verifier_id, challenge_id,
                                                nonce, purpose, claims, signature_alg, signature);
    if (err != VANTAQ_EVIDENCE_OK) {
        return err;
    }

    struct vantaq_evidence *ev = malloc(sizeof(struct vantaq_evidence));
    if (!ev) {
        return VANTAQ_EVIDENCE_ERR_MALLOC_FAILED;
    }

    ER_ZERO_STRUCT(*ev);

    // Using strncpy to ensure we don't overflow, though validation should have caught major issues
    // and we know the sizes.
    strncpy(ev->evidence_id, evidence_id, VANTAQ_EVIDENCE_ID_MAX - 1);
    strncpy(ev->device_id, device_id, VANTAQ_DEVICE_ID_MAX - 1);
    strncpy(ev->verifier_id, verifier_id, VANTAQ_VERIFIER_ID_MAX - 1);
    strncpy(ev->challenge_id, challenge_id, VANTAQ_CHALLENGE_ID_MAX - 1);
    strncpy(ev->nonce, nonce, VANTAQ_NONCE_MAX - 1);
    strncpy(ev->purpose, purpose, VANTAQ_PURPOSE_MAX - 1);
    ev->issued_at_unix = issued_at_unix;
    strncpy(ev->claims, claims, VANTAQ_CLAIMS_MAX - 1);
    strncpy(ev->signature_alg, signature_alg, VANTAQ_SIGNATURE_ALG_MAX - 1);
    strncpy(ev->signature, signature, VANTAQ_SIGNATURE_MAX - 1);

    *out_evidence = ev;
    return VANTAQ_EVIDENCE_OK;
}

void vantaq_evidence_destroy(struct vantaq_evidence *evidence) {
    if (evidence) {
        free(evidence);
    }
}

const char *vantaq_evidence_get_evidence_id(const struct vantaq_evidence *evidence) {
    return evidence ? evidence->evidence_id : NULL;
}

const char *vantaq_evidence_get_device_id(const struct vantaq_evidence *evidence) {
    return evidence ? evidence->device_id : NULL;
}

const char *vantaq_evidence_get_verifier_id(const struct vantaq_evidence *evidence) {
    return evidence ? evidence->verifier_id : NULL;
}

const char *vantaq_evidence_get_challenge_id(const struct vantaq_evidence *evidence) {
    return evidence ? evidence->challenge_id : NULL;
}

const char *vantaq_evidence_get_nonce(const struct vantaq_evidence *evidence) {
    return evidence ? evidence->nonce : NULL;
}

const char *vantaq_evidence_get_purpose(const struct vantaq_evidence *evidence) {
    return evidence ? evidence->purpose : NULL;
}

int64_t vantaq_evidence_get_issued_at_unix(const struct vantaq_evidence *evidence) {
    return evidence ? evidence->issued_at_unix : 0;
}

const char *vantaq_evidence_get_claims(const struct vantaq_evidence *evidence) {
    return evidence ? evidence->claims : NULL;
}

const char *vantaq_evidence_get_signature_alg(const struct vantaq_evidence *evidence) {
    return evidence ? evidence->signature_alg : NULL;
}

const char *vantaq_evidence_get_signature(const struct vantaq_evidence *evidence) {
    return evidence ? evidence->signature : NULL;
}
