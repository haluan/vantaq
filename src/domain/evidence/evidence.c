// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "domain/evidence/evidence.h"
#include "internal/macros.h"

#include <stdlib.h>
#include <string.h>

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

static void secure_zero_memory(void *ptr, size_t size) {
    volatile unsigned char *p = ptr;
    while (size--) {
        *p++ = 0;
    }
}

static void copy_text_bounded(char *dst, size_t dst_size, const char *src) {
    size_t src_len;
    size_t copy_len;

    if (dst == NULL || src == NULL || dst_size == 0) {
        return;
    }

    src_len  = strlen(src);
    copy_len = src_len < (dst_size - 1) ? src_len : (dst_size - 1);
    memcpy(dst, src, copy_len);
    dst[copy_len] = '\0';
}

static vantaq_evidence_err_t validate_text_field(const char *value, size_t max_size) {
    if (!value || strlen(value) == 0) {
        return VANTAQ_EVIDENCE_ERR_MISSING_FIELD;
    }
    if (strlen(value) >= max_size) {
        return VANTAQ_EVIDENCE_ERR_FIELD_TOO_LONG;
    }
    return VANTAQ_EVIDENCE_OK;
}

static vantaq_evidence_err_t validate_fields(const char *evidence_id, const char *device_id,
                                             const char *verifier_id, const char *challenge_id,
                                             const char *nonce, const char *purpose,
                                             int64_t issued_at_unix, const char *claims,
                                             const char *signature_alg, const char *signature) {
    vantaq_evidence_err_t err = validate_text_field(evidence_id, VANTAQ_EVIDENCE_ID_MAX);
    if (err != VANTAQ_EVIDENCE_OK) {
        return err;
    }
    err = validate_text_field(device_id, VANTAQ_DEVICE_ID_MAX);
    if (err != VANTAQ_EVIDENCE_OK) {
        return err;
    }
    err = validate_text_field(verifier_id, VANTAQ_VERIFIER_ID_MAX);
    if (err != VANTAQ_EVIDENCE_OK) {
        return err;
    }
    err = validate_text_field(challenge_id, VANTAQ_CHALLENGE_ID_MAX);
    if (err != VANTAQ_EVIDENCE_OK) {
        return err;
    }
    err = validate_text_field(nonce, VANTAQ_NONCE_MAX);
    if (err != VANTAQ_EVIDENCE_OK) {
        return err;
    }
    err = validate_text_field(purpose, VANTAQ_PURPOSE_MAX);
    if (err != VANTAQ_EVIDENCE_OK) {
        return err;
    }
    err = validate_text_field(claims, VANTAQ_CLAIMS_MAX);
    if (err != VANTAQ_EVIDENCE_OK) {
        return err;
    }
    err = validate_text_field(signature_alg, VANTAQ_SIGNATURE_ALG_MAX);
    if (err != VANTAQ_EVIDENCE_OK) {
        return err;
    }
    err = validate_text_field(signature, VANTAQ_SIGNATURE_MAX);
    if (err != VANTAQ_EVIDENCE_OK) {
        return err;
    }

    if (issued_at_unix <= 0) {
        return VANTAQ_EVIDENCE_ERR_INVALID_ARG;
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

    vantaq_evidence_err_t err =
        validate_fields(evidence_id, device_id, verifier_id, challenge_id, nonce, purpose,
                        issued_at_unix, claims, signature_alg, signature);
    if (err != VANTAQ_EVIDENCE_OK) {
        return err;
    }

    struct vantaq_evidence *ev = malloc(sizeof(struct vantaq_evidence));
    if (!ev) {
        return VANTAQ_EVIDENCE_ERR_MALLOC_FAILED;
    }

    ER_ZERO_STRUCT(*ev);

    copy_text_bounded(ev->evidence_id, sizeof(ev->evidence_id), evidence_id);
    copy_text_bounded(ev->device_id, sizeof(ev->device_id), device_id);
    copy_text_bounded(ev->verifier_id, sizeof(ev->verifier_id), verifier_id);
    copy_text_bounded(ev->challenge_id, sizeof(ev->challenge_id), challenge_id);
    copy_text_bounded(ev->nonce, sizeof(ev->nonce), nonce);
    copy_text_bounded(ev->purpose, sizeof(ev->purpose), purpose);
    ev->issued_at_unix = issued_at_unix;
    copy_text_bounded(ev->claims, sizeof(ev->claims), claims);
    copy_text_bounded(ev->signature_alg, sizeof(ev->signature_alg), signature_alg);
    copy_text_bounded(ev->signature, sizeof(ev->signature), signature);

    *out_evidence = ev;
    return VANTAQ_EVIDENCE_OK;
}

void vantaq_evidence_destroy(struct vantaq_evidence *evidence) {
    if (evidence) {
        secure_zero_memory(evidence, sizeof(*evidence));
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
    return evidence ? evidence->issued_at_unix : -1;
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

vantaq_evidence_err_t vantaq_evidence_update_signature(struct vantaq_evidence *evidence,
                                                       const char *signature) {
    vantaq_evidence_err_t err = VANTAQ_EVIDENCE_OK;

    if (evidence == NULL || signature == NULL) {
        return VANTAQ_EVIDENCE_ERR_INVALID_ARG;
    }

    err = validate_text_field(signature, VANTAQ_SIGNATURE_MAX);
    if (err != VANTAQ_EVIDENCE_OK) {
        return err;
    }

    copy_text_bounded(evidence->signature, sizeof(evidence->signature), signature);
    return VANTAQ_EVIDENCE_OK;
}
