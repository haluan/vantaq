// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "domain/evidence/evidence_canonical.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

vantaq_evidence_err_t vantaq_evidence_serialize_canonical(const struct vantaq_evidence *evidence,
                                                          char **out_buffer, size_t *out_len) {
    if (!evidence || !out_buffer || !out_len) {
        return VANTAQ_EVIDENCE_ERR_INVALID_ARG;
    }

    const char *ev_id = vantaq_evidence_get_evidence_id(evidence);
    const char *dev_id = vantaq_evidence_get_device_id(evidence);
    const char *ver_id = vantaq_evidence_get_verifier_id(evidence);
    const char *ch_id = vantaq_evidence_get_challenge_id(evidence);
    const char *nonce = vantaq_evidence_get_nonce(evidence);
    const char *purpose = vantaq_evidence_get_purpose(evidence);
    int64_t issued_at = vantaq_evidence_get_issued_at_unix(evidence);
    const char *claims = vantaq_evidence_get_claims(evidence);
    const char *sig_alg = vantaq_evidence_get_signature_alg(evidence);

    // Strict fixed order format string (excluding signature)
    const char *format = "challenge_id:%s|claims:%s|device_id:%s|evidence_id:%s|issued_at_unix:%lld|nonce:%s|purpose:%s|signature_alg:%s|verifier_id:%s";

    // 1. Calculate required length
    int len = snprintf(NULL, 0, format, ch_id, claims, dev_id, ev_id, (long long)issued_at, nonce, purpose, sig_alg, ver_id);
    if (len < 0) {
        return VANTAQ_EVIDENCE_ERR_INVALID_ARG; // Should not happen with valid strings
    }

    // 2. Allocate buffer
    char *buffer = malloc(len + 1);
    if (!buffer) {
        return VANTAQ_EVIDENCE_ERR_MALLOC_FAILED;
    }

    // 3. Populate buffer
    int written = snprintf(buffer, len + 1, format, ch_id, claims, dev_id, ev_id, (long long)issued_at, nonce, purpose, sig_alg, ver_id);
    if (written != len) {
        free(buffer);
        return VANTAQ_EVIDENCE_ERR_INVALID_ARG;
    }

    *out_buffer = buffer;
    *out_len = (size_t)len;
    return VANTAQ_EVIDENCE_OK;
}

void vantaq_evidence_canonical_free(char *buffer) {
    if (buffer) {
        free(buffer);
    }
}
