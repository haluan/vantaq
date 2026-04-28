// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "domain/evidence/evidence_canonical.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void secure_zero_memory(void *ptr, size_t size) {
    volatile unsigned char *p = ptr;
    while (size--) {
        *p++ = 0;
    }
}

static char *escape_canonical_field(const char *value) {
    size_t in_len  = strlen(value);
    size_t out_len = 0;
    for (size_t i = 0; i < in_len; ++i) {
        if (value[i] == '|' || value[i] == '\\') {
            out_len += 2;
        } else {
            out_len += 1;
        }
    }

    char *escaped = malloc(out_len + 1);
    if (!escaped) {
        return NULL;
    }

    size_t j = 0;
    for (size_t i = 0; i < in_len; ++i) {
        if (value[i] == '|' || value[i] == '\\') {
            escaped[j++] = '\\';
        }
        escaped[j++] = value[i];
    }
    escaped[j] = '\0';
    return escaped;
}

vantaq_evidence_err_t vantaq_evidence_serialize_canonical(const struct vantaq_evidence *evidence,
                                                          char **out_buffer, size_t *out_len) {
    if (!evidence || !out_buffer || !out_len) {
        return VANTAQ_EVIDENCE_ERR_INVALID_ARG;
    }

    const char *ev_id   = vantaq_evidence_get_evidence_id(evidence);
    const char *dev_id  = vantaq_evidence_get_device_id(evidence);
    const char *ver_id  = vantaq_evidence_get_verifier_id(evidence);
    const char *ch_id   = vantaq_evidence_get_challenge_id(evidence);
    const char *nonce   = vantaq_evidence_get_nonce(evidence);
    const char *purpose = vantaq_evidence_get_purpose(evidence);
    int64_t issued_at   = vantaq_evidence_get_issued_at_unix(evidence);
    const char *claims  = vantaq_evidence_get_claims(evidence);
    const char *sig_alg = vantaq_evidence_get_signature_alg(evidence);
    if (!ev_id || !dev_id || !ver_id || !ch_id || !nonce || !purpose || !claims || !sig_alg ||
        issued_at <= 0) {
        return VANTAQ_EVIDENCE_ERR_INVALID_ARG;
    }

    char *esc_ch_id   = escape_canonical_field(ch_id);
    char *esc_claims  = escape_canonical_field(claims);
    char *esc_dev_id  = escape_canonical_field(dev_id);
    char *esc_ev_id   = escape_canonical_field(ev_id);
    char *esc_nonce   = escape_canonical_field(nonce);
    char *esc_purpose = escape_canonical_field(purpose);
    char *esc_sig_alg = escape_canonical_field(sig_alg);
    char *esc_ver_id  = escape_canonical_field(ver_id);

    if (!esc_ch_id || !esc_claims || !esc_dev_id || !esc_ev_id || !esc_nonce || !esc_purpose ||
        !esc_sig_alg || !esc_ver_id) {
        free(esc_ch_id);
        free(esc_claims);
        free(esc_dev_id);
        free(esc_ev_id);
        free(esc_nonce);
        free(esc_purpose);
        free(esc_sig_alg);
        free(esc_ver_id);
        return VANTAQ_EVIDENCE_ERR_MALLOC_FAILED;
    }

    // Strict fixed order format string (excluding signature). Field values are escaped so '|'
    // remains an unambiguous delimiter in the serialized output.
    const char *format =
        "challenge_id:%s|claims:%s|device_id:%s|evidence_id:%s|issued_at_unix:%" PRId64
        "|nonce:%s|purpose:%s|signature_alg:%s|verifier_id:%s";

    // 1. Calculate required length
    int len = snprintf(NULL, 0, format, esc_ch_id, esc_claims, esc_dev_id, esc_ev_id, issued_at,
                       esc_nonce, esc_purpose, esc_sig_alg, esc_ver_id);
    if (len < 0) {
        free(esc_ch_id);
        free(esc_claims);
        free(esc_dev_id);
        free(esc_ev_id);
        free(esc_nonce);
        free(esc_purpose);
        free(esc_sig_alg);
        free(esc_ver_id);
        return VANTAQ_EVIDENCE_ERR_INTERNAL;
    }

    // 2. Allocate buffer
    char *buffer = malloc(len + 1);
    if (!buffer) {
        free(esc_ch_id);
        free(esc_claims);
        free(esc_dev_id);
        free(esc_ev_id);
        free(esc_nonce);
        free(esc_purpose);
        free(esc_sig_alg);
        free(esc_ver_id);
        return VANTAQ_EVIDENCE_ERR_MALLOC_FAILED;
    }

    // 3. Populate buffer
    int written = snprintf(buffer, len + 1, format, esc_ch_id, esc_claims, esc_dev_id, esc_ev_id,
                           issued_at, esc_nonce, esc_purpose, esc_sig_alg, esc_ver_id);
    free(esc_ch_id);
    free(esc_claims);
    free(esc_dev_id);
    free(esc_ev_id);
    free(esc_nonce);
    free(esc_purpose);
    free(esc_sig_alg);
    free(esc_ver_id);

    // Detect concurrent mutation or runtime inconsistencies between size and write passes.
    if (written != len) {
        free(buffer);
        return VANTAQ_EVIDENCE_ERR_INTERNAL;
    }

    *out_buffer = buffer;
    *out_len    = (size_t)len;
    return VANTAQ_EVIDENCE_OK;
}

void vantaq_evidence_canonical_destroy(char *buffer) {
    if (buffer) {
        secure_zero_memory(buffer, strlen(buffer));
        free(buffer);
    }
}

void vantaq_evidence_canonical_free(char *buffer) { vantaq_evidence_canonical_destroy(buffer); }
