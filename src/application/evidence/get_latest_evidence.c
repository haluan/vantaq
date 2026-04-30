// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/evidence/get_latest_evidence.h"

#include "domain/evidence/evidence.h"
#include "domain/ring_buffer/ring_buffer.h"
#include "evidence_ring_buffer.h"

#include <stdlib.h>
#include <string.h>

static bool verifier_id_is_valid(const char *verifier_id) {
    size_t len;

    if (verifier_id == NULL) {
        return false;
    }

    len = strnlen(verifier_id, VANTAQ_VERIFIER_ID_MAX);
    if (len == 0U || len >= VANTAQ_VERIFIER_ID_MAX) {
        return false;
    }

    return true;
}

enum vantaq_app_get_latest_evidence_status
vantaq_app_get_latest_evidence(struct vantaq_evidence_ring_buffer *ring_buffer,
                               const char *verifier_id, char **out_evidence_json) {
    enum vantaq_evidence_ring_read_status read_status;
    struct vantaq_ring_buffer_read_result *read_result = NULL;
    const struct vantaq_ring_buffer_record *record;
    const char *evidence_json;
    size_t evidence_json_len;
    char *copy;

    if (out_evidence_json == NULL) {
        return VANTAQ_APP_GET_LATEST_EVIDENCE_INVALID_ARGUMENT;
    }
    *out_evidence_json = NULL;

    if (ring_buffer == NULL || !verifier_id_is_valid(verifier_id)) {
        return VANTAQ_APP_GET_LATEST_EVIDENCE_INVALID_ARGUMENT;
    }

    read_status = vantaq_evidence_ring_buffer_read_latest_by_verifier_id(ring_buffer, verifier_id,
                                                                         &read_result);
    if (read_status != VANTAQ_EVIDENCE_RING_READ_OK) {
        return VANTAQ_APP_GET_LATEST_EVIDENCE_INTERNAL_ERROR;
    }
    if (read_result == NULL) {
        return VANTAQ_APP_GET_LATEST_EVIDENCE_INTERNAL_ERROR;
    }

    if (vantaq_ring_buffer_read_result_get_status(read_result) == RING_BUFFER_RECORD_NOT_FOUND) {
        vantaq_ring_buffer_read_result_destroy(read_result);
        return VANTAQ_APP_GET_LATEST_EVIDENCE_NOT_FOUND;
    }
    if (vantaq_ring_buffer_read_result_get_status(read_result) != RING_BUFFER_OK) {
        vantaq_ring_buffer_read_result_destroy(read_result);
        return VANTAQ_APP_GET_LATEST_EVIDENCE_INTERNAL_ERROR;
    }

    record = vantaq_ring_buffer_read_result_get_record(read_result);
    if (record == NULL) {
        vantaq_ring_buffer_read_result_destroy(read_result);
        return VANTAQ_APP_GET_LATEST_EVIDENCE_INTERNAL_ERROR;
    }

    evidence_json = vantaq_ring_buffer_record_get_evidence_json(record);
    if (evidence_json == NULL) {
        vantaq_ring_buffer_read_result_destroy(read_result);
        return VANTAQ_APP_GET_LATEST_EVIDENCE_INTERNAL_ERROR;
    }

    evidence_json_len = strlen(evidence_json);
    copy              = (char *)malloc(evidence_json_len + 1U);
    if (copy == NULL) {
        vantaq_ring_buffer_read_result_destroy(read_result);
        return VANTAQ_APP_GET_LATEST_EVIDENCE_INTERNAL_ERROR;
    }

    memcpy(copy, evidence_json, evidence_json_len + 1U);
    vantaq_ring_buffer_read_result_destroy(read_result);
    *out_evidence_json = copy;

    return VANTAQ_APP_GET_LATEST_EVIDENCE_OK;
}
