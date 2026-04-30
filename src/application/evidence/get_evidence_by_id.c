// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/evidence/get_evidence_by_id.h"

#include "domain/evidence/evidence.h"
#include "domain/ring_buffer/ring_buffer.h"
#include "evidence_ring_buffer.h"

#include <stdlib.h>
#include <string.h>

static bool text_is_valid(const char *value, size_t max_size) {
    size_t len;

    if (value == NULL) {
        return false;
    }

    len = strnlen(value, max_size);
    if (len == 0U || len >= max_size) {
        return false;
    }

    return true;
}

enum vantaq_app_get_evidence_by_id_status
vantaq_app_get_evidence_by_id(struct vantaq_evidence_ring_buffer *ring_buffer,
                              const char *verifier_id, const char *evidence_id,
                              char **out_evidence_json) {
    enum vantaq_evidence_ring_read_status read_status;
    struct vantaq_ring_buffer_read_result *read_result = NULL;
    const struct vantaq_ring_buffer_record *record;
    const char *record_verifier_id;
    const char *evidence_json;
    size_t evidence_json_len;
    char *copy;

    if (out_evidence_json == NULL) {
        return VANTAQ_APP_GET_EVIDENCE_BY_ID_INVALID_ARGUMENT;
    }
    *out_evidence_json = NULL;

    if (ring_buffer == NULL || !text_is_valid(verifier_id, VANTAQ_VERIFIER_ID_MAX) ||
        !text_is_valid(evidence_id, VANTAQ_EVIDENCE_ID_MAX)) {
        return VANTAQ_APP_GET_EVIDENCE_BY_ID_INVALID_ARGUMENT;
    }

    read_status =
        vantaq_evidence_ring_buffer_read_by_evidence_id(ring_buffer, evidence_id, &read_result);
    if (read_status != VANTAQ_EVIDENCE_RING_READ_OK) {
        return VANTAQ_APP_GET_EVIDENCE_BY_ID_INTERNAL_ERROR;
    }
    if (read_result == NULL) {
        return VANTAQ_APP_GET_EVIDENCE_BY_ID_INTERNAL_ERROR;
    }

    if (vantaq_ring_buffer_read_result_get_status(read_result) == RING_BUFFER_RECORD_NOT_FOUND) {
        vantaq_ring_buffer_read_result_destroy(read_result);
        return VANTAQ_APP_GET_EVIDENCE_BY_ID_NOT_FOUND;
    }
    if (vantaq_ring_buffer_read_result_get_status(read_result) != RING_BUFFER_OK) {
        vantaq_ring_buffer_read_result_destroy(read_result);
        return VANTAQ_APP_GET_EVIDENCE_BY_ID_INTERNAL_ERROR;
    }

    record = vantaq_ring_buffer_read_result_get_record(read_result);
    if (record == NULL) {
        vantaq_ring_buffer_read_result_destroy(read_result);
        return VANTAQ_APP_GET_EVIDENCE_BY_ID_INTERNAL_ERROR;
    }

    record_verifier_id = vantaq_ring_buffer_record_get_verifier_id(record);
    if (record_verifier_id == NULL || strcmp(record_verifier_id, verifier_id) != 0) {
        vantaq_ring_buffer_read_result_destroy(read_result);
        return VANTAQ_APP_GET_EVIDENCE_BY_ID_NOT_FOUND;
    }

    evidence_json = vantaq_ring_buffer_record_get_evidence_json(record);
    if (evidence_json == NULL) {
        vantaq_ring_buffer_read_result_destroy(read_result);
        return VANTAQ_APP_GET_EVIDENCE_BY_ID_INTERNAL_ERROR;
    }

    evidence_json_len = strlen(evidence_json);
    copy              = (char *)malloc(evidence_json_len + 1U);
    if (copy == NULL) {
        vantaq_ring_buffer_read_result_destroy(read_result);
        return VANTAQ_APP_GET_EVIDENCE_BY_ID_INTERNAL_ERROR;
    }

    memcpy(copy, evidence_json, evidence_json_len + 1U);
    vantaq_ring_buffer_read_result_destroy(read_result);
    *out_evidence_json = copy;

    return VANTAQ_APP_GET_EVIDENCE_BY_ID_OK;
}
