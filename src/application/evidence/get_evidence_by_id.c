// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/evidence/get_evidence_by_id.h"

#include "domain/evidence/evidence.h"
#include "domain/ring_buffer/ring_buffer.h"
#include "evidence_internal.h"
#include "evidence_ring_buffer.h"

#include <stdlib.h>
#include <string.h>

enum vantaq_app_get_evidence_by_id_status
vantaq_app_get_evidence_by_id(struct vantaq_evidence_ring_buffer *ring_buffer,
                              const char *verifier_id, const char *evidence_id,
                              char **out_evidence_json) {
    enum vantaq_app_get_evidence_by_id_status app_status =
        VANTAQ_APP_GET_EVIDENCE_BY_ID_INTERNAL_ERROR;
    enum vantaq_evidence_ring_read_status read_status;
    struct vantaq_ring_buffer_read_result *read_result = NULL;
    const struct vantaq_ring_buffer_record *record;
    const char *evidence_json;
    size_t evidence_json_len;
    char *copy;

    if (out_evidence_json == NULL) {
        return VANTAQ_APP_GET_EVIDENCE_BY_ID_INVALID_ARGUMENT;
    }
    *out_evidence_json = NULL;

    if (ring_buffer == NULL ||
        !vantaq_app_evidence_text_is_valid(verifier_id, VANTAQ_VERIFIER_ID_MAX) ||
        !vantaq_app_evidence_text_is_valid(evidence_id, VANTAQ_EVIDENCE_ID_MAX)) {
        return VANTAQ_APP_GET_EVIDENCE_BY_ID_INVALID_ARGUMENT;
    }

    read_status = vantaq_evidence_ring_buffer_read_by_evidence_id_for_verifier(
        ring_buffer, evidence_id, verifier_id, &read_result);
    if (read_status != VANTAQ_EVIDENCE_RING_READ_OK) {
        if (read_status == VANTAQ_EVIDENCE_RING_READ_INVALID_ARGUMENT) {
            return VANTAQ_APP_GET_EVIDENCE_BY_ID_INVALID_ARGUMENT;
        }
        return VANTAQ_APP_GET_EVIDENCE_BY_ID_INTERNAL_ERROR;
    }
    if (read_result == NULL) {
        return VANTAQ_APP_GET_EVIDENCE_BY_ID_INTERNAL_ERROR;
    }

    switch (vantaq_ring_buffer_read_result_get_status(read_result)) {
    case RING_BUFFER_OK:
        break;
    case RING_BUFFER_RECORD_NOT_FOUND:
        app_status = VANTAQ_APP_GET_EVIDENCE_BY_ID_NOT_FOUND;
        goto cleanup;
    case RING_BUFFER_RECORD_CORRUPTED:
        app_status = VANTAQ_APP_GET_EVIDENCE_BY_ID_RECORD_CORRUPTED;
        goto cleanup;
    default:
        app_status = VANTAQ_APP_GET_EVIDENCE_BY_ID_INTERNAL_ERROR;
        goto cleanup;
    }

    record = vantaq_ring_buffer_read_result_get_record(read_result);
    if (record == NULL) {
        goto cleanup;
    }

    evidence_json     = vantaq_ring_buffer_record_get_evidence_json(record);
    evidence_json_len = vantaq_ring_buffer_record_get_evidence_json_size(record);

    if (evidence_json[0] == '\0' || evidence_json_len == 0U) {
        goto cleanup;
    }

    if (evidence_json_len >= VANTAQ_RING_BUFFER_MAX_RECORD_BYTES_LIMIT) {
        goto cleanup;
    }

    copy = (char *)malloc(evidence_json_len + 1U);
    if (copy == NULL) {
        goto cleanup;
    }

    memcpy(copy, evidence_json, evidence_json_len);
    copy[evidence_json_len] = '\0';

    *out_evidence_json = copy;
    app_status         = VANTAQ_APP_GET_EVIDENCE_BY_ID_OK;

cleanup:
    if (read_result != NULL) {
        vantaq_ring_buffer_read_result_destroy(read_result);
    }

    return app_status;
}
