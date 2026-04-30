// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_APPLICATION_EVIDENCE_GET_LATEST_EVIDENCE_H
#define VANTAQ_APPLICATION_EVIDENCE_GET_LATEST_EVIDENCE_H

struct vantaq_evidence_ring_buffer;

enum vantaq_app_get_latest_evidence_status {
    VANTAQ_APP_GET_LATEST_EVIDENCE_OK = 0,
    VANTAQ_APP_GET_LATEST_EVIDENCE_NOT_FOUND = 1,
    VANTAQ_APP_GET_LATEST_EVIDENCE_INVALID_ARGUMENT = 2,
    VANTAQ_APP_GET_LATEST_EVIDENCE_RECORD_CORRUPTED = 3,
    VANTAQ_APP_GET_LATEST_EVIDENCE_INTERNAL_ERROR = 4,
};

/**
 * Retrieves the latest evidence JSON for a specific verifier.
 *
 * @param ring_buffer The evidence ring buffer to read from.
 * @param verifier_id The ID of the verifier whose latest evidence is sought.
 * @param out_evidence_json Pointer to a string pointer that will receive the 
 *        JSON content. On VANTAQ_APP_GET_LATEST_EVIDENCE_OK, the caller
 *        is responsible for free()ing this memory.
 * @return Status code of the operation.
 */
enum vantaq_app_get_latest_evidence_status vantaq_app_get_latest_evidence(
    struct vantaq_evidence_ring_buffer *ring_buffer, const char *verifier_id,
    char **out_evidence_json);

#endif
