// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_APPLICATION_EVIDENCE_GET_LATEST_EVIDENCE_H
#define VANTAQ_APPLICATION_EVIDENCE_GET_LATEST_EVIDENCE_H

struct vantaq_evidence_ring_buffer;

enum vantaq_app_get_latest_evidence_status {
    VANTAQ_APP_GET_LATEST_EVIDENCE_OK = 0,
    VANTAQ_APP_GET_LATEST_EVIDENCE_NOT_FOUND = 1,
    VANTAQ_APP_GET_LATEST_EVIDENCE_INVALID_ARGUMENT = 2,
    VANTAQ_APP_GET_LATEST_EVIDENCE_INTERNAL_ERROR = 3,
};

enum vantaq_app_get_latest_evidence_status vantaq_app_get_latest_evidence(
    struct vantaq_evidence_ring_buffer *ring_buffer, const char *verifier_id,
    char **out_evidence_json);

#endif
