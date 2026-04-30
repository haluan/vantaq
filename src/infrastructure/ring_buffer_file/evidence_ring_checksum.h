// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_INFRASTRUCTURE_RING_BUFFER_FILE_EVIDENCE_RING_CHECKSUM_H
#define VANTAQ_INFRASTRUCTURE_RING_BUFFER_FILE_EVIDENCE_RING_CHECKSUM_H

#include "evidence_ring_format.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    VANTAQ_EVIDENCE_RING_CHECKSUM_OK = 0,
    VANTAQ_EVIDENCE_RING_CHECKSUM_MISMATCH,
    VANTAQ_EVIDENCE_RING_CHECKSUM_INVALID_FORMAT,
    VANTAQ_EVIDENCE_RING_CHECKSUM_INVALID_INPUT,
    VANTAQ_EVIDENCE_RING_CHECKSUM_ENGINE_FAILURE,
} vantaq_evidence_ring_checksum_status_t;

vantaq_evidence_ring_checksum_status_t
vantaq_evidence_ring_checksum_compute(const uint8_t *slot_buf, size_t slot_buf_len,
                                      size_t max_record_bytes,
                                      char out_checksum[VANTAQ_RING_BUFFER_CHECKSUM_MAX]);

vantaq_evidence_ring_checksum_status_t
vantaq_evidence_ring_checksum_is_valid_format(const char *checksum);

vantaq_evidence_ring_checksum_status_t
vantaq_evidence_ring_checksum_verify(const uint8_t *slot_buf, size_t slot_buf_len,
                                     size_t max_record_bytes);

vantaq_evidence_ring_checksum_status_t
vantaq_evidence_ring_checksum_compute_into_slot(uint8_t *slot_buf, size_t slot_buf_len,
                                                size_t max_record_bytes);

#endif
