// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_INFRASTRUCTURE_RING_BUFFER_FILE_EVIDENCE_RING_BUFFER_H
#define VANTAQ_INFRASTRUCTURE_RING_BUFFER_FILE_EVIDENCE_RING_BUFFER_H

#include "domain/ring_buffer/ring_buffer.h"

#include <stddef.h>

struct vantaq_evidence_ring_buffer;

enum vantaq_evidence_ring_open_status {
    VANTAQ_EVIDENCE_RING_OPEN_OK = 0,
    VANTAQ_EVIDENCE_RING_OPEN_INVALID_ARGUMENT,
    VANTAQ_EVIDENCE_RING_OPEN_FAILED,
    VANTAQ_EVIDENCE_RING_OPEN_IO_ERROR,
    VANTAQ_EVIDENCE_RING_OPEN_INVALID_HEADER,
    VANTAQ_EVIDENCE_RING_OPEN_CONFIG_MISMATCH,
    VANTAQ_EVIDENCE_RING_OPEN_OUT_OF_MEMORY,
};

enum vantaq_evidence_ring_open_status
vantaq_evidence_ring_buffer_open(const struct vantaq_ring_buffer_config *config,
                                 struct vantaq_evidence_ring_buffer **out_buffer);

void vantaq_evidence_ring_buffer_destroy(struct vantaq_evidence_ring_buffer *buffer);

int vantaq_evidence_ring_buffer_fd(const struct vantaq_evidence_ring_buffer *buffer);
const char *vantaq_evidence_ring_buffer_path(const struct vantaq_evidence_ring_buffer *buffer);
size_t vantaq_evidence_ring_buffer_max_records(const struct vantaq_evidence_ring_buffer *buffer);
size_t
vantaq_evidence_ring_buffer_max_record_bytes(const struct vantaq_evidence_ring_buffer *buffer);
size_t
vantaq_evidence_ring_buffer_record_slot_size(const struct vantaq_evidence_ring_buffer *buffer);
size_t vantaq_evidence_ring_buffer_file_size(const struct vantaq_evidence_ring_buffer *buffer);
const char *
vantaq_evidence_ring_buffer_last_error(const struct vantaq_evidence_ring_buffer *buffer);

#endif
