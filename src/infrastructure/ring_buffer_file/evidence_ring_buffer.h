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

enum vantaq_evidence_ring_append_status {
    VANTAQ_EVIDENCE_RING_APPEND_OK = 0,
    VANTAQ_EVIDENCE_RING_APPEND_INVALID_ARGUMENT,
    VANTAQ_EVIDENCE_RING_APPEND_IO_ERROR,
    VANTAQ_EVIDENCE_RING_APPEND_WRITE_FAILED,
    VANTAQ_EVIDENCE_RING_APPEND_SYNC_FAILED,
};

enum vantaq_evidence_ring_read_status {
    VANTAQ_EVIDENCE_RING_READ_OK = 0,
    VANTAQ_EVIDENCE_RING_READ_INVALID_ARGUMENT,
    VANTAQ_EVIDENCE_RING_READ_IO_ERROR,
    VANTAQ_EVIDENCE_RING_READ_INVALID_HEADER,
    VANTAQ_EVIDENCE_RING_READ_OUT_OF_MEMORY,
};

enum vantaq_evidence_ring_open_status
vantaq_evidence_ring_buffer_open(const struct vantaq_ring_buffer_config *config,
                                 struct vantaq_evidence_ring_buffer **out_buffer);

void vantaq_evidence_ring_buffer_destroy(struct vantaq_evidence_ring_buffer *buffer);

enum vantaq_evidence_ring_append_status
vantaq_evidence_ring_buffer_append(struct vantaq_evidence_ring_buffer *buffer,
                                   const struct vantaq_ring_buffer_record *record,
                                   struct vantaq_ring_buffer_append_result **out_result);

enum vantaq_evidence_ring_read_status
vantaq_evidence_ring_buffer_read_latest(struct vantaq_evidence_ring_buffer *buffer,
                                        struct vantaq_ring_buffer_read_result **out_result);
enum vantaq_evidence_ring_read_status
vantaq_evidence_ring_buffer_read_by_evidence_id(struct vantaq_evidence_ring_buffer *buffer,
                                                const char *evidence_id,
                                                struct vantaq_ring_buffer_read_result **out_result);
enum vantaq_evidence_ring_read_status vantaq_evidence_ring_buffer_read_by_evidence_id_for_verifier(
    struct vantaq_evidence_ring_buffer *buffer, const char *evidence_id, const char *verifier_id,
    struct vantaq_ring_buffer_read_result **out_result);
enum vantaq_evidence_ring_read_status vantaq_evidence_ring_buffer_read_latest_by_verifier_id(
    struct vantaq_evidence_ring_buffer *buffer, const char *verifier_id,
    struct vantaq_ring_buffer_read_result **out_result);

void vantaq_evidence_ring_buffer_path(const struct vantaq_evidence_ring_buffer *buffer, char *out,
                                      size_t out_size);
size_t vantaq_evidence_ring_buffer_max_records(const struct vantaq_evidence_ring_buffer *buffer);
size_t
vantaq_evidence_ring_buffer_max_record_bytes(const struct vantaq_evidence_ring_buffer *buffer);
size_t
vantaq_evidence_ring_buffer_record_slot_size(const struct vantaq_evidence_ring_buffer *buffer);
size_t vantaq_evidence_ring_buffer_file_size(const struct vantaq_evidence_ring_buffer *buffer);
void vantaq_evidence_ring_buffer_last_error(const struct vantaq_evidence_ring_buffer *buffer,
                                            char *out, size_t out_size);

#endif
