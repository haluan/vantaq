// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_DOMAIN_RING_BUFFER_RING_BUFFER_H
#define VANTAQ_DOMAIN_RING_BUFFER_RING_BUFFER_H

#include "domain/evidence/evidence.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VANTAQ_RING_BUFFER_FILE_PATH_MAX 256
#define VANTAQ_RING_BUFFER_EVIDENCE_HASH_MAX 128
#define VANTAQ_RING_BUFFER_CHECKSUM_MAX 128
#define VANTAQ_RING_BUFFER_MAX_RECORD_BYTES_LIMIT (10U * 1024U * 1024U)
#define VANTAQ_RING_BUFFER_INVALID_SLOT UINT64_MAX
#define VANTAQ_RING_BUFFER_INVALID_SEQUENCE UINT64_MAX

typedef enum {
    RING_BUFFER_OK = 0,
    RING_BUFFER_INVALID_CONFIG = 1,
    RING_BUFFER_RECORD_TOO_LARGE = 2,
    RING_BUFFER_RECORD_NOT_FOUND = 3,
    RING_BUFFER_RECORD_CORRUPTED = 4,
    RING_BUFFER_IO_ERROR = 5
} ring_buffer_err_t;

struct vantaq_ring_buffer_config;
struct vantaq_ring_buffer_header;
struct vantaq_ring_buffer_record;
struct vantaq_ring_buffer_append_result;
struct vantaq_ring_buffer_read_result;

ring_buffer_err_t vantaq_ring_buffer_config_create(
    const char *file_path,
    size_t max_records,
    size_t max_record_bytes,
    bool fsync_on_append,
    struct vantaq_ring_buffer_config **out_config);

ring_buffer_err_t
vantaq_ring_buffer_config_validate(const struct vantaq_ring_buffer_config *config);

void vantaq_ring_buffer_config_destroy(struct vantaq_ring_buffer_config *config);

const char *vantaq_ring_buffer_config_get_file_path(const struct vantaq_ring_buffer_config *config);
size_t vantaq_ring_buffer_config_get_max_records(const struct vantaq_ring_buffer_config *config);
size_t
vantaq_ring_buffer_config_get_max_record_bytes(const struct vantaq_ring_buffer_config *config);
bool
vantaq_ring_buffer_config_get_fsync_on_append(const struct vantaq_ring_buffer_config *config);

ring_buffer_err_t vantaq_ring_buffer_header_create(
    uint64_t next_slot,
    uint64_t next_sequence,
    uint64_t active_records,
    struct vantaq_ring_buffer_header **out_header);

void vantaq_ring_buffer_header_destroy(struct vantaq_ring_buffer_header *header);

uint64_t vantaq_ring_buffer_header_get_next_slot(const struct vantaq_ring_buffer_header *header);
uint64_t
vantaq_ring_buffer_header_get_next_sequence(const struct vantaq_ring_buffer_header *header);
uint64_t
vantaq_ring_buffer_header_get_active_records(const struct vantaq_ring_buffer_header *header);

ring_buffer_err_t vantaq_ring_buffer_record_create(
    const struct vantaq_ring_buffer_config *config,
    uint64_t record_slot,
    uint64_t record_sequence,
    const char *evidence_id,
    const char *verifier_id,
    int64_t issued_at_unix,
    const char *evidence_json,
    const char *evidence_hash,
    const char *checksum,
    struct vantaq_ring_buffer_record **out_record);

void vantaq_ring_buffer_record_destroy(struct vantaq_ring_buffer_record *record);

uint64_t vantaq_ring_buffer_record_get_record_slot(const struct vantaq_ring_buffer_record *record);
uint64_t
vantaq_ring_buffer_record_get_record_sequence(const struct vantaq_ring_buffer_record *record);
const char *
vantaq_ring_buffer_record_get_evidence_id(const struct vantaq_ring_buffer_record *record);
const char *
vantaq_ring_buffer_record_get_verifier_id(const struct vantaq_ring_buffer_record *record);
int64_t vantaq_ring_buffer_record_get_issued_at_unix(const struct vantaq_ring_buffer_record *record);
const char *
vantaq_ring_buffer_record_get_evidence_json(const struct vantaq_ring_buffer_record *record);
size_t
vantaq_ring_buffer_record_get_evidence_json_size(const struct vantaq_ring_buffer_record *record);
const char *
vantaq_ring_buffer_record_get_evidence_hash(const struct vantaq_ring_buffer_record *record);
const char *vantaq_ring_buffer_record_get_checksum(const struct vantaq_ring_buffer_record *record);

ring_buffer_err_t vantaq_ring_buffer_append_result_create_success(
    uint64_t record_slot,
    uint64_t record_sequence,
    struct vantaq_ring_buffer_append_result **out_result);

ring_buffer_err_t vantaq_ring_buffer_append_result_create_error(
    ring_buffer_err_t status,
    struct vantaq_ring_buffer_append_result **out_result);

void vantaq_ring_buffer_append_result_destroy(struct vantaq_ring_buffer_append_result *result);

ring_buffer_err_t
vantaq_ring_buffer_append_result_get_status(const struct vantaq_ring_buffer_append_result *result);
uint64_t
vantaq_ring_buffer_append_result_get_record_slot(const struct vantaq_ring_buffer_append_result *result);
uint64_t
vantaq_ring_buffer_append_result_get_record_sequence(const struct vantaq_ring_buffer_append_result *result);

ring_buffer_err_t vantaq_ring_buffer_read_result_create_found(
    const struct vantaq_ring_buffer_record *record,
    struct vantaq_ring_buffer_read_result **out_result);

ring_buffer_err_t
vantaq_ring_buffer_read_result_create_not_found(struct vantaq_ring_buffer_read_result **out_result);

ring_buffer_err_t vantaq_ring_buffer_read_result_create_corrupted(
    uint64_t record_slot,
    uint64_t record_sequence,
    struct vantaq_ring_buffer_read_result **out_result);

ring_buffer_err_t vantaq_ring_buffer_read_result_create_error(
    ring_buffer_err_t status,
    struct vantaq_ring_buffer_read_result **out_result);

void vantaq_ring_buffer_read_result_destroy(struct vantaq_ring_buffer_read_result *result);

ring_buffer_err_t
vantaq_ring_buffer_read_result_get_status(const struct vantaq_ring_buffer_read_result *result);
const struct vantaq_ring_buffer_record *
vantaq_ring_buffer_read_result_get_record(const struct vantaq_ring_buffer_read_result *result);
uint64_t
vantaq_ring_buffer_read_result_get_record_slot(const struct vantaq_ring_buffer_read_result *result);
uint64_t
vantaq_ring_buffer_read_result_get_record_sequence(const struct vantaq_ring_buffer_read_result *result);

#endif
