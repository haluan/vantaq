// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "domain/ring_buffer/ring_buffer.h"
#include "infrastructure/memory/zero_struct.h"

#include <stdlib.h>
#include <string.h>

struct vantaq_ring_buffer_config {
    char file_path[VANTAQ_RING_BUFFER_FILE_PATH_MAX];
    size_t max_records;
    size_t max_record_bytes;
    bool fsync_on_append;
};

struct vantaq_ring_buffer_header {
    uint64_t next_slot;
    uint64_t next_sequence;
    uint64_t active_records;
};

struct vantaq_ring_buffer_record {
    uint64_t record_slot;
    uint64_t record_sequence;
    char evidence_id[VANTAQ_EVIDENCE_ID_MAX];
    char verifier_id[VANTAQ_VERIFIER_ID_MAX];
    int64_t issued_at_unix;
    char *evidence_json;
    size_t evidence_json_size;
    char evidence_hash[VANTAQ_RING_BUFFER_EVIDENCE_HASH_MAX];
    char checksum[VANTAQ_RING_BUFFER_CHECKSUM_MAX];
};

struct vantaq_ring_buffer_append_result {
    ring_buffer_err_t status;
    uint64_t record_slot;
    uint64_t record_sequence;
};

struct vantaq_ring_buffer_read_result {
    ring_buffer_err_t status;
    struct vantaq_ring_buffer_record *record;
    uint64_t record_slot;
    uint64_t record_sequence;
};

static const char k_empty[] = "";

static bool copy_text_bounded(char *dst, size_t dst_size, const char *src) {
    size_t src_len;
    size_t copy_len;

    if (dst == NULL || src == NULL || dst_size == 0U) {
        return false;
    }

    src_len  = strlen(src);
    copy_len = src_len < (dst_size - 1U) ? src_len : (dst_size - 1U);
    dst[0]   = '\0';
    if (copy_len > 0U) {
        memcpy(dst, src, copy_len);
    }
    dst[copy_len] = '\0';

    return src_len < dst_size;
}

static bool text_is_valid(const char *value, size_t max_size) {
    size_t value_len;

    if (value == NULL || max_size == 0U) {
        return false;
    }

    value_len = strnlen(value, max_size);
    if (value_len == 0U || value_len >= max_size) {
        return false;
    }

    return true;
}

static ring_buffer_err_t validate_status_for_error_result(ring_buffer_err_t status) {
    switch (status) {
    case RING_BUFFER_INVALID_CONFIG:
    case RING_BUFFER_RECORD_TOO_LARGE:
    case RING_BUFFER_RECORD_NOT_FOUND:
    case RING_BUFFER_RECORD_CORRUPTED:
    case RING_BUFFER_IO_ERROR:
        return RING_BUFFER_OK;
    case RING_BUFFER_OK:
    default:
        break;
    }
    return RING_BUFFER_INVALID_CONFIG;
}

static ring_buffer_err_t clone_record(const struct vantaq_ring_buffer_record *source,
                                      struct vantaq_ring_buffer_record **out_record) {
    struct vantaq_ring_buffer_record *cloned = NULL;
    ring_buffer_err_t err                    = RING_BUFFER_IO_ERROR;

    if (source == NULL || out_record == NULL || source->evidence_json == NULL) {
        return RING_BUFFER_INVALID_CONFIG;
    }

    if (source->evidence_json_size >= VANTAQ_RING_BUFFER_MAX_RECORD_BYTES_LIMIT) {
        return RING_BUFFER_RECORD_TOO_LARGE;
    }

    *out_record = NULL;

    cloned = malloc(sizeof(struct vantaq_ring_buffer_record));
    if (cloned == NULL) {
        return RING_BUFFER_IO_ERROR;
    }

    VANTAQ_ZERO_STRUCT(*cloned);

    if (source->evidence_json_size > SIZE_MAX - 1U) {
        err = RING_BUFFER_RECORD_TOO_LARGE;
        goto cleanup;
    }

    cloned->evidence_json = malloc(source->evidence_json_size + 1U);
    if (cloned->evidence_json == NULL) {
        goto cleanup;
    }

    cloned->record_slot        = source->record_slot;
    cloned->record_sequence    = source->record_sequence;
    cloned->issued_at_unix     = source->issued_at_unix;
    cloned->evidence_json_size = source->evidence_json_size;

    if (!copy_text_bounded(cloned->evidence_id, sizeof(cloned->evidence_id), source->evidence_id) ||
        !copy_text_bounded(cloned->verifier_id, sizeof(cloned->verifier_id), source->verifier_id) ||
        !copy_text_bounded(cloned->evidence_hash, sizeof(cloned->evidence_hash),
                           source->evidence_hash) ||
        !copy_text_bounded(cloned->checksum, sizeof(cloned->checksum), source->checksum)) {
        err = RING_BUFFER_RECORD_CORRUPTED;
        goto cleanup;
    }

    memcpy(cloned->evidence_json, source->evidence_json, source->evidence_json_size);
    cloned->evidence_json[source->evidence_json_size] = '\0';

    *out_record = cloned;
    return RING_BUFFER_OK;

cleanup:
    vantaq_ring_buffer_record_destroy(cloned);
    return err;
}

ring_buffer_err_t vantaq_ring_buffer_config_create(const char *file_path, size_t max_records,
                                                   size_t max_record_bytes, bool fsync_on_append,
                                                   struct vantaq_ring_buffer_config **out_config) {
    struct vantaq_ring_buffer_config *created = NULL;

    if (out_config == NULL) {
        return RING_BUFFER_INVALID_CONFIG;
    }
    *out_config = NULL;

    if (!text_is_valid(file_path, VANTAQ_RING_BUFFER_FILE_PATH_MAX)) {
        return RING_BUFFER_INVALID_CONFIG;
    }
    if (max_records == 0U || max_record_bytes == 0U ||
        max_record_bytes > VANTAQ_RING_BUFFER_MAX_RECORD_BYTES_LIMIT) {
        return RING_BUFFER_INVALID_CONFIG;
    }

    created = malloc(sizeof(struct vantaq_ring_buffer_config));
    if (created == NULL) {
        return RING_BUFFER_IO_ERROR;
    }

    VANTAQ_ZERO_STRUCT(*created);
    copy_text_bounded(created->file_path, sizeof(created->file_path), file_path);
    created->max_records      = max_records;
    created->max_record_bytes = max_record_bytes;
    created->fsync_on_append  = fsync_on_append;

    *out_config = created;
    return RING_BUFFER_OK;
}

ring_buffer_err_t
vantaq_ring_buffer_config_validate(const struct vantaq_ring_buffer_config *config) {
    if (config == NULL) {
        return RING_BUFFER_INVALID_CONFIG;
    }
    if (!text_is_valid(config->file_path, sizeof(config->file_path))) {
        return RING_BUFFER_INVALID_CONFIG;
    }
    if (config->max_records == 0U || config->max_record_bytes == 0U ||
        config->max_record_bytes > VANTAQ_RING_BUFFER_MAX_RECORD_BYTES_LIMIT) {
        return RING_BUFFER_INVALID_CONFIG;
    }

    return RING_BUFFER_OK;
}

void vantaq_ring_buffer_config_destroy(struct vantaq_ring_buffer_config *config) {
    if (config != NULL) {
        vantaq_explicit_bzero(config, sizeof(*config));
        free(config);
    }
}

const char *
vantaq_ring_buffer_config_get_file_path(const struct vantaq_ring_buffer_config *config) {
    return config ? config->file_path : k_empty;
}

size_t vantaq_ring_buffer_config_get_max_records(const struct vantaq_ring_buffer_config *config) {
    return config ? config->max_records : 0U;
}

size_t
vantaq_ring_buffer_config_get_max_record_bytes(const struct vantaq_ring_buffer_config *config) {
    return config ? config->max_record_bytes : 0U;
}

bool vantaq_ring_buffer_config_get_fsync_on_append(const struct vantaq_ring_buffer_config *config) {
    return config ? config->fsync_on_append : false;
}

ring_buffer_err_t vantaq_ring_buffer_header_create(uint64_t next_slot, uint64_t next_sequence,
                                                   uint64_t active_records,
                                                   struct vantaq_ring_buffer_header **out_header) {
    struct vantaq_ring_buffer_header *created = NULL;

    if (out_header == NULL) {
        return RING_BUFFER_INVALID_CONFIG;
    }
    *out_header = NULL;

    created = malloc(sizeof(struct vantaq_ring_buffer_header));
    if (created == NULL) {
        return RING_BUFFER_IO_ERROR;
    }

    VANTAQ_ZERO_STRUCT(*created);
    created->next_slot      = next_slot;
    created->next_sequence  = next_sequence;
    created->active_records = active_records;

    *out_header = created;
    return RING_BUFFER_OK;
}

void vantaq_ring_buffer_header_destroy(struct vantaq_ring_buffer_header *header) {
    if (header != NULL) {
        vantaq_explicit_bzero(header, sizeof(*header));
        free(header);
    }
}

uint64_t vantaq_ring_buffer_header_get_next_slot(const struct vantaq_ring_buffer_header *header) {
    return header ? header->next_slot : 0U;
}

uint64_t
vantaq_ring_buffer_header_get_next_sequence(const struct vantaq_ring_buffer_header *header) {
    return header ? header->next_sequence : 0U;
}

uint64_t
vantaq_ring_buffer_header_get_active_records(const struct vantaq_ring_buffer_header *header) {
    return header ? header->active_records : 0U;
}

ring_buffer_err_t vantaq_ring_buffer_record_create(const struct vantaq_ring_buffer_config *config,
                                                   uint64_t record_slot, uint64_t record_sequence,
                                                   const char *evidence_id, const char *verifier_id,
                                                   int64_t issued_at_unix,
                                                   const char *evidence_json,
                                                   const char *evidence_hash, const char *checksum,
                                                   struct vantaq_ring_buffer_record **out_record) {
    struct vantaq_ring_buffer_record *created = NULL;
    size_t evidence_json_size;
    ring_buffer_err_t err = RING_BUFFER_IO_ERROR;

    if (out_record == NULL || vantaq_ring_buffer_config_validate(config) != RING_BUFFER_OK) {
        return RING_BUFFER_INVALID_CONFIG;
    }
    *out_record = NULL;

    if (!text_is_valid(evidence_id, VANTAQ_EVIDENCE_ID_MAX) ||
        !text_is_valid(verifier_id, VANTAQ_VERIFIER_ID_MAX) ||
        !text_is_valid(evidence_hash, VANTAQ_RING_BUFFER_EVIDENCE_HASH_MAX) ||
        !text_is_valid(checksum, VANTAQ_RING_BUFFER_CHECKSUM_MAX)) {
        return RING_BUFFER_INVALID_CONFIG;
    }

    evidence_json_size = evidence_json ? strlen(evidence_json) : 0U;
    if (evidence_json_size == 0U) {
        return RING_BUFFER_INVALID_CONFIG;
    }
    if (evidence_json_size > config->max_record_bytes) {
        return RING_BUFFER_RECORD_TOO_LARGE;
    }
    if (issued_at_unix <= 0) {
        return RING_BUFFER_INVALID_CONFIG;
    }

    created = malloc(sizeof(struct vantaq_ring_buffer_record));
    if (created == NULL) {
        return RING_BUFFER_IO_ERROR;
    }

    VANTAQ_ZERO_STRUCT(*created);

    if (evidence_json_size > SIZE_MAX - 1U) {
        err = RING_BUFFER_RECORD_TOO_LARGE;
        goto cleanup;
    }

    created->evidence_json = malloc(evidence_json_size + 1U);
    if (created->evidence_json == NULL) {
        goto cleanup;
    }

    created->record_slot        = record_slot;
    created->record_sequence    = record_sequence;
    created->issued_at_unix     = issued_at_unix;
    created->evidence_json_size = evidence_json_size;

    if (!copy_text_bounded(created->evidence_id, sizeof(created->evidence_id), evidence_id) ||
        !copy_text_bounded(created->verifier_id, sizeof(created->verifier_id), verifier_id) ||
        !copy_text_bounded(created->evidence_hash, sizeof(created->evidence_hash), evidence_hash) ||
        !copy_text_bounded(created->checksum, sizeof(created->checksum), checksum)) {
        err = RING_BUFFER_INVALID_CONFIG;
        goto cleanup;
    }

    memcpy(created->evidence_json, evidence_json, evidence_json_size);
    created->evidence_json[evidence_json_size] = '\0';

    *out_record = created;
    return RING_BUFFER_OK;

cleanup:
    vantaq_ring_buffer_record_destroy(created);
    return err;
}

void vantaq_ring_buffer_record_destroy(struct vantaq_ring_buffer_record *record) {
    if (record == NULL) {
        return;
    }

    if (record->evidence_json != NULL) {
        vantaq_explicit_bzero(record->evidence_json, record->evidence_json_size + 1U);
        free(record->evidence_json);
        record->evidence_json = NULL;
    }
    vantaq_explicit_bzero(record, sizeof(*record));
    free(record);
}

uint64_t vantaq_ring_buffer_record_get_record_slot(const struct vantaq_ring_buffer_record *record) {
    return record ? record->record_slot : 0U;
}

uint64_t
vantaq_ring_buffer_record_get_record_sequence(const struct vantaq_ring_buffer_record *record) {
    return record ? record->record_sequence : 0U;
}

const char *
vantaq_ring_buffer_record_get_evidence_id(const struct vantaq_ring_buffer_record *record) {
    return record ? record->evidence_id : k_empty;
}

const char *
vantaq_ring_buffer_record_get_verifier_id(const struct vantaq_ring_buffer_record *record) {
    return record ? record->verifier_id : k_empty;
}

int64_t
vantaq_ring_buffer_record_get_issued_at_unix(const struct vantaq_ring_buffer_record *record) {
    return record ? record->issued_at_unix : -1;
}

const char *
vantaq_ring_buffer_record_get_evidence_json(const struct vantaq_ring_buffer_record *record) {
    return (record && record->evidence_json) ? record->evidence_json : k_empty;
}

size_t
vantaq_ring_buffer_record_get_evidence_json_size(const struct vantaq_ring_buffer_record *record) {
    return record ? record->evidence_json_size : 0U;
}

const char *
vantaq_ring_buffer_record_get_evidence_hash(const struct vantaq_ring_buffer_record *record) {
    return record ? record->evidence_hash : k_empty;
}

const char *vantaq_ring_buffer_record_get_checksum(const struct vantaq_ring_buffer_record *record) {
    return record ? record->checksum : k_empty;
}

ring_buffer_err_t vantaq_ring_buffer_append_result_create_success(
    uint64_t record_slot, uint64_t record_sequence,
    struct vantaq_ring_buffer_append_result **out_result) {
    struct vantaq_ring_buffer_append_result *created = NULL;

    if (out_result == NULL) {
        return RING_BUFFER_INVALID_CONFIG;
    }
    *out_result = NULL;

    created = malloc(sizeof(struct vantaq_ring_buffer_append_result));
    if (created == NULL) {
        return RING_BUFFER_IO_ERROR;
    }

    VANTAQ_ZERO_STRUCT(*created);
    created->status          = RING_BUFFER_OK;
    created->record_slot     = record_slot;
    created->record_sequence = record_sequence;

    *out_result = created;
    return RING_BUFFER_OK;
}

ring_buffer_err_t vantaq_ring_buffer_append_result_create_error(
    ring_buffer_err_t status, struct vantaq_ring_buffer_append_result **out_result) {
    struct vantaq_ring_buffer_append_result *created = NULL;

    if (out_result == NULL) {
        return RING_BUFFER_INVALID_CONFIG;
    }
    *out_result = NULL;

    if (validate_status_for_error_result(status) != RING_BUFFER_OK) {
        return RING_BUFFER_INVALID_CONFIG;
    }

    created = malloc(sizeof(struct vantaq_ring_buffer_append_result));
    if (created == NULL) {
        return RING_BUFFER_IO_ERROR;
    }

    VANTAQ_ZERO_STRUCT(*created);
    created->status          = status;
    created->record_slot     = VANTAQ_RING_BUFFER_INVALID_SLOT;
    created->record_sequence = VANTAQ_RING_BUFFER_INVALID_SEQUENCE;

    *out_result = created;
    return RING_BUFFER_OK;
}

void vantaq_ring_buffer_append_result_destroy(struct vantaq_ring_buffer_append_result *result) {
    if (result != NULL) {
        vantaq_explicit_bzero(result, sizeof(*result));
        free(result);
    }
}

ring_buffer_err_t
vantaq_ring_buffer_append_result_get_status(const struct vantaq_ring_buffer_append_result *result) {
    return result ? result->status : RING_BUFFER_IO_ERROR;
}

uint64_t vantaq_ring_buffer_append_result_get_record_slot(
    const struct vantaq_ring_buffer_append_result *result) {
    return result ? result->record_slot : 0U;
}

uint64_t vantaq_ring_buffer_append_result_get_record_sequence(
    const struct vantaq_ring_buffer_append_result *result) {
    return result ? result->record_sequence : 0U;
}

ring_buffer_err_t
vantaq_ring_buffer_read_result_create_found(const struct vantaq_ring_buffer_record *record,
                                            struct vantaq_ring_buffer_read_result **out_result) {
    struct vantaq_ring_buffer_read_result *created = NULL;
    ring_buffer_err_t err                          = RING_BUFFER_OK;

    if (record == NULL || out_result == NULL) {
        return RING_BUFFER_INVALID_CONFIG;
    }
    *out_result = NULL;

    created = malloc(sizeof(struct vantaq_ring_buffer_read_result));
    if (created == NULL) {
        return RING_BUFFER_IO_ERROR;
    }

    VANTAQ_ZERO_STRUCT(*created);

    err = clone_record(record, &created->record);
    if (err != RING_BUFFER_OK) {
        vantaq_explicit_bzero(created, sizeof(*created));
        free(created);
        return err;
    }

    created->status          = RING_BUFFER_OK;
    created->record_slot     = created->record->record_slot;
    created->record_sequence = created->record->record_sequence;

    *out_result = created;
    return RING_BUFFER_OK;
}

ring_buffer_err_t vantaq_ring_buffer_read_result_create_not_found(
    struct vantaq_ring_buffer_read_result **out_result) {
    return vantaq_ring_buffer_read_result_create_error(RING_BUFFER_RECORD_NOT_FOUND, out_result);
}

ring_buffer_err_t vantaq_ring_buffer_read_result_create_corrupted(
    uint64_t record_slot, uint64_t record_sequence,
    struct vantaq_ring_buffer_read_result **out_result) {
    struct vantaq_ring_buffer_read_result *created = NULL;

    if (out_result == NULL) {
        return RING_BUFFER_INVALID_CONFIG;
    }
    *out_result = NULL;

    created = malloc(sizeof(struct vantaq_ring_buffer_read_result));
    if (created == NULL) {
        return RING_BUFFER_IO_ERROR;
    }

    VANTAQ_ZERO_STRUCT(*created);
    created->status          = RING_BUFFER_RECORD_CORRUPTED;
    created->record_slot     = record_slot;
    created->record_sequence = record_sequence;

    *out_result = created;
    return RING_BUFFER_OK;
}

ring_buffer_err_t
vantaq_ring_buffer_read_result_create_error(ring_buffer_err_t status,
                                            struct vantaq_ring_buffer_read_result **out_result) {
    struct vantaq_ring_buffer_read_result *created = NULL;

    if (out_result == NULL) {
        return RING_BUFFER_INVALID_CONFIG;
    }
    *out_result = NULL;

    if (validate_status_for_error_result(status) != RING_BUFFER_OK) {
        return RING_BUFFER_INVALID_CONFIG;
    }

    created = malloc(sizeof(struct vantaq_ring_buffer_read_result));
    if (created == NULL) {
        return RING_BUFFER_IO_ERROR;
    }

    VANTAQ_ZERO_STRUCT(*created);
    created->status          = status;
    created->record_slot     = VANTAQ_RING_BUFFER_INVALID_SLOT;
    created->record_sequence = VANTAQ_RING_BUFFER_INVALID_SEQUENCE;

    *out_result = created;
    return RING_BUFFER_OK;
}

void vantaq_ring_buffer_read_result_destroy(struct vantaq_ring_buffer_read_result *result) {
    if (result == NULL) {
        return;
    }

    if (result->record != NULL) {
        vantaq_ring_buffer_record_destroy(result->record);
        result->record = NULL;
    }

    vantaq_explicit_bzero(result, sizeof(*result));
    free(result);
}

ring_buffer_err_t
vantaq_ring_buffer_read_result_get_status(const struct vantaq_ring_buffer_read_result *result) {
    return result ? result->status : RING_BUFFER_IO_ERROR;
}

const struct vantaq_ring_buffer_record *
vantaq_ring_buffer_read_result_get_record(const struct vantaq_ring_buffer_read_result *result) {
    return result ? result->record : NULL;
}

uint64_t vantaq_ring_buffer_read_result_get_record_slot(
    const struct vantaq_ring_buffer_read_result *result) {
    return result ? result->record_slot : 0U;
}

uint64_t vantaq_ring_buffer_read_result_get_record_sequence(
    const struct vantaq_ring_buffer_read_result *result) {
    return result ? result->record_sequence : 0U;
}
