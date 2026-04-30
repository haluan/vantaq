// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "evidence_ring_buffer.h"

#include "evidence_ring_format.h"
#include "infrastructure/memory/zero_struct.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define VANTAQ_EVIDENCE_RING_LAST_ERROR_MAX 256U

struct vantaq_evidence_ring_buffer {
    int fd;
    char path[VANTAQ_RING_BUFFER_FILE_PATH_MAX];
    size_t max_records;
    size_t max_record_bytes;
    size_t slot_size;
    size_t file_size;
    bool fsync_on_append;
    bool mutex_initialized;
    pthread_mutex_t mutex;
    char last_error[VANTAQ_EVIDENCE_RING_LAST_ERROR_MAX];
};

struct vantaq_ring_header_state {
    uint8_t raw[VANTAQ_EVIDENCE_RING_HEADER_SIZE];
    uint32_t write_slot;
    uint64_t next_sequence;
};

struct vantaq_ring_slot_candidate {
    uint32_t record_slot;
    uint64_t record_sequence;
};

static void set_error(struct vantaq_evidence_ring_buffer *buffer, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void set_error(struct vantaq_evidence_ring_buffer *buffer, const char *fmt, ...) {
    va_list args;

    if (buffer == NULL || fmt == NULL) {
        return;
    }

    va_start(args, fmt);
    (void)vsnprintf(buffer->last_error, sizeof(buffer->last_error), fmt, args);
    va_end(args);
}

static enum vantaq_evidence_ring_open_status
compute_file_size(size_t header_size, size_t max_records, size_t slot_size, size_t *out_size) {
    if (out_size == NULL) {
        return VANTAQ_EVIDENCE_RING_OPEN_INVALID_ARGUMENT;
    }
    if (max_records == 0U) {
        return VANTAQ_EVIDENCE_RING_OPEN_INVALID_ARGUMENT;
    }
    if (slot_size > ((SIZE_MAX - header_size) / max_records)) {
        return VANTAQ_EVIDENCE_RING_OPEN_INVALID_ARGUMENT;
    }

    *out_size = header_size + (max_records * slot_size);
    return VANTAQ_EVIDENCE_RING_OPEN_OK;
}

static enum vantaq_evidence_ring_open_status ensure_parent_dirs(const char *path) {
    char *path_copy = NULL;
    char *cursor    = NULL;

    if (path == NULL || path[0] == '\0') {
        return VANTAQ_EVIDENCE_RING_OPEN_INVALID_ARGUMENT;
    }

    path_copy = strdup(path);
    if (path_copy == NULL) {
        return VANTAQ_EVIDENCE_RING_OPEN_OUT_OF_MEMORY;
    }

    cursor = strrchr(path_copy, '/');
    if (cursor == NULL) {
        free(path_copy);
        return VANTAQ_EVIDENCE_RING_OPEN_OK;
    }
    if (cursor == path_copy) {
        free(path_copy);
        return VANTAQ_EVIDENCE_RING_OPEN_OK;
    }

    *cursor = '\0';

    for (cursor = path_copy + 1; *cursor != '\0'; cursor++) {
        if (*cursor != '/') {
            continue;
        }

        *cursor = '\0';
        if (mkdir(path_copy, 0700) != 0 && errno != EEXIST) {
            free(path_copy);
            return VANTAQ_EVIDENCE_RING_OPEN_FAILED;
        }
        *cursor = '/';
    }

    if (mkdir(path_copy, 0700) != 0 && errno != EEXIST) {
        free(path_copy);
        return VANTAQ_EVIDENCE_RING_OPEN_FAILED;
    }

    free(path_copy);
    return VANTAQ_EVIDENCE_RING_OPEN_OK;
}

static enum vantaq_evidence_ring_open_status write_all(int fd, const uint8_t *buf, size_t len) {
    size_t written = 0U;

    if (fd < 0 || buf == NULL) {
        return VANTAQ_EVIDENCE_RING_OPEN_INVALID_ARGUMENT;
    }

    while (written < len) {
        ssize_t rc = write(fd, buf + written, len - written);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return VANTAQ_EVIDENCE_RING_OPEN_IO_ERROR;
        }
        written += (size_t)rc;
    }

    return VANTAQ_EVIDENCE_RING_OPEN_OK;
}

static enum vantaq_evidence_ring_open_status read_all(int fd, uint8_t *buf, size_t len) {
    size_t consumed = 0U;

    if (fd < 0 || buf == NULL) {
        return VANTAQ_EVIDENCE_RING_OPEN_INVALID_ARGUMENT;
    }

    while (consumed < len) {
        ssize_t rc = read(fd, buf + consumed, len - consumed);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return VANTAQ_EVIDENCE_RING_OPEN_IO_ERROR;
        }
        if (rc == 0) {
            return VANTAQ_EVIDENCE_RING_OPEN_INVALID_HEADER;
        }
        consumed += (size_t)rc;
    }

    return VANTAQ_EVIDENCE_RING_OPEN_OK;
}

static enum vantaq_evidence_ring_open_status
read_validated_header(struct vantaq_evidence_ring_buffer *buffer,
                      struct vantaq_ring_header_state *out_state) {
    struct stat st;
    uint32_t version;
    uint32_t persisted_header_size;
    uint32_t persisted_slot_size;
    uint32_t persisted_max_records;
    uint32_t persisted_max_record_bytes;
    size_t persisted_file_size = 0U;
    uint64_t next_sequence;
    enum vantaq_evidence_ring_open_status status;
    const size_t header_size = vantaq_evidence_ring_header_size_bytes();

    if (buffer == NULL || out_state == NULL) {
        return VANTAQ_EVIDENCE_RING_OPEN_INVALID_ARGUMENT;
    }

    if (fstat(buffer->fd, &st) != 0) {
        set_error(buffer, "fstat failed: %s", strerror(errno));
        return VANTAQ_EVIDENCE_RING_OPEN_IO_ERROR;
    }

    if (!S_ISREG(st.st_mode)) {
        set_error(buffer, "path is not a regular file");
        return VANTAQ_EVIDENCE_RING_OPEN_FAILED;
    }

    if ((size_t)st.st_size < header_size) {
        set_error(buffer, "file size mismatch");
        return VANTAQ_EVIDENCE_RING_OPEN_INVALID_HEADER;
    }

    if (lseek(buffer->fd, 0, SEEK_SET) < 0) {
        set_error(buffer, "lseek failed: %s", strerror(errno));
        return VANTAQ_EVIDENCE_RING_OPEN_IO_ERROR;
    }

    status = read_all(buffer->fd, out_state->raw, sizeof(out_state->raw));
    if (status != VANTAQ_EVIDENCE_RING_OPEN_OK) {
        set_error(buffer, "header read failed");
        return status;
    }

    if (memcmp(out_state->raw + VANTAQ_EVIDENCE_RING_HEADER_MAGIC_OFFSET,
               VANTAQ_EVIDENCE_RING_MAGIC, VANTAQ_EVIDENCE_RING_MAGIC_SIZE) != 0) {
        set_error(buffer, "invalid magic");
        return VANTAQ_EVIDENCE_RING_OPEN_INVALID_HEADER;
    }

    version = vantaq_evidence_ring_le32_decode(out_state->raw +
                                               VANTAQ_EVIDENCE_RING_HEADER_VERSION_OFFSET);
    if (version != VANTAQ_EVIDENCE_RING_FORMAT_VERSION) {
        set_error(buffer, "invalid version: %u", version);
        return VANTAQ_EVIDENCE_RING_OPEN_INVALID_HEADER;
    }

    persisted_header_size = vantaq_evidence_ring_le32_decode(
        out_state->raw + VANTAQ_EVIDENCE_RING_HEADER_HEADER_SIZE_OFFSET);
    persisted_slot_size = vantaq_evidence_ring_le32_decode(
        out_state->raw + VANTAQ_EVIDENCE_RING_HEADER_SLOT_SIZE_OFFSET);
    persisted_max_records = vantaq_evidence_ring_le32_decode(
        out_state->raw + VANTAQ_EVIDENCE_RING_HEADER_MAX_RECORDS_OFFSET);
    persisted_max_record_bytes = vantaq_evidence_ring_le32_decode(
        out_state->raw + VANTAQ_EVIDENCE_RING_HEADER_MAX_RECORD_BYTES_OFFSET);

    out_state->write_slot = vantaq_evidence_ring_le32_decode(
        out_state->raw + VANTAQ_EVIDENCE_RING_HEADER_WRITE_SLOT_OFFSET);
    next_sequence = vantaq_evidence_ring_le64_decode(
        out_state->raw + VANTAQ_EVIDENCE_RING_HEADER_NEXT_SEQUENCE_OFFSET);
    out_state->next_sequence = next_sequence;

    if (persisted_header_size != (uint32_t)header_size || persisted_slot_size == 0U ||
        persisted_max_records == 0U || persisted_max_record_bytes == 0U) {
        set_error(buffer, "invalid persisted layout sizes");
        return VANTAQ_EVIDENCE_RING_OPEN_INVALID_HEADER;
    }

    status = compute_file_size((size_t)persisted_header_size, (size_t)persisted_max_records,
                               (size_t)persisted_slot_size, &persisted_file_size);
    if (status != VANTAQ_EVIDENCE_RING_OPEN_OK || (size_t)st.st_size != persisted_file_size) {
        set_error(buffer, "file size mismatch");
        return VANTAQ_EVIDENCE_RING_OPEN_INVALID_HEADER;
    }

    if (persisted_max_records != (uint32_t)buffer->max_records ||
        persisted_max_record_bytes != (uint32_t)buffer->max_record_bytes) {
        set_error(buffer, "config mismatch");
        return VANTAQ_EVIDENCE_RING_OPEN_CONFIG_MISMATCH;
    }

    if (persisted_slot_size != (uint32_t)buffer->slot_size) {
        set_error(buffer, "invalid persisted layout sizes");
        return VANTAQ_EVIDENCE_RING_OPEN_INVALID_HEADER;
    }

    if (out_state->write_slot >= buffer->max_records) {
        set_error(buffer, "write_slot out of range");
        return VANTAQ_EVIDENCE_RING_OPEN_INVALID_HEADER;
    }

    if (out_state->next_sequence < 1U) {
        set_error(buffer, "next_sequence invalid");
        return VANTAQ_EVIDENCE_RING_OPEN_INVALID_HEADER;
    }

    return VANTAQ_EVIDENCE_RING_OPEN_OK;
}

static void copy_bounded_field(uint8_t *dst, size_t dst_size, const char *src) {
    size_t copy_len;

    if (dst == NULL || dst_size == 0U || src == NULL) {
        return;
    }

    copy_len = strnlen(src, dst_size - 1U);
    if (copy_len > 0U) {
        memcpy(dst, src, copy_len);
    }
}

static enum vantaq_evidence_ring_append_status
map_open_status_to_append(enum vantaq_evidence_ring_open_status status) {
    switch (status) {
    case VANTAQ_EVIDENCE_RING_OPEN_INVALID_ARGUMENT:
        return VANTAQ_EVIDENCE_RING_APPEND_INVALID_ARGUMENT;
    case VANTAQ_EVIDENCE_RING_OPEN_OK:
        return VANTAQ_EVIDENCE_RING_APPEND_OK;
    case VANTAQ_EVIDENCE_RING_OPEN_OUT_OF_MEMORY:
    case VANTAQ_EVIDENCE_RING_OPEN_FAILED:
    case VANTAQ_EVIDENCE_RING_OPEN_IO_ERROR:
    case VANTAQ_EVIDENCE_RING_OPEN_INVALID_HEADER:
    case VANTAQ_EVIDENCE_RING_OPEN_CONFIG_MISMATCH:
    default:
        return VANTAQ_EVIDENCE_RING_APPEND_IO_ERROR;
    }
}

static enum vantaq_evidence_ring_read_status
map_open_status_to_read(enum vantaq_evidence_ring_open_status status) {
    switch (status) {
    case VANTAQ_EVIDENCE_RING_OPEN_OK:
        return VANTAQ_EVIDENCE_RING_READ_OK;
    case VANTAQ_EVIDENCE_RING_OPEN_INVALID_ARGUMENT:
        return VANTAQ_EVIDENCE_RING_READ_INVALID_ARGUMENT;
    case VANTAQ_EVIDENCE_RING_OPEN_OUT_OF_MEMORY:
        return VANTAQ_EVIDENCE_RING_READ_OUT_OF_MEMORY;
    case VANTAQ_EVIDENCE_RING_OPEN_INVALID_HEADER:
    case VANTAQ_EVIDENCE_RING_OPEN_CONFIG_MISMATCH:
        return VANTAQ_EVIDENCE_RING_READ_INVALID_HEADER;
    case VANTAQ_EVIDENCE_RING_OPEN_FAILED:
    case VANTAQ_EVIDENCE_RING_OPEN_IO_ERROR:
    default:
        return VANTAQ_EVIDENCE_RING_READ_IO_ERROR;
    }
}

static enum vantaq_evidence_ring_read_status map_domain_status_to_read(ring_buffer_err_t status) {
    switch (status) {
    case RING_BUFFER_OK:
        return VANTAQ_EVIDENCE_RING_READ_OK;
    case RING_BUFFER_IO_ERROR:
        return VANTAQ_EVIDENCE_RING_READ_OUT_OF_MEMORY;
    case RING_BUFFER_INVALID_CONFIG:
    case RING_BUFFER_RECORD_TOO_LARGE:
    case RING_BUFFER_RECORD_NOT_FOUND:
    case RING_BUFFER_RECORD_CORRUPTED:
    default:
        return VANTAQ_EVIDENCE_RING_READ_IO_ERROR;
    }
}

static enum vantaq_evidence_ring_open_status read_at_exact(int fd, off_t offset, uint8_t *buf,
                                                           size_t len) {
    size_t consumed = 0U;

    if (fd < 0 || buf == NULL) {
        return VANTAQ_EVIDENCE_RING_OPEN_INVALID_ARGUMENT;
    }

    while (consumed < len) {
        ssize_t rc = pread(fd, buf + consumed, len - consumed, offset + (off_t)consumed);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return VANTAQ_EVIDENCE_RING_OPEN_IO_ERROR;
        }
        if (rc == 0) {
            return VANTAQ_EVIDENCE_RING_OPEN_INVALID_HEADER;
        }
        consumed += (size_t)rc;
    }

    return VANTAQ_EVIDENCE_RING_OPEN_OK;
}

static bool ring_text_field_is_valid(const uint8_t *field, size_t field_size) {
    size_t len;

    if (field == NULL || field_size == 0U) {
        return false;
    }

    len = strnlen((const char *)field, field_size);
    if (len == 0U || len >= field_size) {
        return false;
    }

    return true;
}

static bool input_text_is_valid(const char *value, size_t max_size) {
    size_t len;

    if (value == NULL || max_size == 0U) {
        return false;
    }

    len = strnlen(value, max_size);
    if (len == 0U || len >= max_size) {
        return false;
    }

    return true;
}

static void ring_copy_text_field(char *dst, size_t dst_size, const uint8_t *src, size_t src_size) {
    size_t len;

    if (dst == NULL || src == NULL || dst_size == 0U || src_size == 0U) {
        return;
    }

    len = strnlen((const char *)src, src_size);
    if (len >= dst_size) {
        len = dst_size - 1U;
    }

    if (len > 0U) {
        memcpy(dst, src, len);
    }
    dst[len] = '\0';
}

static bool parse_slot_candidate(const struct vantaq_evidence_ring_buffer *buffer,
                                 size_t slot_index, const uint8_t *slot_buf,
                                 struct vantaq_ring_slot_candidate *out_candidate) {
    uint32_t record_slot;
    uint64_t record_sequence;
    uint64_t issued_at_raw;
    uint32_t evidence_json_len;

    if (buffer == NULL || slot_buf == NULL || out_candidate == NULL) {
        return false;
    }

    record_slot =
        vantaq_evidence_ring_le32_decode(slot_buf + VANTAQ_EVIDENCE_RING_RECORD_SLOT_OFFSET);
    if (record_slot != slot_index || record_slot >= buffer->max_records) {
        return false;
    }

    record_sequence =
        vantaq_evidence_ring_le64_decode(slot_buf + VANTAQ_EVIDENCE_RING_RECORD_SEQUENCE_OFFSET);
    if (record_sequence < 1U) {
        return false;
    }

    issued_at_raw = vantaq_evidence_ring_le64_decode(
        slot_buf + VANTAQ_EVIDENCE_RING_RECORD_ISSUED_AT_UNIX_OFFSET);
    if (issued_at_raw == 0U || issued_at_raw > (uint64_t)INT64_MAX) {
        return false;
    }

    evidence_json_len = vantaq_evidence_ring_le32_decode(
        slot_buf + VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_JSON_LEN_OFFSET);
    if (evidence_json_len == 0U || evidence_json_len > buffer->max_record_bytes) {
        return false;
    }

    if (!ring_text_field_is_valid(slot_buf + VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_ID_OFFSET,
                                  VANTAQ_EVIDENCE_ID_MAX) ||
        !ring_text_field_is_valid(slot_buf + VANTAQ_EVIDENCE_RING_RECORD_VERIFIER_ID_OFFSET,
                                  VANTAQ_VERIFIER_ID_MAX) ||
        !ring_text_field_is_valid(slot_buf + VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_HASH_OFFSET,
                                  VANTAQ_RING_BUFFER_EVIDENCE_HASH_MAX) ||
        !ring_text_field_is_valid(slot_buf + VANTAQ_EVIDENCE_RING_RECORD_CHECKSUM_OFFSET,
                                  VANTAQ_RING_BUFFER_CHECKSUM_MAX)) {
        return false;
    }

    out_candidate->record_slot     = record_slot;
    out_candidate->record_sequence = record_sequence;
    return true;
}

static enum vantaq_evidence_ring_open_status
init_new_file(struct vantaq_evidence_ring_buffer *buffer, size_t header_size, size_t slot_size,
              size_t total_file_size) {
    uint8_t header[VANTAQ_EVIDENCE_RING_HEADER_SIZE];
    uint8_t tmp32[VANTAQ_EVIDENCE_RING_U32_SIZE];
    uint8_t tmp64[VANTAQ_EVIDENCE_RING_U64_SIZE];

    if (buffer == NULL) {
        return VANTAQ_EVIDENCE_RING_OPEN_INVALID_ARGUMENT;
    }

    VANTAQ_ZERO_STRUCT(header);

    memcpy(header + VANTAQ_EVIDENCE_RING_HEADER_MAGIC_OFFSET, VANTAQ_EVIDENCE_RING_MAGIC,
           VANTAQ_EVIDENCE_RING_MAGIC_SIZE);

    vantaq_evidence_ring_le32_encode(tmp32, VANTAQ_EVIDENCE_RING_FORMAT_VERSION);
    memcpy(header + VANTAQ_EVIDENCE_RING_HEADER_VERSION_OFFSET, tmp32, sizeof(tmp32));

    vantaq_evidence_ring_le32_encode(tmp32, (uint32_t)header_size);
    memcpy(header + VANTAQ_EVIDENCE_RING_HEADER_HEADER_SIZE_OFFSET, tmp32, sizeof(tmp32));

    vantaq_evidence_ring_le32_encode(tmp32, (uint32_t)slot_size);
    memcpy(header + VANTAQ_EVIDENCE_RING_HEADER_SLOT_SIZE_OFFSET, tmp32, sizeof(tmp32));

    vantaq_evidence_ring_le32_encode(tmp32, (uint32_t)buffer->max_records);
    memcpy(header + VANTAQ_EVIDENCE_RING_HEADER_MAX_RECORDS_OFFSET, tmp32, sizeof(tmp32));

    vantaq_evidence_ring_le32_encode(tmp32, (uint32_t)buffer->max_record_bytes);
    memcpy(header + VANTAQ_EVIDENCE_RING_HEADER_MAX_RECORD_BYTES_OFFSET, tmp32, sizeof(tmp32));

    vantaq_evidence_ring_le32_encode(tmp32, 0U);
    memcpy(header + VANTAQ_EVIDENCE_RING_HEADER_WRITE_SLOT_OFFSET, tmp32, sizeof(tmp32));

    vantaq_evidence_ring_le64_encode(tmp64, 1U);
    memcpy(header + VANTAQ_EVIDENCE_RING_HEADER_NEXT_SEQUENCE_OFFSET, tmp64, sizeof(tmp64));

    if (lseek(buffer->fd, 0, SEEK_SET) < 0) {
        set_error(buffer, "lseek failed: %s", strerror(errno));
        return VANTAQ_EVIDENCE_RING_OPEN_IO_ERROR;
    }

    if (write_all(buffer->fd, header, sizeof(header)) != VANTAQ_EVIDENCE_RING_OPEN_OK) {
        set_error(buffer, "header write failed");
        return VANTAQ_EVIDENCE_RING_OPEN_IO_ERROR;
    }

    if (ftruncate(buffer->fd, (off_t)total_file_size) != 0) {
        set_error(buffer, "ftruncate failed: %s", strerror(errno));
        return VANTAQ_EVIDENCE_RING_OPEN_IO_ERROR;
    }

    return VANTAQ_EVIDENCE_RING_OPEN_OK;
}

static enum vantaq_evidence_ring_open_status
validate_existing_header(struct vantaq_evidence_ring_buffer *buffer, const struct stat *st,
                         size_t header_size, size_t slot_size, size_t total_file_size) {
    struct vantaq_ring_header_state state;
    (void)st;
    (void)header_size;
    (void)slot_size;
    (void)total_file_size;

    return read_validated_header(buffer, &state);
}

enum vantaq_evidence_ring_open_status
vantaq_evidence_ring_buffer_open(const struct vantaq_ring_buffer_config *config,
                                 struct vantaq_evidence_ring_buffer **out_buffer) {
    struct vantaq_evidence_ring_buffer *buffer   = NULL;
    enum vantaq_evidence_ring_open_status status = VANTAQ_EVIDENCE_RING_OPEN_OK;
    const char *path;
    size_t header_size;
    size_t slot_size;
    size_t total_file_size;
    struct stat st;

    if (out_buffer == NULL) {
        return VANTAQ_EVIDENCE_RING_OPEN_INVALID_ARGUMENT;
    }
    *out_buffer = NULL;

    if (config == NULL || vantaq_ring_buffer_config_validate(config) != RING_BUFFER_OK) {
        return VANTAQ_EVIDENCE_RING_OPEN_INVALID_ARGUMENT;
    }

    path = vantaq_ring_buffer_config_get_file_path(config);
    if (path == NULL || path[0] == '\0') {
        return VANTAQ_EVIDENCE_RING_OPEN_INVALID_ARGUMENT;
    }

    buffer = calloc(1, sizeof(*buffer));
    if (buffer == NULL) {
        return VANTAQ_EVIDENCE_RING_OPEN_OUT_OF_MEMORY;
    }
    buffer->fd = -1;

    if (pthread_mutex_init(&buffer->mutex, NULL) != 0) {
        free(buffer);
        return VANTAQ_EVIDENCE_RING_OPEN_OUT_OF_MEMORY;
    }
    buffer->mutex_initialized = true;

    buffer->max_records      = vantaq_ring_buffer_config_get_max_records(config);
    buffer->max_record_bytes = vantaq_ring_buffer_config_get_max_record_bytes(config);
    buffer->fsync_on_append  = vantaq_ring_buffer_config_get_fsync_on_append(config);

    if (strlen(path) >= sizeof(buffer->path)) {
        status = VANTAQ_EVIDENCE_RING_OPEN_INVALID_ARGUMENT;
        goto cleanup;
    }
    memcpy(buffer->path, path, strlen(path) + 1U);

    header_size = vantaq_evidence_ring_header_size_bytes();
    slot_size   = vantaq_evidence_ring_record_slot_size_bytes(buffer->max_record_bytes);
    if (slot_size > UINT32_MAX || header_size > UINT32_MAX || buffer->max_records > UINT32_MAX ||
        buffer->max_record_bytes > UINT32_MAX) {
        status = VANTAQ_EVIDENCE_RING_OPEN_INVALID_ARGUMENT;
        goto cleanup;
    }

    status = compute_file_size(header_size, buffer->max_records, slot_size, &total_file_size);
    if (status != VANTAQ_EVIDENCE_RING_OPEN_OK) {
        goto cleanup;
    }

    buffer->slot_size = slot_size;
    buffer->file_size = total_file_size;

    status = ensure_parent_dirs(buffer->path);
    if (status != VANTAQ_EVIDENCE_RING_OPEN_OK) {
        set_error(buffer, "failed to ensure parent dirs for %s", buffer->path);
        goto cleanup;
    }

    buffer->fd = open(buffer->path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (buffer->fd < 0) {
        set_error(buffer, "open failed for %s: %s", buffer->path, strerror(errno));
        status = VANTAQ_EVIDENCE_RING_OPEN_FAILED;
        goto cleanup;
    }

    if (fstat(buffer->fd, &st) != 0) {
        set_error(buffer, "fstat failed: %s", strerror(errno));
        status = VANTAQ_EVIDENCE_RING_OPEN_IO_ERROR;
        goto cleanup;
    }

    if (!S_ISREG(st.st_mode)) {
        set_error(buffer, "path is not a regular file");
        status = VANTAQ_EVIDENCE_RING_OPEN_FAILED;
        goto cleanup;
    }

    if (st.st_size == 0) {
        status = init_new_file(buffer, header_size, slot_size, total_file_size);
        if (status != VANTAQ_EVIDENCE_RING_OPEN_OK) {
            goto cleanup;
        }
    } else {
        status = validate_existing_header(buffer, &st, header_size, slot_size, total_file_size);
        if (status != VANTAQ_EVIDENCE_RING_OPEN_OK) {
            goto cleanup;
        }
    }

    *out_buffer = buffer;
    return VANTAQ_EVIDENCE_RING_OPEN_OK;

cleanup:
    if (buffer != NULL) {
        if (buffer->fd >= 0) {
            (void)close(buffer->fd);
            buffer->fd = -1;
        }
        if (buffer->mutex_initialized) {
            (void)pthread_mutex_destroy(&buffer->mutex);
            buffer->mutex_initialized = false;
        }
        vantaq_explicit_bzero(buffer, sizeof(*buffer));
        free(buffer);
    }
    return status;
}

void vantaq_evidence_ring_buffer_destroy(struct vantaq_evidence_ring_buffer *buffer) {
    if (buffer == NULL) {
        return;
    }

    if (buffer->fd >= 0) {
        (void)close(buffer->fd);
        buffer->fd = -1;
    }

    if (buffer->mutex_initialized) {
        (void)pthread_mutex_destroy(&buffer->mutex);
        buffer->mutex_initialized = false;
    }

    vantaq_explicit_bzero(buffer, sizeof(*buffer));
    free(buffer);
}

enum vantaq_evidence_ring_append_status
vantaq_evidence_ring_buffer_append(struct vantaq_evidence_ring_buffer *buffer,
                                   const struct vantaq_ring_buffer_record *record,
                                   struct vantaq_ring_buffer_append_result **out_result) {
    enum vantaq_evidence_ring_append_status append_status = VANTAQ_EVIDENCE_RING_APPEND_OK;
    enum vantaq_evidence_ring_open_status open_status     = VANTAQ_EVIDENCE_RING_OPEN_OK;
    struct vantaq_ring_header_state header_state;
    uint8_t *slot_buf = NULL;
    uint8_t tmp32[VANTAQ_EVIDENCE_RING_U32_SIZE];
    uint8_t tmp64[VANTAQ_EVIDENCE_RING_U64_SIZE];
    uint32_t assigned_slot;
    uint64_t assigned_sequence;
    uint32_t next_write_slot;
    int lock_rc;
    bool lock_held = false;
    const char *evidence_id;
    const char *verifier_id;
    const char *evidence_json;
    const char *evidence_hash;
    const char *checksum;
    int64_t issued_at_unix;
    size_t evidence_json_size;
    size_t slot_offset;

    if (out_result == NULL) {
        return VANTAQ_EVIDENCE_RING_APPEND_INVALID_ARGUMENT;
    }
    *out_result = NULL;

    if (buffer == NULL || record == NULL) {
        return VANTAQ_EVIDENCE_RING_APPEND_INVALID_ARGUMENT;
    }

    if (!buffer->mutex_initialized) {
        return VANTAQ_EVIDENCE_RING_APPEND_IO_ERROR;
    }

    evidence_id        = vantaq_ring_buffer_record_get_evidence_id(record);
    verifier_id        = vantaq_ring_buffer_record_get_verifier_id(record);
    evidence_json      = vantaq_ring_buffer_record_get_evidence_json(record);
    evidence_hash      = vantaq_ring_buffer_record_get_evidence_hash(record);
    checksum           = vantaq_ring_buffer_record_get_checksum(record);
    issued_at_unix     = vantaq_ring_buffer_record_get_issued_at_unix(record);
    evidence_json_size = vantaq_ring_buffer_record_get_evidence_json_size(record);

    if (evidence_id[0] == '\0' || verifier_id[0] == '\0' || evidence_json[0] == '\0' ||
        evidence_hash[0] == '\0' || checksum[0] == '\0' || issued_at_unix <= 0 ||
        evidence_json_size == 0U || evidence_json_size > buffer->max_record_bytes) {
        return VANTAQ_EVIDENCE_RING_APPEND_INVALID_ARGUMENT;
    }

    lock_rc = pthread_mutex_lock(&buffer->mutex);
    if (lock_rc != 0) {
        return VANTAQ_EVIDENCE_RING_APPEND_IO_ERROR;
    }
    lock_held = true;

    open_status = read_validated_header(buffer, &header_state);
    if (open_status != VANTAQ_EVIDENCE_RING_OPEN_OK) {
        append_status = map_open_status_to_append(open_status);
        goto cleanup;
    }

    assigned_slot     = header_state.write_slot;
    assigned_sequence = header_state.next_sequence;

    slot_offset = vantaq_evidence_ring_slot_offset((size_t)assigned_slot, buffer->max_record_bytes);
    if (slot_offset > buffer->file_size || (buffer->file_size - slot_offset) < buffer->slot_size) {
        append_status = VANTAQ_EVIDENCE_RING_APPEND_IO_ERROR;
        goto cleanup;
    }

    slot_buf = calloc(1U, buffer->slot_size);
    if (slot_buf == NULL) {
        append_status = VANTAQ_EVIDENCE_RING_APPEND_IO_ERROR;
        goto cleanup;
    }

    slot_buf[VANTAQ_EVIDENCE_RING_RECORD_STATE_OFFSET] =
        (uint8_t)VANTAQ_EVIDENCE_RING_RECORD_STATE_WRITTEN;

    vantaq_evidence_ring_le32_encode(tmp32, assigned_slot);
    memcpy(slot_buf + VANTAQ_EVIDENCE_RING_RECORD_SLOT_OFFSET, tmp32, sizeof(tmp32));

    vantaq_evidence_ring_le64_encode(tmp64, assigned_sequence);
    memcpy(slot_buf + VANTAQ_EVIDENCE_RING_RECORD_SEQUENCE_OFFSET, tmp64, sizeof(tmp64));

    vantaq_evidence_ring_le64_encode(tmp64, (uint64_t)issued_at_unix);
    memcpy(slot_buf + VANTAQ_EVIDENCE_RING_RECORD_ISSUED_AT_UNIX_OFFSET, tmp64, sizeof(tmp64));

    vantaq_evidence_ring_le32_encode(tmp32, (uint32_t)evidence_json_size);
    memcpy(slot_buf + VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_JSON_LEN_OFFSET, tmp32, sizeof(tmp32));

    copy_bounded_field(slot_buf + VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_ID_OFFSET,
                       VANTAQ_EVIDENCE_ID_MAX, evidence_id);
    copy_bounded_field(slot_buf + VANTAQ_EVIDENCE_RING_RECORD_VERIFIER_ID_OFFSET,
                       VANTAQ_VERIFIER_ID_MAX, verifier_id);
    copy_bounded_field(slot_buf + VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_HASH_OFFSET,
                       VANTAQ_RING_BUFFER_EVIDENCE_HASH_MAX, evidence_hash);
    copy_bounded_field(slot_buf + VANTAQ_EVIDENCE_RING_RECORD_CHECKSUM_OFFSET,
                       VANTAQ_RING_BUFFER_CHECKSUM_MAX, checksum);

    memcpy(slot_buf + VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_JSON_OFFSET, evidence_json,
           evidence_json_size);

    if (lseek(buffer->fd, (off_t)slot_offset, SEEK_SET) < 0) {
        set_error(buffer, "slot seek failed: %s", strerror(errno));
        append_status = VANTAQ_EVIDENCE_RING_APPEND_WRITE_FAILED;
        goto cleanup;
    }

    open_status = write_all(buffer->fd, slot_buf, buffer->slot_size);
    if (open_status != VANTAQ_EVIDENCE_RING_OPEN_OK) {
        set_error(buffer, "slot write failed");
        append_status = VANTAQ_EVIDENCE_RING_APPEND_WRITE_FAILED;
        goto cleanup;
    }

    next_write_slot = (assigned_slot + 1U) % (uint32_t)buffer->max_records;

    vantaq_evidence_ring_le32_encode(tmp32, next_write_slot);
    memcpy(header_state.raw + VANTAQ_EVIDENCE_RING_HEADER_WRITE_SLOT_OFFSET, tmp32, sizeof(tmp32));

    vantaq_evidence_ring_le64_encode(tmp64, assigned_sequence + 1U);
    memcpy(header_state.raw + VANTAQ_EVIDENCE_RING_HEADER_NEXT_SEQUENCE_OFFSET, tmp64,
           sizeof(tmp64));

    if (lseek(buffer->fd, 0, SEEK_SET) < 0) {
        set_error(buffer, "header seek failed: %s", strerror(errno));
        append_status = VANTAQ_EVIDENCE_RING_APPEND_WRITE_FAILED;
        goto cleanup;
    }

    open_status = write_all(buffer->fd, header_state.raw, sizeof(header_state.raw));
    if (open_status != VANTAQ_EVIDENCE_RING_OPEN_OK) {
        set_error(buffer, "header write failed");
        append_status = VANTAQ_EVIDENCE_RING_APPEND_WRITE_FAILED;
        goto cleanup;
    }

    if (buffer->fsync_on_append && fsync(buffer->fd) != 0) {
        set_error(buffer, "fsync failed: %s", strerror(errno));
        append_status = VANTAQ_EVIDENCE_RING_APPEND_SYNC_FAILED;
        goto cleanup;
    }

    if (vantaq_ring_buffer_append_result_create_success(assigned_slot, assigned_sequence,
                                                        out_result) != RING_BUFFER_OK) {
        append_status = VANTAQ_EVIDENCE_RING_APPEND_IO_ERROR;
        goto cleanup;
    }

cleanup:
    if (slot_buf != NULL) {
        vantaq_explicit_bzero(slot_buf, buffer ? buffer->slot_size : 0U);
        free(slot_buf);
    }
    if (lock_held) {
        (void)pthread_mutex_unlock(&buffer->mutex);
    }

    return append_status;
}

enum vantaq_evidence_ring_read_status
vantaq_evidence_ring_buffer_read_latest(struct vantaq_evidence_ring_buffer *buffer,
                                        struct vantaq_ring_buffer_read_result **out_result) {
    enum vantaq_evidence_ring_read_status read_status = VANTAQ_EVIDENCE_RING_READ_OK;
    enum vantaq_evidence_ring_open_status open_status = VANTAQ_EVIDENCE_RING_OPEN_OK;
    struct vantaq_ring_header_state header_state;
    uint8_t *slot_buf      = NULL;
    uint8_t *best_slot_buf = NULL;
    bool found             = false;
    uint64_t best_sequence = 0U;
    int lock_rc;
    bool lock_held = false;
    size_t slot_index;
    struct vantaq_ring_buffer_config *config         = NULL;
    struct vantaq_ring_buffer_record *record         = NULL;
    struct vantaq_ring_buffer_read_result *result    = NULL;
    struct vantaq_ring_slot_candidate best_candidate = {0};
    ring_buffer_err_t domain_status;

    if (out_result == NULL) {
        return VANTAQ_EVIDENCE_RING_READ_INVALID_ARGUMENT;
    }
    *out_result = NULL;

    if (buffer == NULL) {
        return VANTAQ_EVIDENCE_RING_READ_INVALID_ARGUMENT;
    }

    if (!buffer->mutex_initialized) {
        return VANTAQ_EVIDENCE_RING_READ_IO_ERROR;
    }

    lock_rc = pthread_mutex_lock(&buffer->mutex);
    if (lock_rc != 0) {
        return VANTAQ_EVIDENCE_RING_READ_IO_ERROR;
    }
    lock_held = true;

    open_status = read_validated_header(buffer, &header_state);
    if (open_status != VANTAQ_EVIDENCE_RING_OPEN_OK) {
        read_status = map_open_status_to_read(open_status);
        goto cleanup;
    }

    slot_buf = calloc(1U, buffer->slot_size);
    if (slot_buf == NULL) {
        read_status = VANTAQ_EVIDENCE_RING_READ_OUT_OF_MEMORY;
        goto cleanup;
    }

    best_slot_buf = calloc(1U, buffer->slot_size);
    if (best_slot_buf == NULL) {
        read_status = VANTAQ_EVIDENCE_RING_READ_OUT_OF_MEMORY;
        goto cleanup;
    }

    for (slot_index = 0U; slot_index < buffer->max_records; slot_index++) {
        struct vantaq_ring_slot_candidate candidate;
        size_t slot_offset;

        slot_offset = vantaq_evidence_ring_slot_offset(slot_index, buffer->max_record_bytes);
        if (slot_offset > buffer->file_size ||
            (buffer->file_size - slot_offset) < buffer->slot_size) {
            read_status = VANTAQ_EVIDENCE_RING_READ_INVALID_HEADER;
            goto cleanup;
        }

        open_status = read_at_exact(buffer->fd, (off_t)slot_offset, slot_buf, buffer->slot_size);
        if (open_status != VANTAQ_EVIDENCE_RING_OPEN_OK) {
            read_status = map_open_status_to_read(open_status);
            goto cleanup;
        }

        if (slot_buf[VANTAQ_EVIDENCE_RING_RECORD_STATE_OFFSET] ==
            (uint8_t)VANTAQ_EVIDENCE_RING_RECORD_STATE_EMPTY) {
            continue;
        }

        if (slot_buf[VANTAQ_EVIDENCE_RING_RECORD_STATE_OFFSET] !=
            (uint8_t)VANTAQ_EVIDENCE_RING_RECORD_STATE_WRITTEN) {
            continue;
        }

        if (!parse_slot_candidate(buffer, slot_index, slot_buf, &candidate)) {
            continue;
        }

        if (!found || candidate.record_sequence > best_sequence) {
            memcpy(best_slot_buf, slot_buf, buffer->slot_size);
            best_sequence  = candidate.record_sequence;
            best_candidate = candidate;
            found          = true;
        }
    }

    if (!found) {
        domain_status = vantaq_ring_buffer_read_result_create_not_found(&result);
        read_status   = map_domain_status_to_read(domain_status);
        if (read_status == VANTAQ_EVIDENCE_RING_READ_OK) {
            *out_result = result;
            result      = NULL;
        }
        goto cleanup;
    }

    domain_status = vantaq_ring_buffer_config_create(buffer->path, buffer->max_records,
                                                     buffer->max_record_bytes,
                                                     buffer->fsync_on_append, &config);
    if (domain_status != RING_BUFFER_OK) {
        read_status = map_domain_status_to_read(domain_status);
        goto cleanup;
    }

    {
        uint64_t issued_at_raw;
        uint32_t evidence_json_len;
        char evidence_id[VANTAQ_EVIDENCE_ID_MAX];
        char verifier_id[VANTAQ_VERIFIER_ID_MAX];
        char evidence_hash[VANTAQ_RING_BUFFER_EVIDENCE_HASH_MAX];
        char checksum[VANTAQ_RING_BUFFER_CHECKSUM_MAX];
        char *evidence_json = NULL;

        issued_at_raw = vantaq_evidence_ring_le64_decode(
            best_slot_buf + VANTAQ_EVIDENCE_RING_RECORD_ISSUED_AT_UNIX_OFFSET);
        evidence_json_len = vantaq_evidence_ring_le32_decode(
            best_slot_buf + VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_JSON_LEN_OFFSET);

        if (best_candidate.record_slot >= buffer->max_records ||
            best_candidate.record_sequence < 1U || issued_at_raw == 0U ||
            issued_at_raw > (uint64_t)INT64_MAX || evidence_json_len == 0U ||
            evidence_json_len > buffer->max_record_bytes) {
            read_status = VANTAQ_EVIDENCE_RING_READ_INVALID_HEADER;
            goto cleanup;
        }

        if (!ring_text_field_is_valid(best_slot_buf +
                                          VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_ID_OFFSET,
                                      VANTAQ_EVIDENCE_ID_MAX) ||
            !ring_text_field_is_valid(best_slot_buf +
                                          VANTAQ_EVIDENCE_RING_RECORD_VERIFIER_ID_OFFSET,
                                      VANTAQ_VERIFIER_ID_MAX) ||
            !ring_text_field_is_valid(best_slot_buf +
                                          VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_HASH_OFFSET,
                                      VANTAQ_RING_BUFFER_EVIDENCE_HASH_MAX) ||
            !ring_text_field_is_valid(best_slot_buf + VANTAQ_EVIDENCE_RING_RECORD_CHECKSUM_OFFSET,
                                      VANTAQ_RING_BUFFER_CHECKSUM_MAX)) {
            read_status = VANTAQ_EVIDENCE_RING_READ_INVALID_HEADER;
            goto cleanup;
        }

        evidence_json = malloc((size_t)evidence_json_len + 1U);
        if (evidence_json == NULL) {
            read_status = VANTAQ_EVIDENCE_RING_READ_OUT_OF_MEMORY;
            goto cleanup;
        }

        memcpy(evidence_json, best_slot_buf + VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_JSON_OFFSET,
               evidence_json_len);
        evidence_json[evidence_json_len] = '\0';

        ring_copy_text_field(evidence_id, sizeof(evidence_id),
                             best_slot_buf + VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_ID_OFFSET,
                             VANTAQ_EVIDENCE_ID_MAX);
        ring_copy_text_field(verifier_id, sizeof(verifier_id),
                             best_slot_buf + VANTAQ_EVIDENCE_RING_RECORD_VERIFIER_ID_OFFSET,
                             VANTAQ_VERIFIER_ID_MAX);
        ring_copy_text_field(evidence_hash, sizeof(evidence_hash),
                             best_slot_buf + VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_HASH_OFFSET,
                             VANTAQ_RING_BUFFER_EVIDENCE_HASH_MAX);
        ring_copy_text_field(checksum, sizeof(checksum),
                             best_slot_buf + VANTAQ_EVIDENCE_RING_RECORD_CHECKSUM_OFFSET,
                             VANTAQ_RING_BUFFER_CHECKSUM_MAX);

        domain_status = vantaq_ring_buffer_record_create(
            config, best_candidate.record_slot, best_candidate.record_sequence, evidence_id,
            verifier_id, (int64_t)issued_at_raw, evidence_json, evidence_hash, checksum, &record);
        vantaq_explicit_bzero(evidence_json, (size_t)evidence_json_len + 1U);
        free(evidence_json);
        if (domain_status != RING_BUFFER_OK) {
            read_status = map_domain_status_to_read(domain_status);
            goto cleanup;
        }
    }

    domain_status = vantaq_ring_buffer_read_result_create_found(record, &result);
    if (domain_status != RING_BUFFER_OK) {
        read_status = map_domain_status_to_read(domain_status);
        goto cleanup;
    }

    *out_result = result;
    result      = NULL;

cleanup:
    if (result != NULL) {
        vantaq_ring_buffer_read_result_destroy(result);
    }
    if (record != NULL) {
        vantaq_ring_buffer_record_destroy(record);
    }
    if (config != NULL) {
        vantaq_ring_buffer_config_destroy(config);
    }
    if (best_slot_buf != NULL) {
        vantaq_explicit_bzero(best_slot_buf, buffer ? buffer->slot_size : 0U);
        free(best_slot_buf);
    }
    if (slot_buf != NULL) {
        vantaq_explicit_bzero(slot_buf, buffer ? buffer->slot_size : 0U);
        free(slot_buf);
    }
    if (lock_held) {
        (void)pthread_mutex_unlock(&buffer->mutex);
    }

    return read_status;
}

enum vantaq_evidence_ring_read_status vantaq_evidence_ring_buffer_read_by_evidence_id(
    struct vantaq_evidence_ring_buffer *buffer, const char *evidence_id,
    struct vantaq_ring_buffer_read_result **out_result) {
    enum vantaq_evidence_ring_read_status read_status = VANTAQ_EVIDENCE_RING_READ_OK;
    enum vantaq_evidence_ring_open_status open_status = VANTAQ_EVIDENCE_RING_OPEN_OK;
    struct vantaq_ring_header_state header_state;
    uint8_t *slot_buf      = NULL;
    uint8_t *best_slot_buf = NULL;
    bool found             = false;
    uint64_t best_sequence = 0U;
    int lock_rc;
    bool lock_held = false;
    size_t slot_index;
    struct vantaq_ring_buffer_config *config         = NULL;
    struct vantaq_ring_buffer_record *record         = NULL;
    struct vantaq_ring_buffer_read_result *result    = NULL;
    struct vantaq_ring_slot_candidate best_candidate = {0};
    ring_buffer_err_t domain_status;

    if (out_result == NULL) {
        return VANTAQ_EVIDENCE_RING_READ_INVALID_ARGUMENT;
    }
    *out_result = NULL;

    if (buffer == NULL || !input_text_is_valid(evidence_id, VANTAQ_EVIDENCE_ID_MAX)) {
        return VANTAQ_EVIDENCE_RING_READ_INVALID_ARGUMENT;
    }

    if (!buffer->mutex_initialized) {
        return VANTAQ_EVIDENCE_RING_READ_IO_ERROR;
    }

    lock_rc = pthread_mutex_lock(&buffer->mutex);
    if (lock_rc != 0) {
        return VANTAQ_EVIDENCE_RING_READ_IO_ERROR;
    }
    lock_held = true;

    open_status = read_validated_header(buffer, &header_state);
    if (open_status != VANTAQ_EVIDENCE_RING_OPEN_OK) {
        read_status = map_open_status_to_read(open_status);
        goto cleanup;
    }

    slot_buf = calloc(1U, buffer->slot_size);
    if (slot_buf == NULL) {
        read_status = VANTAQ_EVIDENCE_RING_READ_OUT_OF_MEMORY;
        goto cleanup;
    }

    best_slot_buf = calloc(1U, buffer->slot_size);
    if (best_slot_buf == NULL) {
        read_status = VANTAQ_EVIDENCE_RING_READ_OUT_OF_MEMORY;
        goto cleanup;
    }

    for (slot_index = 0U; slot_index < buffer->max_records; slot_index++) {
        struct vantaq_ring_slot_candidate candidate;
        size_t slot_offset;

        slot_offset = vantaq_evidence_ring_slot_offset(slot_index, buffer->max_record_bytes);
        if (slot_offset > buffer->file_size ||
            (buffer->file_size - slot_offset) < buffer->slot_size) {
            read_status = VANTAQ_EVIDENCE_RING_READ_INVALID_HEADER;
            goto cleanup;
        }

        open_status = read_at_exact(buffer->fd, (off_t)slot_offset, slot_buf, buffer->slot_size);
        if (open_status != VANTAQ_EVIDENCE_RING_OPEN_OK) {
            read_status = map_open_status_to_read(open_status);
            goto cleanup;
        }

        if (slot_buf[VANTAQ_EVIDENCE_RING_RECORD_STATE_OFFSET] ==
            (uint8_t)VANTAQ_EVIDENCE_RING_RECORD_STATE_EMPTY) {
            continue;
        }

        if (slot_buf[VANTAQ_EVIDENCE_RING_RECORD_STATE_OFFSET] !=
            (uint8_t)VANTAQ_EVIDENCE_RING_RECORD_STATE_WRITTEN) {
            continue;
        }

        if (!parse_slot_candidate(buffer, slot_index, slot_buf, &candidate)) {
            continue;
        }

        if (strcmp((const char *)(slot_buf + VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_ID_OFFSET),
                   evidence_id) != 0) {
            continue;
        }

        if (!found || candidate.record_sequence > best_sequence) {
            memcpy(best_slot_buf, slot_buf, buffer->slot_size);
            best_sequence  = candidate.record_sequence;
            best_candidate = candidate;
            found          = true;
        }
    }

    if (!found) {
        domain_status = vantaq_ring_buffer_read_result_create_not_found(&result);
        read_status   = map_domain_status_to_read(domain_status);
        if (read_status == VANTAQ_EVIDENCE_RING_READ_OK) {
            *out_result = result;
            result      = NULL;
        }
        goto cleanup;
    }

    domain_status = vantaq_ring_buffer_config_create(buffer->path, buffer->max_records,
                                                     buffer->max_record_bytes,
                                                     buffer->fsync_on_append, &config);
    if (domain_status != RING_BUFFER_OK) {
        read_status = map_domain_status_to_read(domain_status);
        goto cleanup;
    }

    {
        uint64_t issued_at_raw;
        uint32_t evidence_json_len;
        char record_evidence_id[VANTAQ_EVIDENCE_ID_MAX];
        char verifier_id[VANTAQ_VERIFIER_ID_MAX];
        char evidence_hash[VANTAQ_RING_BUFFER_EVIDENCE_HASH_MAX];
        char checksum[VANTAQ_RING_BUFFER_CHECKSUM_MAX];
        char *evidence_json = NULL;

        issued_at_raw = vantaq_evidence_ring_le64_decode(
            best_slot_buf + VANTAQ_EVIDENCE_RING_RECORD_ISSUED_AT_UNIX_OFFSET);
        evidence_json_len = vantaq_evidence_ring_le32_decode(
            best_slot_buf + VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_JSON_LEN_OFFSET);

        if (best_candidate.record_slot >= buffer->max_records ||
            best_candidate.record_sequence < 1U || issued_at_raw == 0U ||
            issued_at_raw > (uint64_t)INT64_MAX || evidence_json_len == 0U ||
            evidence_json_len > buffer->max_record_bytes) {
            read_status = VANTAQ_EVIDENCE_RING_READ_INVALID_HEADER;
            goto cleanup;
        }

        if (!ring_text_field_is_valid(best_slot_buf +
                                          VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_ID_OFFSET,
                                      VANTAQ_EVIDENCE_ID_MAX) ||
            !ring_text_field_is_valid(best_slot_buf +
                                          VANTAQ_EVIDENCE_RING_RECORD_VERIFIER_ID_OFFSET,
                                      VANTAQ_VERIFIER_ID_MAX) ||
            !ring_text_field_is_valid(best_slot_buf +
                                          VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_HASH_OFFSET,
                                      VANTAQ_RING_BUFFER_EVIDENCE_HASH_MAX) ||
            !ring_text_field_is_valid(best_slot_buf + VANTAQ_EVIDENCE_RING_RECORD_CHECKSUM_OFFSET,
                                      VANTAQ_RING_BUFFER_CHECKSUM_MAX)) {
            read_status = VANTAQ_EVIDENCE_RING_READ_INVALID_HEADER;
            goto cleanup;
        }

        evidence_json = malloc((size_t)evidence_json_len + 1U);
        if (evidence_json == NULL) {
            read_status = VANTAQ_EVIDENCE_RING_READ_OUT_OF_MEMORY;
            goto cleanup;
        }

        memcpy(evidence_json, best_slot_buf + VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_JSON_OFFSET,
               evidence_json_len);
        evidence_json[evidence_json_len] = '\0';

        ring_copy_text_field(record_evidence_id, sizeof(record_evidence_id),
                             best_slot_buf + VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_ID_OFFSET,
                             VANTAQ_EVIDENCE_ID_MAX);
        ring_copy_text_field(verifier_id, sizeof(verifier_id),
                             best_slot_buf + VANTAQ_EVIDENCE_RING_RECORD_VERIFIER_ID_OFFSET,
                             VANTAQ_VERIFIER_ID_MAX);
        ring_copy_text_field(evidence_hash, sizeof(evidence_hash),
                             best_slot_buf + VANTAQ_EVIDENCE_RING_RECORD_EVIDENCE_HASH_OFFSET,
                             VANTAQ_RING_BUFFER_EVIDENCE_HASH_MAX);
        ring_copy_text_field(checksum, sizeof(checksum),
                             best_slot_buf + VANTAQ_EVIDENCE_RING_RECORD_CHECKSUM_OFFSET,
                             VANTAQ_RING_BUFFER_CHECKSUM_MAX);

        domain_status = vantaq_ring_buffer_record_create(
            config, best_candidate.record_slot, best_candidate.record_sequence, record_evidence_id,
            verifier_id, (int64_t)issued_at_raw, evidence_json, evidence_hash, checksum, &record);
        vantaq_explicit_bzero(evidence_json, (size_t)evidence_json_len + 1U);
        free(evidence_json);
        if (domain_status != RING_BUFFER_OK) {
            read_status = map_domain_status_to_read(domain_status);
            goto cleanup;
        }
    }

    domain_status = vantaq_ring_buffer_read_result_create_found(record, &result);
    if (domain_status != RING_BUFFER_OK) {
        read_status = map_domain_status_to_read(domain_status);
        goto cleanup;
    }

    *out_result = result;
    result      = NULL;

cleanup:
    if (result != NULL) {
        vantaq_ring_buffer_read_result_destroy(result);
    }
    if (record != NULL) {
        vantaq_ring_buffer_record_destroy(record);
    }
    if (config != NULL) {
        vantaq_ring_buffer_config_destroy(config);
    }
    if (best_slot_buf != NULL) {
        vantaq_explicit_bzero(best_slot_buf, buffer ? buffer->slot_size : 0U);
        free(best_slot_buf);
    }
    if (slot_buf != NULL) {
        vantaq_explicit_bzero(slot_buf, buffer ? buffer->slot_size : 0U);
        free(slot_buf);
    }
    if (lock_held) {
        (void)pthread_mutex_unlock(&buffer->mutex);
    }

    return read_status;
}

int vantaq_evidence_ring_buffer_fd(const struct vantaq_evidence_ring_buffer *buffer) {
    return buffer ? buffer->fd : -1;
}

const char *vantaq_evidence_ring_buffer_path(const struct vantaq_evidence_ring_buffer *buffer) {
    static const char k_empty[] = "";

    return buffer ? buffer->path : k_empty;
}

size_t vantaq_evidence_ring_buffer_max_records(const struct vantaq_evidence_ring_buffer *buffer) {
    return buffer ? buffer->max_records : 0U;
}

size_t
vantaq_evidence_ring_buffer_max_record_bytes(const struct vantaq_evidence_ring_buffer *buffer) {
    return buffer ? buffer->max_record_bytes : 0U;
}

size_t
vantaq_evidence_ring_buffer_record_slot_size(const struct vantaq_evidence_ring_buffer *buffer) {
    return buffer ? buffer->slot_size : 0U;
}

size_t vantaq_evidence_ring_buffer_file_size(const struct vantaq_evidence_ring_buffer *buffer) {
    return buffer ? buffer->file_size : 0U;
}

const char *
vantaq_evidence_ring_buffer_last_error(const struct vantaq_evidence_ring_buffer *buffer) {
    static const char k_empty[] = "";

    return buffer ? buffer->last_error : k_empty;
}
