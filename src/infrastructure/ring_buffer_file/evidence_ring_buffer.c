// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "evidence_ring_buffer.h"

#include "evidence_ring_format.h"
#include "infrastructure/memory/zero_struct.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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
    char last_error[VANTAQ_EVIDENCE_RING_LAST_ERROR_MAX];
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
    uint8_t header[VANTAQ_EVIDENCE_RING_HEADER_SIZE];
    uint32_t version;
    uint32_t persisted_header_size;
    uint32_t persisted_slot_size;
    uint32_t persisted_max_records;
    uint32_t persisted_max_record_bytes;
    uint32_t write_slot;
    uint64_t next_sequence;
    enum vantaq_evidence_ring_open_status status;

    if (buffer == NULL || st == NULL) {
        return VANTAQ_EVIDENCE_RING_OPEN_INVALID_ARGUMENT;
    }

    if ((size_t)st->st_size < header_size) {
        set_error(buffer, "file smaller than header");
        return VANTAQ_EVIDENCE_RING_OPEN_INVALID_HEADER;
    }

    if (lseek(buffer->fd, 0, SEEK_SET) < 0) {
        set_error(buffer, "lseek failed: %s", strerror(errno));
        return VANTAQ_EVIDENCE_RING_OPEN_IO_ERROR;
    }

    status = read_all(buffer->fd, header, sizeof(header));
    if (status != VANTAQ_EVIDENCE_RING_OPEN_OK) {
        set_error(buffer, "header read failed");
        return status;
    }

    if (memcmp(header + VANTAQ_EVIDENCE_RING_HEADER_MAGIC_OFFSET, VANTAQ_EVIDENCE_RING_MAGIC,
               VANTAQ_EVIDENCE_RING_MAGIC_SIZE) != 0) {
        set_error(buffer, "invalid magic");
        return VANTAQ_EVIDENCE_RING_OPEN_INVALID_HEADER;
    }

    version = vantaq_evidence_ring_le32_decode(header + VANTAQ_EVIDENCE_RING_HEADER_VERSION_OFFSET);
    if (version != VANTAQ_EVIDENCE_RING_FORMAT_VERSION) {
        set_error(buffer, "invalid version: %u", version);
        return VANTAQ_EVIDENCE_RING_OPEN_INVALID_HEADER;
    }

    persisted_header_size =
        vantaq_evidence_ring_le32_decode(header + VANTAQ_EVIDENCE_RING_HEADER_HEADER_SIZE_OFFSET);
    persisted_slot_size =
        vantaq_evidence_ring_le32_decode(header + VANTAQ_EVIDENCE_RING_HEADER_SLOT_SIZE_OFFSET);
    persisted_max_records =
        vantaq_evidence_ring_le32_decode(header + VANTAQ_EVIDENCE_RING_HEADER_MAX_RECORDS_OFFSET);
    persisted_max_record_bytes = vantaq_evidence_ring_le32_decode(
        header + VANTAQ_EVIDENCE_RING_HEADER_MAX_RECORD_BYTES_OFFSET);
    write_slot =
        vantaq_evidence_ring_le32_decode(header + VANTAQ_EVIDENCE_RING_HEADER_WRITE_SLOT_OFFSET);
    next_sequence =
        vantaq_evidence_ring_le64_decode(header + VANTAQ_EVIDENCE_RING_HEADER_NEXT_SEQUENCE_OFFSET);

    if (persisted_header_size != (uint32_t)header_size ||
        persisted_slot_size != (uint32_t)slot_size) {
        set_error(buffer, "invalid persisted layout sizes");
        return VANTAQ_EVIDENCE_RING_OPEN_INVALID_HEADER;
    }

    if (persisted_max_records != (uint32_t)buffer->max_records ||
        persisted_max_record_bytes != (uint32_t)buffer->max_record_bytes) {
        set_error(buffer, "config mismatch");
        return VANTAQ_EVIDENCE_RING_OPEN_CONFIG_MISMATCH;
    }

    if (write_slot >= buffer->max_records) {
        set_error(buffer, "write_slot out of range");
        return VANTAQ_EVIDENCE_RING_OPEN_INVALID_HEADER;
    }

    if (next_sequence < 1U) {
        set_error(buffer, "next_sequence invalid");
        return VANTAQ_EVIDENCE_RING_OPEN_INVALID_HEADER;
    }

    if ((size_t)st->st_size != total_file_size) {
        set_error(buffer, "file size mismatch");
        return VANTAQ_EVIDENCE_RING_OPEN_INVALID_HEADER;
    }

    return VANTAQ_EVIDENCE_RING_OPEN_OK;
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

    buffer->max_records      = vantaq_ring_buffer_config_get_max_records(config);
    buffer->max_record_bytes = vantaq_ring_buffer_config_get_max_record_bytes(config);

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

    vantaq_explicit_bzero(buffer, sizeof(*buffer));
    free(buffer);
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
