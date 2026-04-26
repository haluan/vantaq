// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/audit_log.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define VANTAQ_AUDIT_MAX_ERROR_LEN 256
#define VANTAQ_AUDIT_MAX_LINE_LEN 2048

struct vantaq_audit_log {
    char *path;
    size_t max_bytes;
    char last_error[VANTAQ_AUDIT_MAX_ERROR_LEN];
};

static void set_error(struct vantaq_audit_log *log, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void set_error(struct vantaq_audit_log *log, const char *fmt, ...) {
    va_list args;

    if (log == NULL || fmt == NULL) {
        return;
    }

    va_start(args, fmt);
    (void)vsnprintf(log->last_error, sizeof(log->last_error), fmt, args);
    va_end(args);
}

static int appendf(char *buf, size_t buf_size, size_t *used, const char *fmt, ...) {
    va_list args;
    int n;

    if (buf == NULL || used == NULL || fmt == NULL || *used >= buf_size) {
        return -1;
    }

    va_start(args, fmt);
    n = vsnprintf(buf + *used, buf_size - *used, fmt, args);
    va_end(args);
    if (n < 0 || (size_t)n >= buf_size - *used) {
        return -1;
    }

    *used += (size_t)n;
    return 0;
}

static int append_json_escaped(char *buf, size_t buf_size, size_t *used, const char *text) {
    if (buf == NULL || used == NULL || text == NULL) {
        return -1;
    }

    while (*text != '\0') {
        const char *esc = NULL;
        switch (*text) {
        case '\"':
            esc = "\\\"";
            break;
        case '\\':
            esc = "\\\\";
            break;
        case '\b':
            esc = "\\b";
            break;
        case '\f':
            esc = "\\f";
            break;
        case '\n':
            esc = "\\n";
            break;
        case '\r':
            esc = "\\r";
            break;
        case '\t':
            esc = "\\t";
            break;
        default:
            if ((unsigned char)*text < 32U) {
                if (appendf(buf, buf_size, used, "\\u%04x", (unsigned char)*text) != 0) {
                    return -1;
                }
            } else {
                if (*used >= buf_size - 1U) {
                    return -1;
                }
                buf[(*used)++] = *text;
                buf[*used]     = '\0';
            }
            break;
        }
        if (esc != NULL) {
            if (appendf(buf, buf_size, used, "%s", esc) != 0) {
                return -1;
            }
        }

        text++;
    }

    return 0;
}

static enum vantaq_audit_log_status validate_event(const struct vantaq_audit_event *event) {
    if (event == NULL || event->source_ip == NULL || event->method == NULL || event->path == NULL ||
        event->result == NULL || event->reason == NULL || event->source_ip[0] == '\0' ||
        event->method[0] == '\0' || event->path[0] == '\0' || event->result[0] == '\0' ||
        event->reason[0] == '\0') {
        return VANTAQ_AUDIT_LOG_STATUS_INVALID_ARGUMENT;
    }

    return VANTAQ_AUDIT_LOG_STATUS_OK;
}

static enum vantaq_audit_log_status write_all(int fd, const char *buf, size_t len) {
    size_t sent = 0;

    while (sent < len) {
        ssize_t n = write(fd, buf + sent, len - sent);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return VANTAQ_AUDIT_LOG_STATUS_IO_ERROR;
        }
        sent += (size_t)n;
    }

    return VANTAQ_AUDIT_LOG_STATUS_OK;
}

enum vantaq_audit_log_status vantaq_audit_log_create(const char *path, size_t max_bytes,
                                                     struct vantaq_audit_log **out_log) {
    struct vantaq_audit_log *log;
    size_t len;

    if (path == NULL || path[0] == '\0' || max_bytes == 0 || out_log == NULL) {
        return VANTAQ_AUDIT_LOG_STATUS_INVALID_ARGUMENT;
    }

    log = (struct vantaq_audit_log *)calloc(1, sizeof(*log));
    if (log == NULL) {
        return VANTAQ_AUDIT_LOG_STATUS_OUT_OF_MEMORY;
    }

    len       = strlen(path);
    log->path = (char *)malloc(len + 1);
    if (log->path == NULL) {
        free(log);
        return VANTAQ_AUDIT_LOG_STATUS_OUT_OF_MEMORY;
    }
    memcpy(log->path, path, len + 1);
    log->max_bytes     = max_bytes;
    log->last_error[0] = '\0';

    *out_log = log;
    return VANTAQ_AUDIT_LOG_STATUS_OK;
}

void vantaq_audit_log_destroy(struct vantaq_audit_log *log) {
    if (log == NULL) {
        return;
    }

    free(log->path);
    log->path = NULL;
    free(log);
}

enum vantaq_audit_log_status
vantaq_audit_log_serialize_event(const struct vantaq_audit_event *event, char *out_line,
                                 size_t out_line_size) {
    char time_buf[32];
    struct tm tm_utc;
    size_t used = 0;
    time_t event_time;

    if (validate_event(event) != VANTAQ_AUDIT_LOG_STATUS_OK || out_line == NULL ||
        out_line_size == 0) {
        return VANTAQ_AUDIT_LOG_STATUS_INVALID_ARGUMENT;
    }

    event_time = event->time_utc_epoch_seconds;
    if (event_time <= 0) {
        event_time = time(NULL);
    }

    if (gmtime_r(&event_time, &tm_utc) == NULL ||
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%SZ", &tm_utc) == 0) {
        return VANTAQ_AUDIT_LOG_STATUS_FORMAT_ERROR;
    }

    out_line[0] = '\0';
    if (appendf(out_line, out_line_size, &used, "{\"time\":\"") != 0 ||
        append_json_escaped(out_line, out_line_size, &used, time_buf) != 0 ||
        appendf(out_line, out_line_size, &used, "\",\"source_ip\":\"") != 0 ||
        append_json_escaped(out_line, out_line_size, &used, event->source_ip) != 0 ||
        appendf(out_line, out_line_size, &used, "\",\"method\":\"") != 0 ||
        append_json_escaped(out_line, out_line_size, &used, event->method) != 0 ||
        appendf(out_line, out_line_size, &used, "\",\"path\":\"") != 0 ||
        append_json_escaped(out_line, out_line_size, &used, event->path) != 0 ||
        appendf(out_line, out_line_size, &used, "\",\"result\":\"") != 0 ||
        append_json_escaped(out_line, out_line_size, &used, event->result) != 0 ||
        appendf(out_line, out_line_size, &used, "\",\"reason\":\"") != 0 ||
        append_json_escaped(out_line, out_line_size, &used, event->reason) != 0 ||
        appendf(out_line, out_line_size, &used, "\"}\n") != 0) {
        return VANTAQ_AUDIT_LOG_STATUS_FORMAT_ERROR;
    }

    return VANTAQ_AUDIT_LOG_STATUS_OK;
}

enum vantaq_audit_log_status vantaq_audit_log_append(struct vantaq_audit_log *log,
                                                     const struct vantaq_audit_event *event) {
    char line[VANTAQ_AUDIT_MAX_LINE_LEN];
    struct stat st;
    int fd;
    enum vantaq_audit_log_status status;
    size_t line_len;

    if (log == NULL || event == NULL) {
        return VANTAQ_AUDIT_LOG_STATUS_INVALID_ARGUMENT;
    }

    status = vantaq_audit_log_serialize_event(event, line, sizeof(line));
    if (status != VANTAQ_AUDIT_LOG_STATUS_OK) {
        set_error(log, "failed to serialize audit event");
        return status;
    }
    line_len = strlen(line);

    if (line_len > log->max_bytes) {
        set_error(log, "event size %zu exceeds max_bytes %zu", line_len, log->max_bytes);
        return VANTAQ_AUDIT_LOG_STATUS_FORMAT_ERROR;
    }

    fd = open(log->path, O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
        set_error(log, "open failed for %s: %s", log->path, strerror(errno));
        return VANTAQ_AUDIT_LOG_STATUS_IO_ERROR;
    }

    if (fstat(fd, &st) != 0) {
        set_error(log, "fstat failed for %s: %s", log->path, strerror(errno));
        (void)close(fd);
        return VANTAQ_AUDIT_LOG_STATUS_IO_ERROR;
    }

    if ((size_t)st.st_size + line_len > log->max_bytes) {
        if (ftruncate(fd, 0) != 0 || lseek(fd, 0, SEEK_SET) < 0) {
            set_error(log, "truncate failed for %s: %s", log->path, strerror(errno));
            (void)close(fd);
            return VANTAQ_AUDIT_LOG_STATUS_IO_ERROR;
        }
    } else if (lseek(fd, 0, SEEK_END) < 0) {
        set_error(log, "seek failed for %s: %s", log->path, strerror(errno));
        (void)close(fd);
        return VANTAQ_AUDIT_LOG_STATUS_IO_ERROR;
    }

    status = write_all(fd, line, line_len);
    if (status != VANTAQ_AUDIT_LOG_STATUS_OK) {
        set_error(log, "write failed for %s: %s", log->path, strerror(errno));
        (void)close(fd);
        return status;
    }

    if (close(fd) != 0) {
        set_error(log, "close failed for %s: %s", log->path, strerror(errno));
        return VANTAQ_AUDIT_LOG_STATUS_IO_ERROR;
    }

    return VANTAQ_AUDIT_LOG_STATUS_OK;
}

const char *vantaq_audit_log_last_error(const struct vantaq_audit_log *log) {
    if (log == NULL) {
        return NULL;
    }
    return log->last_error;
}

const char *vantaq_audit_log_status_text(enum vantaq_audit_log_status status) {
    switch (status) {
    case VANTAQ_AUDIT_LOG_STATUS_OK:
        return "ok";
    case VANTAQ_AUDIT_LOG_STATUS_INVALID_ARGUMENT:
        return "invalid argument";
    case VANTAQ_AUDIT_LOG_STATUS_IO_ERROR:
        return "io error";
    case VANTAQ_AUDIT_LOG_STATUS_FORMAT_ERROR:
        return "format error";
    case VANTAQ_AUDIT_LOG_STATUS_OUT_OF_MEMORY:
        return "out of memory";
    default:
        return "unknown";
    }
}
