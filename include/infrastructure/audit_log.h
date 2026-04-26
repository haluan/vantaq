// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_INFRASTRUCTURE_AUDIT_LOG_H
#define VANTAQ_INFRASTRUCTURE_AUDIT_LOG_H

#include <stddef.h>
#include <time.h>

enum vantaq_audit_log_status {
    VANTAQ_AUDIT_LOG_STATUS_OK = 0,
    VANTAQ_AUDIT_LOG_STATUS_INVALID_ARGUMENT,
    VANTAQ_AUDIT_LOG_STATUS_IO_ERROR,
    VANTAQ_AUDIT_LOG_STATUS_FORMAT_ERROR,
    VANTAQ_AUDIT_LOG_STATUS_OUT_OF_MEMORY,
};

struct vantaq_audit_event {
    time_t time_utc_epoch_seconds;
    const char *source_ip;
    const char *method;
    const char *path;
    const char *result;
    const char *reason;
};

struct vantaq_audit_log;

enum vantaq_audit_log_status vantaq_audit_log_create(const char *path, size_t max_bytes,
                                                     struct vantaq_audit_log **out_log);
void vantaq_audit_log_destroy(struct vantaq_audit_log *log);

enum vantaq_audit_log_status vantaq_audit_log_serialize_event(const struct vantaq_audit_event *event,
                                                              char *out_line,
                                                              size_t out_line_size);
enum vantaq_audit_log_status vantaq_audit_log_append(struct vantaq_audit_log *log,
                                                     const struct vantaq_audit_event *event);

const char *vantaq_audit_log_last_error(const struct vantaq_audit_log *log);
const char *vantaq_audit_log_status_text(enum vantaq_audit_log_status status);

#endif
