// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/linux_measurement/boot_state.h"
#include "domain/measurement/supported_claims.h"
#include "infrastructure/memory/zero_struct.h"

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define VANTAQ_BOOT_STATE_SECURE_BOOT_KEY VANTAQ_BOOT_STATE_KEY_SECURE_BOOT
#define VANTAQ_BOOT_STATE_BOOT_MODE_KEY VANTAQ_BOOT_STATE_KEY_BOOT_MODE
#define VANTAQ_BOOT_STATE_ROLLBACK_KEY VANTAQ_BOOT_STATE_KEY_ROLLBACK_DETECTED

/* Parsed field pointers reference slices of the mutable buffer passed to parse_boot_state_buffer()
 * until that buffer is freed or repurposed. */
struct vantaq_boot_state_fields {
    const char *secure_boot;
    const char *boot_mode;
    const char *rollback_detected;
    int has_secure_boot;
    int has_boot_mode;
    int has_rollback;
};

/* Trims leading/trailing ASCII whitespace in place; writes a NUL terminator. Text must point into
 * writable storage (never a string literal). */
static char *trim_in_place(char *text) {
    char *start;
    char *end;

    if (text == NULL) {
        return NULL;
    }

    start = text;
    while (*start != '\0' && isspace((unsigned char)*start) != 0) {
        start++;
    }

    end = start + strlen(start);
    while (end > start && isspace((unsigned char)*(end - 1)) != 0) {
        end--;
    }
    *end = '\0';

    return start;
}

static int boot_state_field_value_invalid(const char *value) {
    const unsigned char *p;

    if (value == NULL) {
        return 1;
    }
    for (p = (const unsigned char *)value; *p != '\0'; p++) {
        /* Block delimiter injection and control characters that could confuse downstream parsers.
         */
        if (*p == (unsigned char)';' || *p == (unsigned char)'=' || *p < 0x20U || *p == 0x7fU) {
            return 1;
        }
    }
    return 0;
}

static vantaq_measurement_error_code_t
map_status_to_measurement_error(enum vantaq_boot_state_status status) {
    switch (status) {
    case VANTAQ_BOOT_STATE_ERR_SOURCE_NOT_FOUND:
        return MEASUREMENT_SOURCE_NOT_FOUND;
    case VANTAQ_BOOT_STATE_ERR_PARSE_FAILED:
        return MEASUREMENT_PARSE_FAILED;
    case VANTAQ_BOOT_STATE_ERR_FILE_TOO_LARGE:
    case VANTAQ_BOOT_STATE_ERR_READ_FAILED:
        return MEASUREMENT_READ_FAILED;
    default:
        return MEASUREMENT_READ_FAILED;
    }
}

static enum vantaq_boot_state_status read_file_bounded(FILE *fp, size_t max_file_bytes,
                                                       char **out_buffer, size_t *out_len) {
    char chunk[4096];
    char *buffer = NULL;
    size_t used  = 0U;
    size_t cap   = 0U;

    if (fp == NULL || out_buffer == NULL || out_len == NULL || max_file_bytes == 0U) {
        return VANTAQ_BOOT_STATE_ERR_INVALID_ARG;
    }
    *out_buffer = NULL;
    *out_len    = 0U;

    while (true) {
        size_t read_len = fread(chunk, 1, sizeof(chunk), fp);
        if (read_len > 0U) {
            char *new_buffer;
            size_t needed  = 0U;
            size_t new_cap = 0U;

            if (used > max_file_bytes - read_len) {
                vantaq_explicit_bzero(chunk, sizeof(chunk));
                free(buffer);
                return VANTAQ_BOOT_STATE_ERR_FILE_TOO_LARGE;
            }
            needed = used + read_len + 1U;
            if (needed < used || needed > max_file_bytes + 1U) {
                vantaq_explicit_bzero(chunk, sizeof(chunk));
                free(buffer);
                return VANTAQ_BOOT_STATE_ERR_FILE_TOO_LARGE;
            }

            new_cap = (cap == 0U) ? needed : cap;
            while (new_cap < needed) {
                if (new_cap > (SIZE_MAX / 2U)) {
                    new_cap = needed;
                    break;
                }
                new_cap *= 2U;
            }
            if (new_cap > max_file_bytes + 1U) {
                new_cap = max_file_bytes + 1U;
            }
            if (new_cap < needed) {
                vantaq_explicit_bzero(chunk, sizeof(chunk));
                free(buffer);
                return VANTAQ_BOOT_STATE_ERR_READ_FAILED;
            }

            new_buffer = realloc(buffer, new_cap);
            if (new_buffer == NULL) {
                vantaq_explicit_bzero(chunk, sizeof(chunk));
                free(buffer);
                return VANTAQ_BOOT_STATE_ERR_READ_FAILED;
            }
            buffer = new_buffer;
            cap    = new_cap;

            memcpy(buffer + used, chunk, read_len);
            used += read_len;
        }

        if (read_len < sizeof(chunk)) {
            if (ferror(fp) != 0) {
                vantaq_explicit_bzero(chunk, sizeof(chunk));
                free(buffer);
                return VANTAQ_BOOT_STATE_ERR_READ_FAILED;
            }
            break;
        }
    }

    if (used == 0U) {
        vantaq_explicit_bzero(chunk, sizeof(chunk));
        free(buffer);
        return VANTAQ_BOOT_STATE_ERR_READ_FAILED;
    }

    if (buffer == NULL) {
        vantaq_explicit_bzero(chunk, sizeof(chunk));
        return VANTAQ_BOOT_STATE_ERR_READ_FAILED;
    }

    buffer[used] = '\0';
    *out_buffer  = buffer;
    *out_len     = used;
    vantaq_explicit_bzero(chunk, sizeof(chunk));
    return VANTAQ_BOOT_STATE_OK;
}

/* Parses boot_state text from buffer. Mutates buffer (strtok_r and '=' overwritten with NUL).
 * After return, lines are split and keys/values point into buffer — buffer must remain unchanged
 * until callers finish using fields (typically until freeing buffer). */
static enum vantaq_boot_state_status
parse_boot_state_buffer(char *buffer, struct vantaq_boot_state_fields *fields) {
    char *line_ctx = NULL;
    char *line;

    line = strtok_r(buffer, "\n", &line_ctx);
    while (line != NULL) {
        char *parsed_line = trim_in_place(line);
        char *equal_sign;
        char *key;
        char *value;

        if (parsed_line[0] == '\0') {
            line = strtok_r(NULL, "\n", &line_ctx);
            continue;
        }

        equal_sign = strchr(parsed_line, '=');
        if (equal_sign == NULL) {
            return VANTAQ_BOOT_STATE_ERR_PARSE_FAILED;
        }

        *equal_sign = '\0';
        key         = trim_in_place(parsed_line);
        value       = trim_in_place(equal_sign + 1);

        if (key[0] == '\0') {
            return VANTAQ_BOOT_STATE_ERR_PARSE_FAILED;
        }

        if (strcmp(key, VANTAQ_BOOT_STATE_SECURE_BOOT_KEY) == 0) {
            if (fields->has_secure_boot || value[0] == '\0') {
                return VANTAQ_BOOT_STATE_ERR_PARSE_FAILED;
            }
            fields->secure_boot     = value;
            fields->has_secure_boot = 1;
        } else if (strcmp(key, VANTAQ_BOOT_STATE_BOOT_MODE_KEY) == 0) {
            if (fields->has_boot_mode || value[0] == '\0') {
                return VANTAQ_BOOT_STATE_ERR_PARSE_FAILED;
            }
            fields->boot_mode     = value;
            fields->has_boot_mode = 1;
        } else if (strcmp(key, VANTAQ_BOOT_STATE_ROLLBACK_KEY) == 0) {
            if (fields->has_rollback || value[0] == '\0') {
                return VANTAQ_BOOT_STATE_ERR_PARSE_FAILED;
            }
            fields->rollback_detected = value;
            fields->has_rollback      = 1;
        } else {
            return VANTAQ_BOOT_STATE_ERR_PARSE_FAILED;
        }

        line = strtok_r(NULL, "\n", &line_ctx);
    }

    if (!fields->has_secure_boot || !fields->has_boot_mode) {
        return VANTAQ_BOOT_STATE_ERR_PARSE_FAILED;
    }

    return VANTAQ_BOOT_STATE_OK;
}

enum vantaq_boot_state_status
vantaq_boot_state_measure(const struct vantaq_runtime_config *config,
                          struct vantaq_measurement_result **out_result) {
    enum vantaq_boot_state_status status = VANTAQ_BOOT_STATE_OK;
    FILE *fp                             = NULL;
    char *buffer                         = NULL;
    size_t buffer_len                    = 0U;
    const char *boot_state_path;
    size_t max_file_bytes;
    struct vantaq_boot_state_fields fields = {0};
    char value[VANTAQ_MEASUREMENT_VALUE_MAX];
    const char *rollback_value;
    int write_len;
    vantaq_measurement_error_code_t measurement_error = MEASUREMENT_READ_FAILED;
    vantaq_measurement_model_err_t model_err          = VANTAQ_MEASUREMENT_MODEL_OK;

    if (out_result == NULL || config == NULL) {
        return VANTAQ_BOOT_STATE_ERR_INVALID_ARG;
    }
    *out_result = NULL;

    boot_state_path = vantaq_runtime_measurement_boot_state_path(config);
    max_file_bytes  = vantaq_runtime_measurement_max_file_bytes(config);
    if (boot_state_path == NULL || boot_state_path[0] == '\0' || max_file_bytes == 0U ||
        max_file_bytes > VANTAQ_MEASUREMENT_DEFAULT_MAX_FILE_BYTES) {
        return VANTAQ_BOOT_STATE_ERR_INVALID_ARG;
    }

    errno = 0;
    fp    = fopen(boot_state_path, "rb");
    if (fp == NULL) {
        int fopen_errno = errno;
        struct stat path_st;

        if (fopen_errno == ENOENT) {
            status = VANTAQ_BOOT_STATE_ERR_SOURCE_NOT_FOUND;
            goto cleanup;
        }
        if (stat(boot_state_path, &path_st) != 0) {
            int stat_errno = errno;

            if (stat_errno == ENOENT) {
                status = VANTAQ_BOOT_STATE_ERR_SOURCE_NOT_FOUND;
                goto cleanup;
            }
        }
        status = VANTAQ_BOOT_STATE_ERR_READ_FAILED;
        goto cleanup;
    }

    status = read_file_bounded(fp, max_file_bytes, &buffer, &buffer_len);
    if (status != VANTAQ_BOOT_STATE_OK) {
        goto cleanup;
    }

    status = parse_boot_state_buffer(buffer, &fields);
    if (status != VANTAQ_BOOT_STATE_OK) {
        goto cleanup;
    }

    if (boot_state_field_value_invalid(fields.secure_boot) ||
        boot_state_field_value_invalid(fields.boot_mode) ||
        (fields.has_rollback && boot_state_field_value_invalid(fields.rollback_detected))) {
        status = VANTAQ_BOOT_STATE_ERR_PARSE_FAILED;
        goto cleanup;
    }

    rollback_value = fields.has_rollback ? fields.rollback_detected : "";
    write_len = snprintf(value, sizeof(value), "secure_boot=%s;boot_mode=%s;rollback_detected=%s",
                         fields.secure_boot, fields.boot_mode, rollback_value);
    if (write_len < 0 || (size_t)write_len >= sizeof(value)) {
        status = VANTAQ_BOOT_STATE_ERR_PARSE_FAILED;
        goto cleanup;
    }

    model_err = vantaq_measurement_result_create_success(VANTAQ_CLAIM_BOOT_STATE, value,
                                                         boot_state_path, out_result);
    if (model_err != VANTAQ_MEASUREMENT_MODEL_OK) {
        status = VANTAQ_BOOT_STATE_ERR_MODEL_FAILED;
        goto cleanup;
    }

    status = VANTAQ_BOOT_STATE_OK;

cleanup:
    if (status != VANTAQ_BOOT_STATE_OK && status != VANTAQ_BOOT_STATE_ERR_INVALID_ARG &&
        *out_result == NULL) {
        measurement_error = (status == VANTAQ_BOOT_STATE_ERR_MODEL_FAILED)
                                ? MEASUREMENT_READ_FAILED
                                : map_status_to_measurement_error(status);
        model_err = vantaq_measurement_result_create_error(VANTAQ_CLAIM_BOOT_STATE, boot_state_path,
                                                           measurement_error, out_result);
        if (model_err != VANTAQ_MEASUREMENT_MODEL_OK) {
            status      = VANTAQ_BOOT_STATE_ERR_MODEL_FAILED;
            *out_result = NULL;
        }
    }
    if (fp != NULL) {
        fclose(fp);
    }
    if (buffer != NULL) {
        vantaq_explicit_bzero(buffer, buffer_len + 1U);
        free(buffer);
    }
    vantaq_explicit_bzero(value, sizeof(value));
    return status;
}
