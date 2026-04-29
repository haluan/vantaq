// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/linux_measurement/boot_state.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VANTAQ_BOOT_STATE_CLAIM "boot_state"
#define VANTAQ_BOOT_STATE_SECURE_BOOT_KEY "secure_boot"
#define VANTAQ_BOOT_STATE_BOOT_MODE_KEY "boot_mode"
#define VANTAQ_BOOT_STATE_ROLLBACK_KEY "rollback_detected"

struct vantaq_boot_state_fields {
    const char *secure_boot;
    const char *boot_mode;
    const char *rollback_detected;
    int has_secure_boot;
    int has_boot_mode;
    int has_rollback;
};

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

static enum vantaq_boot_state_status
build_measurement_error_result(const char *path, vantaq_measurement_error_code_t error_code,
                               struct vantaq_measurement_result **out_result) {
    vantaq_measurement_model_err_t model_err = vantaq_measurement_result_create_error(
        VANTAQ_BOOT_STATE_CLAIM, path, error_code, out_result);
    if (model_err != VANTAQ_MEASUREMENT_MODEL_OK) {
        return VANTAQ_BOOT_STATE_ERR_MODEL_FAILED;
    }
    return VANTAQ_BOOT_STATE_OK;
}

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
            if (fields->has_rollback) {
                return VANTAQ_BOOT_STATE_ERR_PARSE_FAILED;
            }
            fields->rollback_detected = value;
            fields->has_rollback      = 1;
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
    enum vantaq_boot_state_status status = VANTAQ_BOOT_STATE_ERR_READ_FAILED;
    FILE *fp                             = NULL;
    long file_len                        = -1;
    char *buffer                         = NULL;
    size_t read_len                      = 0;
    const char *boot_state_path;
    size_t max_file_bytes;
    struct vantaq_boot_state_fields fields = {0};
    char value[VANTAQ_MEASUREMENT_VALUE_MAX];
    const char *rollback_value;
    int write_len;

    if (out_result == NULL || config == NULL) {
        return VANTAQ_BOOT_STATE_ERR_INVALID_ARG;
    }
    *out_result = NULL;

    boot_state_path = vantaq_runtime_measurement_boot_state_path(config);
    max_file_bytes  = vantaq_runtime_measurement_max_file_bytes(config);
    if (boot_state_path == NULL || boot_state_path[0] == '\0' || max_file_bytes == 0) {
        return VANTAQ_BOOT_STATE_ERR_INVALID_ARG;
    }

    fp = fopen(boot_state_path, "rb");
    if (fp == NULL) {
        if (errno == ENOENT) {
            status = VANTAQ_BOOT_STATE_ERR_SOURCE_NOT_FOUND;
            goto map_error;
        }
        status = VANTAQ_BOOT_STATE_ERR_READ_FAILED;
        goto map_error;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        status = VANTAQ_BOOT_STATE_ERR_READ_FAILED;
        goto map_error;
    }

    file_len = ftell(fp);
    if (file_len < 0) {
        status = VANTAQ_BOOT_STATE_ERR_READ_FAILED;
        goto map_error;
    }
    if ((size_t)file_len > max_file_bytes) {
        status = VANTAQ_BOOT_STATE_ERR_FILE_TOO_LARGE;
        goto map_error;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        status = VANTAQ_BOOT_STATE_ERR_READ_FAILED;
        goto map_error;
    }

    buffer = malloc((size_t)file_len + 1U);
    if (buffer == NULL) {
        status = VANTAQ_BOOT_STATE_ERR_READ_FAILED;
        goto map_error;
    }

    read_len = fread(buffer, 1, (size_t)file_len, fp);
    if (read_len != (size_t)file_len) {
        status = VANTAQ_BOOT_STATE_ERR_READ_FAILED;
        goto map_error;
    }
    buffer[file_len] = '\0';

    status = parse_boot_state_buffer(buffer, &fields);
    if (status != VANTAQ_BOOT_STATE_OK) {
        goto map_error;
    }

    rollback_value = fields.has_rollback ? fields.rollback_detected : "";
    write_len = snprintf(value, sizeof(value), "secure_boot=%s;boot_mode=%s;rollback_detected=%s",
                         fields.secure_boot, fields.boot_mode, rollback_value);
    if (write_len < 0 || (size_t)write_len >= sizeof(value)) {
        status = VANTAQ_BOOT_STATE_ERR_PARSE_FAILED;
        goto map_error;
    }

    if (vantaq_measurement_result_create_success(VANTAQ_BOOT_STATE_CLAIM, value, boot_state_path,
                                                 out_result) != VANTAQ_MEASUREMENT_MODEL_OK) {
        status = VANTAQ_BOOT_STATE_ERR_MODEL_FAILED;
        goto cleanup;
    }

    status = VANTAQ_BOOT_STATE_OK;
    goto cleanup;

map_error:
    if (status == VANTAQ_BOOT_STATE_ERR_SOURCE_NOT_FOUND) {
        enum vantaq_boot_state_status map_status = build_measurement_error_result(
            boot_state_path, MEASUREMENT_SOURCE_NOT_FOUND, out_result);
        if (map_status != VANTAQ_BOOT_STATE_OK) {
            status = map_status;
        }
    } else {
        enum vantaq_boot_state_status map_status =
            build_measurement_error_result(boot_state_path, MEASUREMENT_READ_FAILED, out_result);
        if (map_status != VANTAQ_BOOT_STATE_OK) {
            status = map_status;
        }
    }

cleanup:
    if (fp != NULL) {
        fclose(fp);
    }
    if (buffer != NULL) {
        free(buffer);
    }
    return status;
}
