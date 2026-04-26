// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/config_loader.h"

#include <ctype.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VANTAQ_MAX_LINE_LEN 512
#define VANTAQ_MAX_PATH_LEN 256
#define VANTAQ_MAX_ERROR_LEN 256
#define VANTAQ_MAX_FIELD_LEN 128
#define VANTAQ_MAX_LIST_ITEMS 32

#define VANTAQ_ZERO_STRUCT(s) memset(&(s), 0, sizeof(s))

enum vantaq_section {
    VANTAQ_SECTION_NONE = 0,
    VANTAQ_SECTION_SERVICE,
    VANTAQ_SECTION_DEVICE_IDENTITY,
    VANTAQ_SECTION_CAPABILITIES,
};

struct vantaq_string_list {
    char *items[VANTAQ_MAX_LIST_ITEMS];
    size_t count;
};

struct vantaq_runtime_config {
    char service_listen_host[VANTAQ_MAX_FIELD_LEN];
    int service_listen_port;
    char service_version[VANTAQ_MAX_FIELD_LEN];

    char device_id[VANTAQ_MAX_FIELD_LEN];
    char model[VANTAQ_MAX_FIELD_LEN];
    char serial_number[VANTAQ_MAX_FIELD_LEN];
    char manufacturer[VANTAQ_MAX_FIELD_LEN];
    char firmware_version[VANTAQ_MAX_FIELD_LEN];

    struct vantaq_string_list supported_claims;
    struct vantaq_string_list signature_algorithms;
    struct vantaq_string_list evidence_formats;
    struct vantaq_string_list challenge_modes;
    struct vantaq_string_list storage_modes;

    bool has_service_listen_host;
    bool has_service_listen_port;
    bool has_service_version;
    bool has_device_id;
    bool has_model;
    bool has_serial_number;
    bool has_manufacturer;
    bool has_firmware_version;
    bool has_supported_claims;
    bool has_signature_algorithms;
    bool has_evidence_formats;
    bool has_challenge_modes;
    bool has_storage_modes;
};

struct vantaq_config_loader {
    struct vantaq_runtime_config config;
    char last_error[VANTAQ_MAX_ERROR_LEN];
};

static const struct vantaq_string_list *get_list_const(const struct vantaq_runtime_config *config,
                                                       enum vantaq_capability_list list) {
    if (config == NULL) {
        return NULL;
    }

    switch (list) {
    case VANTAQ_CAPABILITY_SUPPORTED_CLAIMS:
        return &config->supported_claims;
    case VANTAQ_CAPABILITY_SIGNATURE_ALGORITHMS:
        return &config->signature_algorithms;
    case VANTAQ_CAPABILITY_EVIDENCE_FORMATS:
        return &config->evidence_formats;
    case VANTAQ_CAPABILITY_CHALLENGE_MODES:
        return &config->challenge_modes;
    case VANTAQ_CAPABILITY_STORAGE_MODES:
        return &config->storage_modes;
    default:
        return NULL;
    }
}

static struct vantaq_string_list *get_list_mut(struct vantaq_runtime_config *config,
                                               enum vantaq_capability_list list) {
    return (struct vantaq_string_list *)get_list_const(config, list);
}

static void loader_set_error(struct vantaq_config_loader *loader, const char *fmt,
                             const char *value) {
    char clipped[96];
    size_t n;

    if (loader == NULL || fmt == NULL) {
        return;
    }

    if (value == NULL) {
        (void)snprintf(loader->last_error, sizeof(loader->last_error), "%s", fmt);
        return;
    }

    n = strlen(value);
    if (n >= sizeof(clipped)) {
        n = sizeof(clipped) - 1;
    }
    memcpy(clipped, value, n);
    clipped[n] = '\0';

    (void)snprintf(loader->last_error, sizeof(loader->last_error), fmt, clipped);
}

static char *string_dup(const char *input) {
    size_t len;
    char *dup;

    if (input == NULL) {
        return NULL;
    }

    len = strlen(input);
    dup = (char *)malloc(len + 1);
    if (dup == NULL) {
        return NULL;
    }

    memcpy(dup, input, len + 1);
    return dup;
}

static char *ltrim(char *value) {
    while (*value != '\0' && isspace((unsigned char)*value)) {
        value++;
    }
    return value;
}

static void rtrim(char *value) {
    size_t len;

    if (value == NULL) {
        return;
    }

    len = strlen(value);
    while (len > 0 && isspace((unsigned char)value[len - 1])) {
        value[len - 1] = '\0';
        len--;
    }
}

static char *trim(char *value) {
    char *start = ltrim(value);
    rtrim(start);
    return start;
}

static bool is_blank_or_comment(const char *value) {
    if (value == NULL) {
        return true;
    }

    while (*value != '\0') {
        if (isspace((unsigned char)*value)) {
            value++;
            continue;
        }
        return *value == '#';
    }

    return true;
}

static void free_list(struct vantaq_string_list *list) {
    size_t i;

    if (list == NULL) {
        return;
    }

    for (i = 0; i < list->count; i++) {
        free(list->items[i]);
        list->items[i] = NULL;
    }
    list->count = 0;
}

static void free_config_lists(struct vantaq_runtime_config *config) {
    if (config == NULL) {
        return;
    }

    free_list(&config->supported_claims);
    free_list(&config->signature_algorithms);
    free_list(&config->evidence_formats);
    free_list(&config->challenge_modes);
    free_list(&config->storage_modes);
}

static enum vantaq_config_status copy_string_to_field(struct vantaq_config_loader *loader,
                                                      const char *full_key, const char *value_raw,
                                                      char *dst, size_t dst_size, bool *seen) {
    char *value = (char *)value_raw;
    size_t len;

    if (value == NULL) {
        loader_set_error(loader, "missing value for %s", full_key);
        return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
    }

    value = trim(value);
    if (value[0] == '\0') {
        loader_set_error(loader, "missing value for %s", full_key);
        return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
    }

    if (value[0] == '"') {
        len = strlen(value);
        if (len < 2 || value[len - 1] != '"') {
            loader_set_error(loader, "invalid quoted string for %s", full_key);
            return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
        }
        value[len - 1] = '\0';
        value++;
    }

    len = strlen(value);
    if (len == 0 || len >= dst_size) {
        loader_set_error(loader, "invalid value length for %s", full_key);
        return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
    }

    memcpy(dst, value, len + 1);
    *seen = true;
    return VANTAQ_CONFIG_STATUS_OK;
}

static enum vantaq_config_status parse_list_item(struct vantaq_config_loader *loader,
                                                 const char *item_raw,
                                                 struct vantaq_string_list *list,
                                                 const char *field_name) {
    char local[VANTAQ_MAX_FIELD_LEN];
    char *item;
    size_t len;

    if (item_raw == NULL || list == NULL) {
        return VANTAQ_CONFIG_STATUS_INVALID_ARGUMENT;
    }

    if (list->count >= VANTAQ_MAX_LIST_ITEMS) {
        loader_set_error(loader, "too many items in %s", field_name);
        return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
    }

    len = strlen(item_raw);
    if (len >= sizeof(local)) {
        loader_set_error(loader, "list item too long in %s", field_name);
        return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
    }

    memcpy(local, item_raw, len + 1);
    item = trim(local);
    if (item[0] == '\0') {
        loader_set_error(loader, "empty list item in %s", field_name);
        return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
    }

    if (item[0] == '"') {
        size_t item_len = strlen(item);
        if (item_len < 2 || item[item_len - 1] != '"') {
            loader_set_error(loader, "invalid quoted list item in %s", field_name);
            return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
        }
        item[item_len - 1] = '\0';
        item++;
    }

    list->items[list->count] = string_dup(item);
    if (list->items[list->count] == NULL) {
        loader_set_error(loader, "out of memory while parsing %s", field_name);
        return VANTAQ_CONFIG_STATUS_IO_ERROR;
    }

    list->count++;
    return VANTAQ_CONFIG_STATUS_OK;
}

static enum vantaq_config_status parse_inline_list(struct vantaq_config_loader *loader,
                                                   const char *value,
                                                   struct vantaq_string_list *list,
                                                   const char *field_name) {
    char local[VANTAQ_MAX_LINE_LEN];
    char *cursor;
    size_t len;

    if (value == NULL || list == NULL) {
        return VANTAQ_CONFIG_STATUS_INVALID_ARGUMENT;
    }

    len = strlen(value);
    if (len >= sizeof(local)) {
        loader_set_error(loader, "inline list too long for %s", field_name);
        return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
    }

    memcpy(local, value, len + 1);
    cursor = trim(local);

    if (strcmp(cursor, "[]") == 0) {
        list->count = 0;
        return VANTAQ_CONFIG_STATUS_OK;
    }

    if (cursor[0] != '[') {
        loader_set_error(loader, "invalid list syntax for %s", field_name);
        return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
    }

    cursor++;
    while (*cursor != '\0') {
        char *end;
        char *token;
        bool closes_list = false;

        if (*cursor == ']') {
            return VANTAQ_CONFIG_STATUS_OK;
        }

        end = strchr(cursor, ',');
        if (end == NULL) {
            end = strchr(cursor, ']');
            if (end == NULL) {
                loader_set_error(loader, "unterminated list for %s", field_name);
                return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
            }
            closes_list = true;
        }

        *end  = '\0';
        token = trim(cursor);
        if (token[0] != '\0') {
            enum vantaq_config_status rc = parse_list_item(loader, token, list, field_name);
            if (rc != VANTAQ_CONFIG_STATUS_OK) {
                return rc;
            }
        }

        if (closes_list) {
            return VANTAQ_CONFIG_STATUS_OK;
        }

        cursor = end + 1;
    }

    loader_set_error(loader, "unterminated list for %s", field_name);
    return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
}

static enum vantaq_config_status parse_int(struct vantaq_config_loader *loader,
                                           const char *field_name, const char *value_raw, int *out,
                                           bool *seen) {
    char *endptr;
    long number;
    char local[VANTAQ_MAX_FIELD_LEN];
    size_t len;

    if (value_raw == NULL || out == NULL || seen == NULL) {
        return VANTAQ_CONFIG_STATUS_INVALID_ARGUMENT;
    }

    len = strlen(value_raw);
    if (len >= sizeof(local)) {
        loader_set_error(loader, "value too long for %s", field_name);
        return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
    }

    memcpy(local, value_raw, len + 1);
    trim(local);
    if (local[0] == '\0') {
        loader_set_error(loader, "missing value for %s", field_name);
        return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
    }

    number = strtol(local, &endptr, 10);
    if (*endptr != '\0' || number < 1 || number > 65535 || number > INT_MAX) {
        loader_set_error(loader, "invalid integer for %s", field_name);
        return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
    }

    *out  = (int)number;
    *seen = true;
    return VANTAQ_CONFIG_STATUS_OK;
}

static bool list_contains(const struct vantaq_string_list *list, const char *needle) {
    size_t i;

    if (list == NULL || needle == NULL) {
        return false;
    }

    for (i = 0; i < list->count; i++) {
        if (strcmp(list->items[i], needle) == 0) {
            return true;
        }
    }

    return false;
}

static enum vantaq_config_status validate_config(struct vantaq_config_loader *loader,
                                                 const struct vantaq_runtime_config *config) {
    if (!config->has_service_listen_host) {
        loader_set_error(loader, "missing required field %s", "service.listen_host");
        return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
    }
    if (!config->has_service_listen_port) {
        loader_set_error(loader, "missing required field %s", "service.listen_port");
        return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
    }
    if (!config->has_service_version) {
        loader_set_error(loader, "missing required field %s", "service.version");
        return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
    }
    if (!config->has_device_id) {
        loader_set_error(loader, "missing required field %s", "device_identity.device_id");
        return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
    }
    if (!config->has_model) {
        loader_set_error(loader, "missing required field %s", "device_identity.model");
        return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
    }
    if (!config->has_serial_number) {
        loader_set_error(loader, "missing required field %s", "device_identity.serial_number");
        return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
    }
    if (!config->has_manufacturer) {
        loader_set_error(loader, "missing required field %s", "device_identity.manufacturer");
        return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
    }
    if (!config->has_firmware_version) {
        loader_set_error(loader, "missing required field %s", "device_identity.firmware_version");
        return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
    }
    if (!config->has_supported_claims) {
        loader_set_error(loader, "missing required field %s", "capabilities.supported_claims");
        return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
    }
    if (!list_contains(&config->supported_claims, "device_identity")) {
        loader_set_error(loader, "missing required capability %s", "device_identity");
        return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
    }
    if (!config->has_signature_algorithms) {
        loader_set_error(loader, "missing required field %s", "capabilities.signature_algorithms");
        return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
    }
    if (!config->has_evidence_formats) {
        loader_set_error(loader, "missing required field %s", "capabilities.evidence_formats");
        return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
    }
    if (!config->has_challenge_modes) {
        loader_set_error(loader, "missing required field %s", "capabilities.challenge_modes");
        return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
    }
    if (!config->has_storage_modes) {
        loader_set_error(loader, "missing required field %s", "capabilities.storage_modes");
        return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
    }

    return VANTAQ_CONFIG_STATUS_OK;
}

static enum vantaq_capability_list parse_capability_key(const char *key, bool *ok) {
    *ok = true;

    if (strcmp(key, "supported_claims") == 0) {
        return VANTAQ_CAPABILITY_SUPPORTED_CLAIMS;
    }
    if (strcmp(key, "signature_algorithms") == 0) {
        return VANTAQ_CAPABILITY_SIGNATURE_ALGORITHMS;
    }
    if (strcmp(key, "evidence_formats") == 0) {
        return VANTAQ_CAPABILITY_EVIDENCE_FORMATS;
    }
    if (strcmp(key, "challenge_modes") == 0) {
        return VANTAQ_CAPABILITY_CHALLENGE_MODES;
    }
    if (strcmp(key, "storage_modes") == 0) {
        return VANTAQ_CAPABILITY_STORAGE_MODES;
    }

    *ok = false;
    return VANTAQ_CAPABILITY_SUPPORTED_CLAIMS;
}

static void mark_capability_seen(struct vantaq_runtime_config *config,
                                 enum vantaq_capability_list list) {
    switch (list) {
    case VANTAQ_CAPABILITY_SUPPORTED_CLAIMS:
        config->has_supported_claims = true;
        break;
    case VANTAQ_CAPABILITY_SIGNATURE_ALGORITHMS:
        config->has_signature_algorithms = true;
        break;
    case VANTAQ_CAPABILITY_EVIDENCE_FORMATS:
        config->has_evidence_formats = true;
        break;
    case VANTAQ_CAPABILITY_CHALLENGE_MODES:
        config->has_challenge_modes = true;
        break;
    case VANTAQ_CAPABILITY_STORAGE_MODES:
        config->has_storage_modes = true;
        break;
    default:
        break;
    }
}

static enum vantaq_config_status parse_config_file(struct vantaq_config_loader *loader, FILE *fp,
                                                   struct vantaq_runtime_config *tmp) {
    char line[VANTAQ_MAX_LINE_LEN];
    enum vantaq_section section             = VANTAQ_SECTION_NONE;
    bool has_active_capability_list         = false;
    enum vantaq_capability_list active_list = VANTAQ_CAPABILITY_SUPPORTED_CLAIMS;

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *cursor;
        char *colon;
        char *key;
        char *value;
        size_t indent;
        enum vantaq_config_status rc;

        rtrim(line);
        if (is_blank_or_comment(line)) {
            continue;
        }

        cursor = line;
        while (*cursor == ' ') {
            cursor++;
        }
        indent = (size_t)(cursor - line);

        if (cursor[0] == '-' && (cursor[1] == ' ' || cursor[1] == '\t')) {
            if (indent != 4 || section != VANTAQ_SECTION_CAPABILITIES ||
                !has_active_capability_list) {
                loader_set_error(loader, "invalid list indentation", NULL);
                return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
            }

            rc = parse_list_item(loader, cursor + 1, get_list_mut(tmp, active_list),
                                 "capabilities list");
            if (rc != VANTAQ_CONFIG_STATUS_OK) {
                return rc;
            }
            continue;
        }

        has_active_capability_list = false;

        colon = strchr(cursor, ':');
        if (colon == NULL) {
            loader_set_error(loader, "missing ':' in yaml line", NULL);
            return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
        }

        *colon = '\0';
        key    = trim(cursor);
        value  = trim(colon + 1);

        if (indent == 0) {
            if (value[0] != '\0') {
                loader_set_error(loader, "top-level key must be an object", NULL);
                return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
            }

            if (strcmp(key, "service") == 0) {
                section = VANTAQ_SECTION_SERVICE;
                continue;
            }
            if (strcmp(key, "device_identity") == 0) {
                section = VANTAQ_SECTION_DEVICE_IDENTITY;
                continue;
            }
            if (strcmp(key, "capabilities") == 0) {
                section = VANTAQ_SECTION_CAPABILITIES;
                continue;
            }

            loader_set_error(loader, "unknown top-level key %s", key);
            return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
        }

        if (indent != 2) {
            loader_set_error(loader, "unsupported yaml indentation", NULL);
            return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
        }

        if (section == VANTAQ_SECTION_SERVICE) {
            if (strcmp(key, "listen_host") == 0) {
                rc = copy_string_to_field(
                    loader, "service.listen_host", value, tmp->service_listen_host,
                    sizeof(tmp->service_listen_host), &tmp->has_service_listen_host);
                if (rc != VANTAQ_CONFIG_STATUS_OK) {
                    return rc;
                }
                continue;
            }
            if (strcmp(key, "listen_port") == 0) {
                rc = parse_int(loader, "service.listen_port", value, &tmp->service_listen_port,
                               &tmp->has_service_listen_port);
                if (rc != VANTAQ_CONFIG_STATUS_OK) {
                    return rc;
                }
                continue;
            }
            if (strcmp(key, "version") == 0) {
                rc = copy_string_to_field(loader, "service.version", value, tmp->service_version,
                                          sizeof(tmp->service_version), &tmp->has_service_version);
                if (rc != VANTAQ_CONFIG_STATUS_OK) {
                    return rc;
                }
                continue;
            }

            loader_set_error(loader, "unknown service field %s", key);
            return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
        }

        if (section == VANTAQ_SECTION_DEVICE_IDENTITY) {
            if (strcmp(key, "device_id") == 0) {
                rc =
                    copy_string_to_field(loader, "device_identity.device_id", value, tmp->device_id,
                                         sizeof(tmp->device_id), &tmp->has_device_id);
                if (rc != VANTAQ_CONFIG_STATUS_OK) {
                    return rc;
                }
                continue;
            }
            if (strcmp(key, "model") == 0) {
                rc = copy_string_to_field(loader, "device_identity.model", value, tmp->model,
                                          sizeof(tmp->model), &tmp->has_model);
                if (rc != VANTAQ_CONFIG_STATUS_OK) {
                    return rc;
                }
                continue;
            }
            if (strcmp(key, "serial_number") == 0) {
                rc = copy_string_to_field(loader, "device_identity.serial_number", value,
                                          tmp->serial_number, sizeof(tmp->serial_number),
                                          &tmp->has_serial_number);
                if (rc != VANTAQ_CONFIG_STATUS_OK) {
                    return rc;
                }
                continue;
            }
            if (strcmp(key, "manufacturer") == 0) {
                rc = copy_string_to_field(loader, "device_identity.manufacturer", value,
                                          tmp->manufacturer, sizeof(tmp->manufacturer),
                                          &tmp->has_manufacturer);
                if (rc != VANTAQ_CONFIG_STATUS_OK) {
                    return rc;
                }
                continue;
            }
            if (strcmp(key, "firmware_version") == 0) {
                rc = copy_string_to_field(loader, "device_identity.firmware_version", value,
                                          tmp->firmware_version, sizeof(tmp->firmware_version),
                                          &tmp->has_firmware_version);
                if (rc != VANTAQ_CONFIG_STATUS_OK) {
                    return rc;
                }
                continue;
            }

            loader_set_error(loader, "unknown device_identity field %s", key);
            return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
        }

        if (section == VANTAQ_SECTION_CAPABILITIES) {
            bool ok;

            active_list = parse_capability_key(key, &ok);
            if (!ok) {
                loader_set_error(loader, "unknown capabilities field %s", key);
                return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
            }

            mark_capability_seen(tmp, active_list);
            free_list(get_list_mut(tmp, active_list));

            if (value[0] == '\0') {
                has_active_capability_list = true;
                continue;
            }

            rc = parse_inline_list(loader, value, get_list_mut(tmp, active_list), key);
            if (rc != VANTAQ_CONFIG_STATUS_OK) {
                return rc;
            }
            continue;
        }

        loader_set_error(loader, "field found outside section", NULL);
        return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
    }

    if (ferror(fp)) {
        loader_set_error(loader, "failed to read config file", NULL);
        return VANTAQ_CONFIG_STATUS_IO_ERROR;
    }

    return validate_config(loader, tmp);
}

struct vantaq_config_loader *vantaq_config_loader_create(void) {
    struct vantaq_config_loader *loader = (struct vantaq_config_loader *)calloc(1, sizeof(*loader));
    return loader;
}

void vantaq_config_loader_destroy(struct vantaq_config_loader *loader) {
    if (loader == NULL) {
        return;
    }

    free_config_lists(&loader->config);
    free(loader);
}

enum vantaq_config_status vantaq_config_loader_load(struct vantaq_config_loader *loader,
                                                    const char *path) {
    struct vantaq_runtime_config tmp;
    enum vantaq_config_status rc;
    FILE *fp;
    char resolved_path[VANTAQ_MAX_PATH_LEN];

    if (loader == NULL) {
        return VANTAQ_CONFIG_STATUS_INVALID_ARGUMENT;
    }

    loader->last_error[0] = '\0';
    VANTAQ_ZERO_STRUCT(tmp);

    if (path == NULL || path[0] == '\0') {
        path = VANTAQ_DEFAULT_CONFIG_PATH;
    }

    if (strlen(path) >= sizeof(resolved_path)) {
        loader_set_error(loader, "config path too long", NULL);
        return VANTAQ_CONFIG_STATUS_INVALID_ARGUMENT;
    }
    memcpy(resolved_path, path, strlen(path) + 1);

    fp = fopen(resolved_path, "r");
    if (fp == NULL) {
        loader_set_error(loader, "unable to open config file: %s", resolved_path);
        return VANTAQ_CONFIG_STATUS_IO_ERROR;
    }

    rc = parse_config_file(loader, fp, &tmp);
    (void)fclose(fp);
    if (rc != VANTAQ_CONFIG_STATUS_OK) {
        free_config_lists(&tmp);
        return rc;
    }

    free_config_lists(&loader->config);
    loader->config = tmp;
    return VANTAQ_CONFIG_STATUS_OK;
}

const char *vantaq_config_loader_last_error(const struct vantaq_config_loader *loader) {
    if (loader == NULL || loader->last_error[0] == '\0') {
        return "";
    }
    return loader->last_error;
}

const struct vantaq_runtime_config *
vantaq_config_loader_config(const struct vantaq_config_loader *loader) {
    if (loader == NULL) {
        return NULL;
    }
    return &loader->config;
}

const char *vantaq_runtime_service_listen_host(const struct vantaq_runtime_config *config) {
    return config == NULL ? "" : config->service_listen_host;
}

int vantaq_runtime_service_listen_port(const struct vantaq_runtime_config *config) {
    return config == NULL ? 0 : config->service_listen_port;
}

const char *vantaq_runtime_service_version(const struct vantaq_runtime_config *config) {
    return config == NULL ? "" : config->service_version;
}

const char *vantaq_runtime_device_id(const struct vantaq_runtime_config *config) {
    return config == NULL ? "" : config->device_id;
}

const char *vantaq_runtime_device_model(const struct vantaq_runtime_config *config) {
    return config == NULL ? "" : config->model;
}

const char *vantaq_runtime_device_serial_number(const struct vantaq_runtime_config *config) {
    return config == NULL ? "" : config->serial_number;
}

const char *vantaq_runtime_device_manufacturer(const struct vantaq_runtime_config *config) {
    return config == NULL ? "" : config->manufacturer;
}

const char *vantaq_runtime_device_firmware_version(const struct vantaq_runtime_config *config) {
    return config == NULL ? "" : config->firmware_version;
}

size_t vantaq_runtime_capability_count(const struct vantaq_runtime_config *config,
                                       enum vantaq_capability_list list) {
    const struct vantaq_string_list *target = get_list_const(config, list);
    return target == NULL ? 0 : target->count;
}

const char *vantaq_runtime_capability_item(const struct vantaq_runtime_config *config,
                                           enum vantaq_capability_list list, size_t index) {
    const struct vantaq_string_list *target = get_list_const(config, list);

    if (target == NULL || index >= target->count) {
        return NULL;
    }

    return target->items[index];
}
