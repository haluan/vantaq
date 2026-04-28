// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/config_loader.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define VANTAQ_MAX_LINE_LEN 512
#define VANTAQ_MAX_PATH_LEN 256
#define VANTAQ_MAX_ERROR_LEN 256

#include "infrastructure/memory/zero_struct.h"

enum vantaq_section {
    VANTAQ_SECTION_NONE = 0,
    VANTAQ_SECTION_SERVER,
    VANTAQ_SECTION_SERVER_TLS,
    VANTAQ_SECTION_DEVICE_IDENTITY,
    VANTAQ_SECTION_CAPABILITIES,
    VANTAQ_SECTION_NETWORK_ACCESS,
    VANTAQ_SECTION_AUDIT,
    VANTAQ_SECTION_VERIFIERS,
    VANTAQ_SECTION_CHALLENGE,
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

static void loader_set_error(struct vantaq_config_loader *loader, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void loader_set_error(struct vantaq_config_loader *loader, const char *fmt, ...) {
    va_list args;

    if (loader == NULL || fmt == NULL) {
        return;
    }

    va_start(args, fmt);
    (void)vsnprintf(loader->last_error, sizeof(loader->last_error), fmt, args);
    va_end(args);
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
    size_t i;

    if (config == NULL) {
        return;
    }

    free_list(&config->supported_claims);
    free_list(&config->signature_algorithms);
    free_list(&config->evidence_formats);
    free_list(&config->challenge_modes);
    free_list(&config->storage_modes);
    free_list(&config->allowed_subnets);
    for (i = 0; i < config->verifiers_count; i++) {
        free_list(&config->verifiers[i].roles);
        free_list(&config->verifiers[i].allowed_apis);
    }
    config->verifiers_count = 0;
}

static enum vantaq_config_status copy_string_to_field(struct vantaq_config_loader *loader,
                                                      const char *full_key, const char *value_raw,
                                                      char *dst, size_t dst_size, bool *seen) {
    char local[VANTAQ_MAX_LINE_LEN];
    char *value;
    size_t len;

    VANTAQ_ZERO_STRUCT(local);

    if (value_raw == NULL) {
        loader_set_error(loader, "missing value for %s", full_key);
        return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
    }

    if (*seen) {
        loader_set_error(loader, "duplicate field %s", full_key);
        return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
    }

    len = strlen(value_raw);
    if (len >= sizeof(local)) {
        loader_set_error(loader, "value too long for %s", full_key);
        return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
    }

    memcpy(local, value_raw, len + 1);
    value = trim(local);
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

    VANTAQ_ZERO_STRUCT(local);

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

    if (item[0] == '\0') {
        loader_set_error(loader, "empty list item in %s", field_name);
        return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
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

    VANTAQ_ZERO_STRUCT(local);

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
            cursor++;
            if (trim(cursor)[0] != '\0') {
                loader_set_error(loader, "trailing content after list for %s", field_name);
                return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
            }
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
            cursor = end + 1;
            if (trim(cursor)[0] != '\0') {
                loader_set_error(loader, "trailing content after list for %s", field_name);
                return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
            }
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

    VANTAQ_ZERO_STRUCT(local);

    if (value_raw == NULL || out == NULL || seen == NULL) {
        return VANTAQ_CONFIG_STATUS_INVALID_ARGUMENT;
    }

    if (*seen) {
        loader_set_error(loader, "duplicate field %s", field_name);
        return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
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

static enum vantaq_config_status parse_size_t(struct vantaq_config_loader *loader,
                                              const char *field_name, const char *value_raw,
                                              size_t *out, bool *seen) {
    char *endptr;
    unsigned long long number;
    char local[VANTAQ_MAX_FIELD_LEN];
    size_t len;

    VANTAQ_ZERO_STRUCT(local);

    if (value_raw == NULL || out == NULL || seen == NULL) {
        return VANTAQ_CONFIG_STATUS_INVALID_ARGUMENT;
    }

    if (*seen) {
        loader_set_error(loader, "duplicate field %s", field_name);
        return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
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

    number = strtoull(local, &endptr, 10);
    if (*endptr != '\0' || number == 0) {
        loader_set_error(loader, "invalid size for %s", field_name);
        return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
    }

    *out  = (size_t)number;
    *seen = true;
    return VANTAQ_CONFIG_STATUS_OK;
}

static enum vantaq_config_status parse_bool(struct vantaq_config_loader *loader,
                                            const char *field_name, const char *value_raw,
                                            bool *out, bool *seen) {
    char local[VANTAQ_MAX_FIELD_LEN];
    size_t len;
    char *value;

    VANTAQ_ZERO_STRUCT(local);

    if (value_raw == NULL || out == NULL || seen == NULL) {
        return VANTAQ_CONFIG_STATUS_INVALID_ARGUMENT;
    }

    if (*seen) {
        loader_set_error(loader, "duplicate field %s", field_name);
        return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
    }

    len = strlen(value_raw);
    if (len >= sizeof(local)) {
        loader_set_error(loader, "value too long for %s", field_name);
        return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
    }

    memcpy(local, value_raw, len + 1);
    value = trim(local);
    if (strcmp(value, "true") == 0) {
        *out  = true;
        *seen = true;
        return VANTAQ_CONFIG_STATUS_OK;
    }
    if (strcmp(value, "false") == 0) {
        *out  = false;
        *seen = true;
        return VANTAQ_CONFIG_STATUS_OK;
    }

    loader_set_error(loader, "invalid boolean for %s", field_name);
    return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
}

static bool is_valid_capability_item(enum vantaq_capability_list list, const char *item) {
    static const char *const supported_claims[] = {
        "device_identity",  "firmware_hash", "hw_version",     "sw_version",
        "boot_loader_hash", "pcr_values",    "security_level", NULL};
    static const char *const signature_algorithms[] = {"ES256", "ES384", "ES512", "RS256",
                                                       "RS384", "RS512", NULL};
    static const char *const evidence_formats[]     = {"eat", "dice", "tpm1.2", "tpm2.0", NULL};
    static const char *const challenge_modes[]      = {"nonce", "timestamp", "counter", NULL};
    static const char *const storage_modes[] = {"volatile", "persistent", "secure_element", NULL};

    const char *const *allowlist;
    size_t i;

    if (item == NULL) {
        return false;
    }

    switch (list) {
    case VANTAQ_CAPABILITY_SUPPORTED_CLAIMS:
        allowlist = supported_claims;
        break;
    case VANTAQ_CAPABILITY_SIGNATURE_ALGORITHMS:
        allowlist = signature_algorithms;
        break;
    case VANTAQ_CAPABILITY_EVIDENCE_FORMATS:
        allowlist = evidence_formats;
        break;
    case VANTAQ_CAPABILITY_CHALLENGE_MODES:
        allowlist = challenge_modes;
        break;
    case VANTAQ_CAPABILITY_STORAGE_MODES:
        allowlist = storage_modes;
        break;
    default:
        return false;
    }

    for (i = 0; allowlist[i] != NULL; i++) {
        if (strcmp(allowlist[i], item) == 0) {
            return true;
        }
    }

    return false;
}

static bool is_valid_ipv4_cidr(const char *cidr) {
    char local[VANTAQ_MAX_FIELD_LEN];
    char *slash;
    char *prefix_text;
    char *endptr;
    long prefix;
    struct in_addr addr;
    size_t len;

    if (cidr == NULL) {
        return false;
    }

    len = strlen(cidr);
    if (len == 0 || len >= sizeof(local)) {
        return false;
    }

    memcpy(local, cidr, len + 1);
    slash = strchr(local, '/');
    if (slash == NULL) {
        return false;
    }

    *slash      = '\0';
    prefix_text = slash + 1;
    if (local[0] == '\0' || prefix_text[0] == '\0') {
        return false;
    }

    if (inet_pton(AF_INET, local, &addr) != 1) {
        return false;
    }

    prefix = strtol(prefix_text, &endptr, 10);
    if (*endptr != '\0' || prefix < 0 || prefix > 32) {
        return false;
    }

    return true;
}

static bool is_valid_listen_host(const char *host) {
    struct in_addr addr4;
    struct in6_addr addr6;
    const char *p;

    if (host == NULL || host[0] == '\0') {
        return false;
    }

    if (inet_pton(AF_INET, host, &addr4) == 1) {
        return true;
    }

    if (inet_pton(AF_INET6, host, &addr6) == 1) {
        return true;
    }

    for (p = host; *p != '\0'; p++) {
        if (!isalnum((unsigned char)*p) && *p != '.' && *p != '-') {
            return false;
        }
    }

    return true;
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
    size_t i;
    size_t j;

    if (!config->has_service_listen_host) {
        loader_set_error(loader, "missing required field %s", "server.listen_address");
        return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
    }
    if (!is_valid_listen_host(config->service_listen_host)) {
        loader_set_error(loader, "invalid server.listen_address: %s", config->service_listen_host);
        return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
    }
    if (!config->has_service_listen_port) {
        loader_set_error(loader, "missing required field %s", "server.listen_port");
        return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
    }
    if (!config->has_service_version) {
        loader_set_error(loader, "missing required field %s", "server.version");
        return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
    }
    if (!config->has_tls_enabled) {
        loader_set_error(loader, "missing required field %s", "server.tls.enabled");
        return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
    }
    if (!config->has_tls_server_cert_path) {
        loader_set_error(loader, "missing required field %s", "server.tls.server_cert_path");
        return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
    }
    if (!config->has_tls_server_key_path) {
        loader_set_error(loader, "missing required field %s", "server.tls.server_key_path");
        return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
    }
    if (!config->has_tls_trusted_client_ca_path) {
        loader_set_error(loader, "missing required field %s", "server.tls.trusted_client_ca_path");
        return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
    }
    if (!config->has_tls_require_client_cert) {
        loader_set_error(loader, "missing required field %s", "server.tls.require_client_cert");
        return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
    }
    if (access(config->tls_server_cert_path, R_OK) != 0) {
        loader_set_error(loader, "path not readable for %s: %s", "server.tls.server_cert_path",
                         config->tls_server_cert_path);
        return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
    }
    if (access(config->tls_server_key_path, R_OK) != 0) {
        loader_set_error(loader, "path not readable for %s: %s", "server.tls.server_key_path",
                         config->tls_server_key_path);
        return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
    }
    if (access(config->tls_trusted_client_ca_path, R_OK) != 0) {
        loader_set_error(loader, "path not readable for %s: %s",
                         "server.tls.trusted_client_ca_path", config->tls_trusted_client_ca_path);
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
    if (!config->has_device_priv_key_path) {
        loader_set_error(loader, "missing required field %s",
                         "device_identity.device_priv_key_path");
        return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
    }
    if (!config->has_device_pub_key_path) {
        loader_set_error(loader, "missing required field %s",
                         "device_identity.device_pub_key_path");
        return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
    }
    if (access(config->device_priv_key_path, R_OK) != 0) {
        loader_set_error(loader, "path not readable for %s: %s",
                         "device_identity.device_priv_key_path", config->device_priv_key_path);
        return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
    }
    if (access(config->device_pub_key_path, R_OK) != 0) {
        loader_set_error(loader, "path not readable for %s: %s",
                         "device_identity.device_pub_key_path", config->device_pub_key_path);
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

    // Semantic validation of capability items
    {
        enum vantaq_capability_list lists[] = {
            VANTAQ_CAPABILITY_SUPPORTED_CLAIMS, VANTAQ_CAPABILITY_SIGNATURE_ALGORITHMS,
            VANTAQ_CAPABILITY_EVIDENCE_FORMATS, VANTAQ_CAPABILITY_CHALLENGE_MODES,
            VANTAQ_CAPABILITY_STORAGE_MODES};
        size_t l, i;
        for (l = 0; l < 5; l++) {
            const struct vantaq_string_list *list_data = get_list_const(config, lists[l]);
            if (list_data == NULL) {
                continue;
            }
            for (i = 0; i < list_data->count; i++) {
                if (!is_valid_capability_item(lists[l], list_data->items[i])) {
                    loader_set_error(loader, "unsupported capability '%s' in list %d",
                                     list_data->items[i], (int)lists[l]);
                    return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
                }
            }
        }
    }

    if (config->has_allowed_subnets) {
        for (i = 0; i < config->allowed_subnets.count; i++) {
            if (!is_valid_ipv4_cidr(config->allowed_subnets.items[i])) {
                loader_set_error(loader, "invalid CIDR in %s", config->allowed_subnets.items[i]);
                return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
            }
        }
    }

    if (!config->has_verifiers || config->verifiers_count == 0) {
        loader_set_error(loader, "missing required field %s", "verifiers");
        return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
    }
    for (i = 0; i < config->verifiers_count; i++) {
        const struct vantaq_verifier_config *verifier = &config->verifiers[i];
        if (!verifier->has_verifier_id || verifier->verifier_id[0] == '\0') {
            loader_set_error(loader, "missing required field verifiers[%zu].verifier_id", i);
            return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
        }
        if (!verifier->has_cert_subject_cn || verifier->cert_subject_cn[0] == '\0') {
            loader_set_error(loader, "missing required field verifiers[%zu].cert_subject_cn", i);
            return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
        }
        if (!verifier->has_cert_san_uri || verifier->cert_san_uri[0] == '\0') {
            loader_set_error(loader, "missing required field verifiers[%zu].cert_san_uri", i);
            return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
        }
        if (!verifier->has_status || verifier->status[0] == '\0') {
            loader_set_error(loader, "missing required field verifiers[%zu].status", i);
            return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
        }
        if (strcmp(verifier->status, "active") != 0 && strcmp(verifier->status, "inactive") != 0) {
            loader_set_error(loader, "invalid verifier status verifiers[%zu].status: %s", i,
                             verifier->status);
            return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
        }
        if (!verifier->has_roles || verifier->roles.count == 0) {
            loader_set_error(loader, "missing required field verifiers[%zu].roles", i);
            return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
        }
        if (!verifier->has_allowed_apis || verifier->allowed_apis.count == 0) {
            loader_set_error(loader, "missing required field verifiers[%zu].allowed_apis", i);
            return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
        }

        for (j = i + 1; j < config->verifiers_count; j++) {
            if (strcmp(verifier->verifier_id, config->verifiers[j].verifier_id) == 0) {
                loader_set_error(loader, "duplicate verifier_id: %s", verifier->verifier_id);
                return VANTAQ_CONFIG_STATUS_VALIDATION_ERROR;
            }
        }
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

static bool mark_capability_seen(struct vantaq_runtime_config *config,
                                 enum vantaq_capability_list list) {
    bool *flag = NULL;

    switch (list) {
    case VANTAQ_CAPABILITY_SUPPORTED_CLAIMS:
        flag = &config->has_supported_claims;
        break;
    case VANTAQ_CAPABILITY_SIGNATURE_ALGORITHMS:
        flag = &config->has_signature_algorithms;
        break;
    case VANTAQ_CAPABILITY_EVIDENCE_FORMATS:
        flag = &config->has_evidence_formats;
        break;
    case VANTAQ_CAPABILITY_CHALLENGE_MODES:
        flag = &config->has_challenge_modes;
        break;
    case VANTAQ_CAPABILITY_STORAGE_MODES:
        flag = &config->has_storage_modes;
        break;
    default:
        return true;
    }

    if (flag != NULL && *flag) {
        return false;
    }

    if (flag != NULL) {
        *flag = true;
    }

    return true;
}

static enum vantaq_config_status parse_verifier_field(struct vantaq_config_loader *loader,
                                                      struct vantaq_verifier_config *verifier,
                                                      const char *key, const char *value,
                                                      bool *active_roles_list,
                                                      bool *active_allowed_apis_list) {
    enum vantaq_config_status rc;

    if (loader == NULL || verifier == NULL || key == NULL || value == NULL ||
        active_roles_list == NULL || active_allowed_apis_list == NULL) {
        return VANTAQ_CONFIG_STATUS_INVALID_ARGUMENT;
    }

    *active_roles_list        = false;
    *active_allowed_apis_list = false;

    if (strcmp(key, "verifier_id") == 0) {
        return copy_string_to_field(loader, "verifiers.verifier_id", value, verifier->verifier_id,
                                    sizeof(verifier->verifier_id), &verifier->has_verifier_id);
    }
    if (strcmp(key, "cert_subject_cn") == 0) {
        return copy_string_to_field(loader, "verifiers.cert_subject_cn", value,
                                    verifier->cert_subject_cn, sizeof(verifier->cert_subject_cn),
                                    &verifier->has_cert_subject_cn);
    }
    if (strcmp(key, "cert_san_uri") == 0) {
        return copy_string_to_field(loader, "verifiers.cert_san_uri", value, verifier->cert_san_uri,
                                    sizeof(verifier->cert_san_uri), &verifier->has_cert_san_uri);
    }
    if (strcmp(key, "status") == 0) {
        return copy_string_to_field(loader, "verifiers.status", value, verifier->status,
                                    sizeof(verifier->status), &verifier->has_status);
    }
    if (strcmp(key, "roles") == 0) {
        if (verifier->has_roles) {
            loader_set_error(loader, "duplicate field %s", "verifiers.roles");
            return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
        }
        verifier->has_roles = true;
        free_list(&verifier->roles);
        if (value[0] == '\0') {
            *active_roles_list = true;
            return VANTAQ_CONFIG_STATUS_OK;
        }
        rc = parse_inline_list(loader, value, &verifier->roles, "verifiers.roles");
        if (rc != VANTAQ_CONFIG_STATUS_OK) {
            return rc;
        }
        return VANTAQ_CONFIG_STATUS_OK;
    }
    if (strcmp(key, "allowed_apis") == 0) {
        if (verifier->has_allowed_apis) {
            loader_set_error(loader, "duplicate field %s", "verifiers.allowed_apis");
            return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
        }
        verifier->has_allowed_apis = true;
        free_list(&verifier->allowed_apis);
        if (value[0] == '\0') {
            *active_allowed_apis_list = true;
            return VANTAQ_CONFIG_STATUS_OK;
        }
        rc = parse_inline_list(loader, value, &verifier->allowed_apis, "verifiers.allowed_apis");
        if (rc != VANTAQ_CONFIG_STATUS_OK) {
            return rc;
        }
        return VANTAQ_CONFIG_STATUS_OK;
    }

    loader_set_error(loader, "unknown verifier field %s", key);
    return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
}

static enum vantaq_config_status parse_config_file(struct vantaq_config_loader *loader, FILE *fp,
                                                   struct vantaq_runtime_config *tmp) {
    char line[VANTAQ_MAX_LINE_LEN];
    enum vantaq_section section                = VANTAQ_SECTION_NONE;
    bool has_active_capability_list            = false;
    bool has_active_network_subnet_list        = false;
    bool has_active_verifier_roles_list        = false;
    bool has_active_verifier_allowed_apis_list = false;
    bool has_active_verifier                   = false;
    size_t active_verifier_index               = 0;
    enum vantaq_capability_list active_list    = VANTAQ_CAPABILITY_SUPPORTED_CLAIMS;

    VANTAQ_ZERO_STRUCT(line);

    while (fgets(line, sizeof(line), fp) != NULL) {
        size_t line_len = strlen(line);
        char *cursor;
        char *colon;
        char *key;
        char *value;
        size_t indent;
        enum vantaq_config_status rc;

        if (line_len > 0 && line[line_len - 1] != '\n' && !feof(fp)) {
            loader_set_error(loader, "line exceeds maximum length of %d characters",
                             VANTAQ_MAX_LINE_LEN - 1);
            return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
        }

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
            if (section == VANTAQ_SECTION_CAPABILITIES && indent == 4 &&
                has_active_capability_list) {
                rc = parse_list_item(loader, cursor + 1, get_list_mut(tmp, active_list),
                                     "capabilities list");
                if (rc != VANTAQ_CONFIG_STATUS_OK) {
                    return rc;
                }
                continue;
            }

            if (section == VANTAQ_SECTION_NETWORK_ACCESS && indent == 4 &&
                has_active_network_subnet_list) {
                rc = parse_list_item(loader, cursor + 1, &tmp->allowed_subnets,
                                     "network_access.allowed_subnets");
                if (rc != VANTAQ_CONFIG_STATUS_OK) {
                    return rc;
                }
                continue;
            }

            if (section == VANTAQ_SECTION_VERIFIERS && indent == 2) {
                char *verifier_cursor;
                char *verifier_colon;
                char *verifier_key;
                char *verifier_value;
                struct vantaq_verifier_config *verifier;

                if (tmp->verifiers_count >= VANTAQ_MAX_LIST_ITEMS) {
                    loader_set_error(loader, "too many verifiers");
                    return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
                }

                verifier = &tmp->verifiers[tmp->verifiers_count];
                VANTAQ_ZERO_STRUCT(*verifier);
                tmp->verifiers_count++;
                has_active_verifier                   = true;
                active_verifier_index                 = tmp->verifiers_count - 1;
                has_active_verifier_roles_list        = false;
                has_active_verifier_allowed_apis_list = false;

                verifier_cursor = trim(cursor + 1);
                if (verifier_cursor[0] == '\0') {
                    continue;
                }

                verifier_colon = strchr(verifier_cursor, ':');
                if (verifier_colon == NULL) {
                    loader_set_error(loader, "invalid verifier entry");
                    return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
                }

                *verifier_colon = '\0';
                verifier_key    = trim(verifier_cursor);
                verifier_value  = trim(verifier_colon + 1);

                rc = parse_verifier_field(loader, verifier, verifier_key, verifier_value,
                                          &has_active_verifier_roles_list,
                                          &has_active_verifier_allowed_apis_list);
                if (rc != VANTAQ_CONFIG_STATUS_OK) {
                    return rc;
                }
                continue;
            }

            if (section == VANTAQ_SECTION_VERIFIERS && indent == 6 && has_active_verifier) {
                struct vantaq_verifier_config *verifier = &tmp->verifiers[active_verifier_index];
                if (has_active_verifier_roles_list) {
                    rc = parse_list_item(loader, cursor + 1, &verifier->roles, "verifiers.roles");
                    if (rc != VANTAQ_CONFIG_STATUS_OK) {
                        return rc;
                    }
                    continue;
                }
                if (has_active_verifier_allowed_apis_list) {
                    rc = parse_list_item(loader, cursor + 1, &verifier->allowed_apis,
                                         "verifiers.allowed_apis");
                    if (rc != VANTAQ_CONFIG_STATUS_OK) {
                        return rc;
                    }
                    continue;
                }
            }

            loader_set_error(loader, "invalid list indentation");
            return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
        }

        has_active_capability_list            = false;
        has_active_network_subnet_list        = false;
        has_active_verifier_roles_list        = false;
        has_active_verifier_allowed_apis_list = false;

        colon = strchr(cursor, ':');
        if (colon == NULL) {
            loader_set_error(loader, "missing ':' in yaml line");
            return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
        }

        *colon = '\0';
        key    = trim(cursor);
        value  = trim(colon + 1);

        if (indent == 0) {
            if (value[0] != '\0') {
                loader_set_error(loader, "top-level key must be an object");
                return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
            }

            if (strcmp(key, "service") == 0) {
                loader_set_error(loader, "unknown top-level key %s", key);
                return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
            }
            if (strcmp(key, "server") == 0) {
                section                        = VANTAQ_SECTION_SERVER;
                has_active_capability_list     = false;
                has_active_network_subnet_list = false;
                continue;
            }
            if (strcmp(key, "device_identity") == 0) {
                section                        = VANTAQ_SECTION_DEVICE_IDENTITY;
                has_active_capability_list     = false;
                has_active_network_subnet_list = false;
                continue;
            }
            if (strcmp(key, "capabilities") == 0) {
                section                        = VANTAQ_SECTION_CAPABILITIES;
                has_active_capability_list     = false;
                has_active_network_subnet_list = false;
                continue;
            }
            if (strcmp(key, "network_access") == 0) {
                section                        = VANTAQ_SECTION_NETWORK_ACCESS;
                has_active_capability_list     = false;
                has_active_network_subnet_list = false;
                continue;
            }
            if (strcmp(key, "audit") == 0) {
                section                        = VANTAQ_SECTION_AUDIT;
                has_active_capability_list     = false;
                has_active_network_subnet_list = false;
                continue;
            }
            if (strcmp(key, "verifiers") == 0) {
                section                        = VANTAQ_SECTION_VERIFIERS;
                has_active_verifier            = false;
                tmp->has_verifiers             = true;
                has_active_capability_list     = false;
                has_active_network_subnet_list = false;
                continue;
            }
            if (strcmp(key, "challenge") == 0) {
                section                        = VANTAQ_SECTION_CHALLENGE;
                has_active_capability_list     = false;
                has_active_network_subnet_list = false;
                continue;
            }

            loader_set_error(loader, "unknown top-level key %s", key);
            return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
        }

        if (section == VANTAQ_SECTION_SERVER_TLS && indent == 2) {
            section = VANTAQ_SECTION_SERVER;
        }

        if (section == VANTAQ_SECTION_SERVER_TLS && indent != 4) {
            loader_set_error(loader, "unsupported yaml indentation");
            return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
        }
        if (section != VANTAQ_SECTION_SERVER_TLS && section != VANTAQ_SECTION_VERIFIERS &&
            indent != 2) {
            loader_set_error(loader, "unsupported yaml indentation");
            return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
        }

        if (section == VANTAQ_SECTION_SERVER) {
            if (strcmp(key, "listen_address") == 0) {
                rc = copy_string_to_field(
                    loader, "server.listen_address", value, tmp->service_listen_host,
                    sizeof(tmp->service_listen_host), &tmp->has_service_listen_host);
                if (rc != VANTAQ_CONFIG_STATUS_OK) {
                    return rc;
                }
                continue;
            }
            if (strcmp(key, "listen_port") == 0) {
                rc = parse_int(loader, "server.listen_port", value, &tmp->service_listen_port,
                               &tmp->has_service_listen_port);
                if (rc != VANTAQ_CONFIG_STATUS_OK) {
                    return rc;
                }
                continue;
            }
            if (strcmp(key, "version") == 0) {
                rc = copy_string_to_field(loader, "server.version", value, tmp->service_version,
                                          sizeof(tmp->service_version), &tmp->has_service_version);
                if (rc != VANTAQ_CONFIG_STATUS_OK) {
                    return rc;
                }
                continue;
            }
            if (strcmp(key, "tls") == 0) {
                if (value[0] != '\0') {
                    loader_set_error(loader, "server.tls must be an object");
                    return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
                }
                section = VANTAQ_SECTION_SERVER_TLS;
                continue;
            }

            loader_set_error(loader, "unknown server field %s", key);
            return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
        }

        if (section == VANTAQ_SECTION_SERVER_TLS) {
            if (strcmp(key, "enabled") == 0) {
                rc = parse_bool(loader, "server.tls.enabled", value, &tmp->tls_enabled,
                                &tmp->has_tls_enabled);
                if (rc != VANTAQ_CONFIG_STATUS_OK) {
                    return rc;
                }
                continue;
            }
            if (strcmp(key, "server_cert_path") == 0) {
                rc = copy_string_to_field(
                    loader, "server.tls.server_cert_path", value, tmp->tls_server_cert_path,
                    sizeof(tmp->tls_server_cert_path), &tmp->has_tls_server_cert_path);
                if (rc != VANTAQ_CONFIG_STATUS_OK) {
                    return rc;
                }
                continue;
            }
            if (strcmp(key, "server_key_path") == 0) {
                rc = copy_string_to_field(
                    loader, "server.tls.server_key_path", value, tmp->tls_server_key_path,
                    sizeof(tmp->tls_server_key_path), &tmp->has_tls_server_key_path);
                if (rc != VANTAQ_CONFIG_STATUS_OK) {
                    return rc;
                }
                continue;
            }
            if (strcmp(key, "trusted_client_ca_path") == 0) {
                rc = copy_string_to_field(loader, "server.tls.trusted_client_ca_path", value,
                                          tmp->tls_trusted_client_ca_path,
                                          sizeof(tmp->tls_trusted_client_ca_path),
                                          &tmp->has_tls_trusted_client_ca_path);
                if (rc != VANTAQ_CONFIG_STATUS_OK) {
                    return rc;
                }
                continue;
            }
            if (strcmp(key, "require_client_cert") == 0) {
                rc = parse_bool(loader, "server.tls.require_client_cert", value,
                                &tmp->tls_require_client_cert, &tmp->has_tls_require_client_cert);
                if (rc != VANTAQ_CONFIG_STATUS_OK) {
                    return rc;
                }
                continue;
            }

            loader_set_error(loader, "unknown server.tls field %s", key);
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
            if (strcmp(key, "device_priv_key_path") == 0) {
                rc = copy_string_to_field(loader, "device_identity.device_priv_key_path", value,
                                          tmp->device_priv_key_path,
                                          sizeof(tmp->device_priv_key_path),
                                          &tmp->has_device_priv_key_path);
                if (rc != VANTAQ_CONFIG_STATUS_OK) {
                    return rc;
                }
                continue;
            }
            if (strcmp(key, "device_pub_key_path") == 0) {
                rc = copy_string_to_field(
                    loader, "device_identity.device_pub_key_path", value, tmp->device_pub_key_path,
                    sizeof(tmp->device_pub_key_path), &tmp->has_device_pub_key_path);
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

            if (!mark_capability_seen(tmp, active_list)) {
                loader_set_error(loader, "duplicate capability field %s", key);
                return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
            }

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

        if (section == VANTAQ_SECTION_NETWORK_ACCESS) {
            if (strcmp(key, "allowed_subnets") == 0) {
                if (tmp->has_allowed_subnets) {
                    loader_set_error(loader, "duplicate field network_access.allowed_subnets");
                    return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
                }
                tmp->has_allowed_subnets = true;
                free_list(&tmp->allowed_subnets);

                if (value[0] == '\0') {
                    has_active_network_subnet_list = true;
                    continue;
                }

                rc = parse_inline_list(loader, value, &tmp->allowed_subnets,
                                       "network_access.allowed_subnets");
                if (rc != VANTAQ_CONFIG_STATUS_OK) {
                    return rc;
                }
                continue;
            }

            if (strcmp(key, "dev_allow_all_networks") == 0) {
                rc = parse_bool(loader, "network_access.dev_allow_all_networks", value,
                                &tmp->dev_allow_all_networks, &tmp->has_dev_allow_all_networks);
                if (rc != VANTAQ_CONFIG_STATUS_OK) {
                    return rc;
                }
                continue;
            }

            loader_set_error(loader, "unknown network_access field %s", key);
            return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
        }

        if (section == VANTAQ_SECTION_AUDIT) {
            if (strcmp(key, "max_bytes") == 0) {
                rc = parse_size_t(loader, "audit.max_bytes", value, &tmp->audit_log_max_bytes,
                                  &tmp->has_audit_log_max_bytes);
                if (rc != VANTAQ_CONFIG_STATUS_OK) {
                    return rc;
                }
                continue;
            }
            if (strcmp(key, "path") == 0) {
                rc = copy_string_to_field(loader, "audit.path", value, tmp->audit_log_path,
                                          sizeof(tmp->audit_log_path), &tmp->has_audit_log_path);
                if (rc != VANTAQ_CONFIG_STATUS_OK) {
                    return rc;
                }
                continue;
            }

            loader_set_error(loader, "unknown audit field %s", key);
            return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
        }

        if (section == VANTAQ_SECTION_CHALLENGE) {
            if (strcmp(key, "ttl_seconds") == 0) {
                rc = parse_size_t(loader, "challenge.ttl_seconds", value,
                                  &tmp->challenge_ttl_seconds, &tmp->has_challenge_ttl_seconds);
                if (rc != VANTAQ_CONFIG_STATUS_OK) {
                    return rc;
                }
                continue;
            }
            if (strcmp(key, "max_global") == 0) {
                rc = parse_size_t(loader, "challenge.max_global", value, &tmp->challenge_max_global,
                                  &tmp->has_challenge_max_global);
                if (rc != VANTAQ_CONFIG_STATUS_OK) {
                    return rc;
                }
                continue;
            }
            if (strcmp(key, "max_per_verifier") == 0) {
                rc = parse_size_t(loader, "challenge.max_per_verifier", value,
                                  &tmp->challenge_max_per_verifier,
                                  &tmp->has_challenge_max_per_verifier);
                if (rc != VANTAQ_CONFIG_STATUS_OK) {
                    return rc;
                }
                continue;
            }

            loader_set_error(loader, "unknown challenge field %s", key);
            return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
        }

        if (section == VANTAQ_SECTION_VERIFIERS) {
            struct vantaq_verifier_config *verifier;
            if (indent != 4 || !has_active_verifier ||
                active_verifier_index >= tmp->verifiers_count) {
                loader_set_error(loader, "invalid verifier field indentation");
                return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
            }

            verifier = &tmp->verifiers[active_verifier_index];
            rc = parse_verifier_field(loader, verifier, key, value, &has_active_verifier_roles_list,
                                      &has_active_verifier_allowed_apis_list);
            if (rc != VANTAQ_CONFIG_STATUS_OK) {
                return rc;
            }
            continue;
        }

        loader_set_error(loader, "field found outside section");
        return VANTAQ_CONFIG_STATUS_PARSE_ERROR;
    }

    if (ferror(fp)) {
        loader_set_error(loader, "failed to read config file");
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
    tmp.cbSize = sizeof(tmp);

    if (path == NULL || path[0] == '\0') {
        path = VANTAQ_DEFAULT_CONFIG_PATH;
    }

    if (strlen(path) >= sizeof(resolved_path)) {
        loader_set_error(loader, "config path too long");
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
    if (config == NULL ||
        config->cbSize < offsetof(struct vantaq_runtime_config, service_listen_host) +
                             sizeof(config->service_listen_host)) {
        return "";
    }
    return config->service_listen_host;
}

int vantaq_runtime_service_listen_port(const struct vantaq_runtime_config *config) {
    if (config == NULL ||
        config->cbSize < offsetof(struct vantaq_runtime_config, service_listen_port) +
                             sizeof(config->service_listen_port)) {
        return 0;
    }
    return config->service_listen_port;
}

const char *vantaq_runtime_service_version(const struct vantaq_runtime_config *config) {
    if (config == NULL || config->cbSize < offsetof(struct vantaq_runtime_config, service_version) +
                                               sizeof(config->service_version)) {
        return "";
    }
    return config->service_version;
}

bool vantaq_runtime_tls_enabled(const struct vantaq_runtime_config *config) {
    if (config == NULL || config->cbSize < offsetof(struct vantaq_runtime_config, tls_enabled) +
                                               sizeof(config->tls_enabled)) {
        return false;
    }
    return config->tls_enabled;
}

const char *vantaq_runtime_tls_server_cert_path(const struct vantaq_runtime_config *config) {
    if (config == NULL ||
        config->cbSize < offsetof(struct vantaq_runtime_config, tls_server_cert_path) +
                             sizeof(config->tls_server_cert_path)) {
        return "";
    }
    return config->tls_server_cert_path;
}

const char *vantaq_runtime_tls_server_key_path(const struct vantaq_runtime_config *config) {
    if (config == NULL ||
        config->cbSize < offsetof(struct vantaq_runtime_config, tls_server_key_path) +
                             sizeof(config->tls_server_key_path)) {
        return "";
    }
    return config->tls_server_key_path;
}

const char *vantaq_runtime_tls_trusted_client_ca_path(const struct vantaq_runtime_config *config) {
    if (config == NULL ||
        config->cbSize < offsetof(struct vantaq_runtime_config, tls_trusted_client_ca_path) +
                             sizeof(config->tls_trusted_client_ca_path)) {
        return "";
    }
    return config->tls_trusted_client_ca_path;
}

bool vantaq_runtime_tls_require_client_cert(const struct vantaq_runtime_config *config) {
    if (config == NULL ||
        config->cbSize < offsetof(struct vantaq_runtime_config, tls_require_client_cert) +
                             sizeof(config->tls_require_client_cert)) {
        return false;
    }
    return config->tls_require_client_cert;
}

const char *vantaq_runtime_device_id(const struct vantaq_runtime_config *config) {
    if (config == NULL || config->cbSize < offsetof(struct vantaq_runtime_config, device_id) +
                                               sizeof(config->device_id)) {
        return "";
    }
    return config->device_id;
}

const char *vantaq_runtime_device_model(const struct vantaq_runtime_config *config) {
    if (config == NULL ||
        config->cbSize < offsetof(struct vantaq_runtime_config, model) + sizeof(config->model)) {
        return "";
    }
    return config->model;
}

const char *vantaq_runtime_device_serial_number(const struct vantaq_runtime_config *config) {
    if (config == NULL || config->cbSize < offsetof(struct vantaq_runtime_config, serial_number) +
                                               sizeof(config->serial_number)) {
        return "";
    }
    return config->serial_number;
}

const char *vantaq_runtime_device_manufacturer(const struct vantaq_runtime_config *config) {
    if (config == NULL || config->cbSize < offsetof(struct vantaq_runtime_config, manufacturer) +
                                               sizeof(config->manufacturer)) {
        return "";
    }
    return config->manufacturer;
}

const char *vantaq_runtime_device_firmware_version(const struct vantaq_runtime_config *config) {
    if (config == NULL ||
        config->cbSize < offsetof(struct vantaq_runtime_config, firmware_version) +
                             sizeof(config->firmware_version)) {
        return "";
    }
    return config->firmware_version;
}

const char *vantaq_runtime_device_priv_key_path(const struct vantaq_runtime_config *config) {
    if (config == NULL ||
        config->cbSize < offsetof(struct vantaq_runtime_config, device_priv_key_path) +
                             sizeof(config->device_priv_key_path)) {
        return "";
    }
    return config->device_priv_key_path;
}

const char *vantaq_runtime_device_pub_key_path(const struct vantaq_runtime_config *config) {
    if (config == NULL ||
        config->cbSize < offsetof(struct vantaq_runtime_config, device_pub_key_path) +
                             sizeof(config->device_pub_key_path)) {
        return "";
    }
    return config->device_pub_key_path;
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

size_t vantaq_runtime_allowed_subnet_count(const struct vantaq_runtime_config *config) {
    if (config == NULL || config->cbSize < offsetof(struct vantaq_runtime_config, allowed_subnets) +
                                               sizeof(config->allowed_subnets)) {
        return 0;
    }
    return config->allowed_subnets.count;
}

const char *vantaq_runtime_allowed_subnet_item(const struct vantaq_runtime_config *config,
                                               size_t index) {
    if (config == NULL || config->cbSize < offsetof(struct vantaq_runtime_config, allowed_subnets) +
                                               sizeof(config->allowed_subnets)) {
        return NULL;
    }

    if (index >= config->allowed_subnets.count) {
        return NULL;
    }

    return config->allowed_subnets.items[index];
}

bool vantaq_runtime_dev_allow_all_networks(const struct vantaq_runtime_config *config) {
    if (config == NULL ||
        config->cbSize < offsetof(struct vantaq_runtime_config, dev_allow_all_networks) +
                             sizeof(config->dev_allow_all_networks)) {
        return false;
    }
    return config->dev_allow_all_networks;
}

size_t vantaq_runtime_audit_log_max_bytes(const struct vantaq_runtime_config *config) {
    if (config == NULL ||
        config->cbSize < offsetof(struct vantaq_runtime_config, audit_log_max_bytes) +
                             sizeof(config->audit_log_max_bytes)) {
        return 0;
    }
    return config->audit_log_max_bytes;
}

const char *vantaq_runtime_audit_log_path(const struct vantaq_runtime_config *config) {
    if (config == NULL || config->cbSize < offsetof(struct vantaq_runtime_config, audit_log_path) +
                                               sizeof(config->audit_log_path)) {
        return "";
    }
    return config->audit_log_path;
}

size_t vantaq_runtime_verifier_count(const struct vantaq_runtime_config *config) {
    if (config == NULL || config->cbSize < offsetof(struct vantaq_runtime_config, verifiers_count) +
                                               sizeof(config->verifiers_count)) {
        return 0;
    }
    return config->verifiers_count;
}

const char *vantaq_runtime_verifier_id(const struct vantaq_runtime_config *config, size_t index) {
    if (config == NULL || index >= vantaq_runtime_verifier_count(config)) {
        return NULL;
    }
    return config->verifiers[index].verifier_id;
}

const char *vantaq_runtime_verifier_cert_subject_cn(const struct vantaq_runtime_config *config,
                                                    size_t index) {
    if (config == NULL || index >= vantaq_runtime_verifier_count(config)) {
        return NULL;
    }
    return config->verifiers[index].cert_subject_cn;
}

const char *vantaq_runtime_verifier_cert_san_uri(const struct vantaq_runtime_config *config,
                                                 size_t index) {
    if (config == NULL || index >= vantaq_runtime_verifier_count(config)) {
        return NULL;
    }
    return config->verifiers[index].cert_san_uri;
}

const char *vantaq_runtime_verifier_status(const struct vantaq_runtime_config *config,
                                           size_t index) {
    if (config == NULL || index >= vantaq_runtime_verifier_count(config)) {
        return NULL;
    }
    return config->verifiers[index].status;
}

size_t vantaq_runtime_verifier_role_count(const struct vantaq_runtime_config *config,
                                          size_t index) {
    if (config == NULL || index >= vantaq_runtime_verifier_count(config)) {
        return 0;
    }
    return config->verifiers[index].roles.count;
}

const char *vantaq_runtime_verifier_role_item(const struct vantaq_runtime_config *config,
                                              size_t verifier_index, size_t role_index) {
    if (config == NULL || verifier_index >= vantaq_runtime_verifier_count(config)) {
        return NULL;
    }
    if (role_index >= config->verifiers[verifier_index].roles.count) {
        return NULL;
    }
    return config->verifiers[verifier_index].roles.items[role_index];
}

size_t vantaq_runtime_verifier_allowed_api_count(const struct vantaq_runtime_config *config,
                                                 size_t index) {
    if (config == NULL || index >= vantaq_runtime_verifier_count(config)) {
        return 0;
    }
    return config->verifiers[index].allowed_apis.count;
}

const char *vantaq_runtime_verifier_allowed_api_item(const struct vantaq_runtime_config *config,
                                                     size_t verifier_index, size_t api_index) {
    if (config == NULL || verifier_index >= vantaq_runtime_verifier_count(config)) {
        return NULL;
    }
    if (api_index >= config->verifiers[verifier_index].allowed_apis.count) {
        return NULL;
    }
    return config->verifiers[verifier_index].allowed_apis.items[api_index];
}

size_t vantaq_runtime_challenge_ttl_seconds(const struct vantaq_runtime_config *config) {
    return (config && config->has_challenge_ttl_seconds) ? config->challenge_ttl_seconds : 30;
}

size_t vantaq_runtime_challenge_max_global(const struct vantaq_runtime_config *config) {
    return (config && config->has_challenge_max_global) ? config->challenge_max_global : 1000;
}

size_t vantaq_runtime_challenge_max_per_verifier(const struct vantaq_runtime_config *config) {
    return (config && config->has_challenge_max_per_verifier) ? config->challenge_max_per_verifier
                                                              : 100;
}
