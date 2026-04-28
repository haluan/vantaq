// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_INFRASTRUCTURE_CONFIG_LOADER_H
#define VANTAQ_INFRASTRUCTURE_CONFIG_LOADER_H

#include <stddef.h>

#define VANTAQ_DEFAULT_CONFIG_PATH "/etc/vantaqd/vantaqd.yaml"
#define VANTAQ_MAX_LIST_ITEMS 64
#define VANTAQ_MAX_FIELD_LEN 128

#include <stdbool.h>

struct vantaq_string_list {
    char *items[VANTAQ_MAX_LIST_ITEMS];
    size_t count;
};

struct vantaq_verifier_config {
    char verifier_id[VANTAQ_MAX_FIELD_LEN];
    char cert_subject_cn[VANTAQ_MAX_FIELD_LEN];
    char cert_san_uri[VANTAQ_MAX_FIELD_LEN];
    char status[VANTAQ_MAX_FIELD_LEN];
    struct vantaq_string_list roles;
    struct vantaq_string_list allowed_apis;

    bool has_verifier_id;
    bool has_cert_subject_cn;
    bool has_cert_san_uri;
    bool has_status;
    bool has_roles;
    bool has_allowed_apis;
};

struct vantaq_runtime_config {
    size_t cbSize;

    char service_listen_host[VANTAQ_MAX_FIELD_LEN];
    int service_listen_port;
    char service_version[VANTAQ_MAX_FIELD_LEN];
    bool tls_enabled;
    char tls_server_cert_path[VANTAQ_MAX_FIELD_LEN];
    char tls_server_key_path[VANTAQ_MAX_FIELD_LEN];
    char tls_trusted_client_ca_path[VANTAQ_MAX_FIELD_LEN];
    bool tls_require_client_cert;

    char device_id[VANTAQ_MAX_FIELD_LEN];
    char model[VANTAQ_MAX_FIELD_LEN];
    char serial_number[VANTAQ_MAX_FIELD_LEN];
    char manufacturer[VANTAQ_MAX_FIELD_LEN];
    char firmware_version[VANTAQ_MAX_FIELD_LEN];
    char device_priv_key_path[VANTAQ_MAX_FIELD_LEN];
    char device_pub_key_path[VANTAQ_MAX_FIELD_LEN];

    struct vantaq_string_list supported_claims;
    struct vantaq_string_list signature_algorithms;
    struct vantaq_string_list evidence_formats;
    struct vantaq_string_list challenge_modes;
    struct vantaq_string_list storage_modes;
    struct vantaq_string_list allowed_subnets;
    bool dev_allow_all_networks;
    size_t audit_log_max_bytes;
    char audit_log_path[VANTAQ_MAX_FIELD_LEN];
    struct vantaq_verifier_config verifiers[VANTAQ_MAX_LIST_ITEMS];
    size_t verifiers_count;
    size_t challenge_ttl_seconds;
    size_t challenge_max_global;
    size_t challenge_max_per_verifier;

    bool has_service_listen_host;
    bool has_service_listen_port;
    bool has_service_version;
    bool has_tls_enabled;
    bool has_tls_server_cert_path;
    bool has_tls_server_key_path;
    bool has_tls_trusted_client_ca_path;
    bool has_tls_require_client_cert;
    bool has_device_id;
    bool has_model;
    bool has_serial_number;
    bool has_manufacturer;
    bool has_firmware_version;
    bool has_device_priv_key_path;
    bool has_device_pub_key_path;
    bool has_supported_claims;
    bool has_signature_algorithms;
    bool has_evidence_formats;
    bool has_challenge_modes;
    bool has_storage_modes;
    bool has_allowed_subnets;
    bool has_dev_allow_all_networks;
    bool has_audit_log_max_bytes;
    bool has_audit_log_path;
    bool has_verifiers;
    bool has_challenge_ttl_seconds;
    bool has_challenge_max_global;
    bool has_challenge_max_per_verifier;
};

enum vantaq_config_status {
    VANTAQ_CONFIG_STATUS_OK = 0,
    VANTAQ_CONFIG_STATUS_INVALID_ARGUMENT,
    VANTAQ_CONFIG_STATUS_IO_ERROR,
    VANTAQ_CONFIG_STATUS_PARSE_ERROR,
    VANTAQ_CONFIG_STATUS_VALIDATION_ERROR,
};

enum vantaq_capability_list {
    VANTAQ_CAPABILITY_SUPPORTED_CLAIMS = 0,
    VANTAQ_CAPABILITY_SIGNATURE_ALGORITHMS,
    VANTAQ_CAPABILITY_EVIDENCE_FORMATS,
    VANTAQ_CAPABILITY_CHALLENGE_MODES,
    VANTAQ_CAPABILITY_STORAGE_MODES,
};

enum vantaq_network_subnet_list {
    VANTAQ_NETWORK_ALLOWED_SUBNETS = 0,
};

struct vantaq_config_loader;

struct vantaq_config_loader *vantaq_config_loader_create(void);
void vantaq_config_loader_destroy(struct vantaq_config_loader *loader);

enum vantaq_config_status vantaq_config_loader_load(struct vantaq_config_loader *loader,
                                                    const char *path);
const char *vantaq_config_loader_last_error(const struct vantaq_config_loader *loader);
const struct vantaq_runtime_config *
vantaq_config_loader_config(const struct vantaq_config_loader *loader);

const char *vantaq_runtime_service_listen_host(const struct vantaq_runtime_config *config);
int vantaq_runtime_service_listen_port(const struct vantaq_runtime_config *config);
const char *vantaq_runtime_service_version(const struct vantaq_runtime_config *config);
bool vantaq_runtime_tls_enabled(const struct vantaq_runtime_config *config);
const char *vantaq_runtime_tls_server_cert_path(const struct vantaq_runtime_config *config);
const char *vantaq_runtime_tls_server_key_path(const struct vantaq_runtime_config *config);
const char *vantaq_runtime_tls_trusted_client_ca_path(const struct vantaq_runtime_config *config);
bool vantaq_runtime_tls_require_client_cert(const struct vantaq_runtime_config *config);

const char *vantaq_runtime_device_id(const struct vantaq_runtime_config *config);
const char *vantaq_runtime_device_model(const struct vantaq_runtime_config *config);
const char *vantaq_runtime_device_serial_number(const struct vantaq_runtime_config *config);
const char *vantaq_runtime_device_manufacturer(const struct vantaq_runtime_config *config);
const char *vantaq_runtime_device_firmware_version(const struct vantaq_runtime_config *config);
const char *vantaq_runtime_device_priv_key_path(const struct vantaq_runtime_config *config);
const char *vantaq_runtime_device_pub_key_path(const struct vantaq_runtime_config *config);

size_t vantaq_runtime_capability_count(const struct vantaq_runtime_config *config,
                                       enum vantaq_capability_list list);
const char *vantaq_runtime_capability_item(const struct vantaq_runtime_config *config,
                                           enum vantaq_capability_list list, size_t index);
size_t vantaq_runtime_allowed_subnet_count(const struct vantaq_runtime_config *config);
const char *vantaq_runtime_allowed_subnet_item(const struct vantaq_runtime_config *config,
                                               size_t index);
bool vantaq_runtime_dev_allow_all_networks(const struct vantaq_runtime_config *config);
size_t vantaq_runtime_audit_log_max_bytes(const struct vantaq_runtime_config *config);
const char *vantaq_runtime_audit_log_path(const struct vantaq_runtime_config *config);
size_t vantaq_runtime_verifier_count(const struct vantaq_runtime_config *config);
const char *vantaq_runtime_verifier_id(const struct vantaq_runtime_config *config, size_t index);
const char *vantaq_runtime_verifier_cert_subject_cn(const struct vantaq_runtime_config *config,
                                                    size_t index);
const char *vantaq_runtime_verifier_cert_san_uri(const struct vantaq_runtime_config *config,
                                                 size_t index);
const char *vantaq_runtime_verifier_status(const struct vantaq_runtime_config *config, size_t index);
size_t vantaq_runtime_verifier_role_count(const struct vantaq_runtime_config *config, size_t index);
const char *vantaq_runtime_verifier_role_item(const struct vantaq_runtime_config *config,
                                              size_t verifier_index, size_t role_index);
size_t vantaq_runtime_verifier_allowed_api_count(const struct vantaq_runtime_config *config,
                                                 size_t index);
const char *vantaq_runtime_verifier_allowed_api_item(const struct vantaq_runtime_config *config,
                                                     size_t verifier_index, size_t api_index);
size_t vantaq_runtime_challenge_ttl_seconds(const struct vantaq_runtime_config *config);
size_t vantaq_runtime_challenge_max_global(const struct vantaq_runtime_config *config);
size_t vantaq_runtime_challenge_max_per_verifier(const struct vantaq_runtime_config *config);

#endif
