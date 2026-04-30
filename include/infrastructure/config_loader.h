// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_INFRASTRUCTURE_CONFIG_LOADER_H
#define VANTAQ_INFRASTRUCTURE_CONFIG_LOADER_H

#include <stddef.h>

#define VANTAQ_DEFAULT_CONFIG_PATH "/etc/vantaqd/vantaqd.yaml"
#define VANTAQ_MAX_LIST_ITEMS 64
#define VANTAQ_MAX_FIELD_LEN 128
#define VANTAQ_MEASUREMENT_DEFAULT_FIRMWARE_PATH "/opt/vantaqd/firmware/current.bin"
#define VANTAQ_MEASUREMENT_DEFAULT_SECURITY_CONFIG_PATH "/etc/vantaqd/security.conf"
#define VANTAQ_MEASUREMENT_DEFAULT_AGENT_BINARY_PATH "/usr/local/bin/vantaqd"
#define VANTAQ_MEASUREMENT_DEFAULT_BOOT_STATE_PATH "/run/vantaqd/boot_state"
#define VANTAQ_MEASUREMENT_DEFAULT_MAX_FILE_BYTES (16U * 1024U * 1024U)
#define VANTAQ_EVIDENCE_STORE_DEFAULT_FILE_PATH "/var/lib/vantaqd/evidence.ring"
#define VANTAQ_EVIDENCE_STORE_DEFAULT_MAX_RECORDS 1024U
#define VANTAQ_EVIDENCE_STORE_DEFAULT_MAX_RECORD_BYTES 8192U
#define VANTAQ_EVIDENCE_STORE_DEFAULT_FSYNC_ON_APPEND 1

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

struct vantaq_runtime_config;

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
enum vantaq_config_status vantaq_config_loader_load_fd(struct vantaq_config_loader *loader, int fd,
                                                        const char *source_name);
const char *vantaq_config_loader_last_error(const struct vantaq_config_loader *loader);
const struct vantaq_runtime_config *
vantaq_config_loader_config(const struct vantaq_config_loader *loader);

/**
 * @brief Release a reference to a configuration object obtained from the loader.
 */
void vantaq_config_release(const struct vantaq_runtime_config *config);

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
const char *vantaq_runtime_measurement_firmware_path(const struct vantaq_runtime_config *config);
const char *
vantaq_runtime_measurement_security_config_path(const struct vantaq_runtime_config *config);
const char *vantaq_runtime_measurement_agent_binary_path(const struct vantaq_runtime_config *config);
const char *vantaq_runtime_measurement_boot_state_path(const struct vantaq_runtime_config *config);
size_t vantaq_runtime_measurement_max_file_bytes(const struct vantaq_runtime_config *config);

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
const char *vantaq_runtime_evidence_store_file_path(const struct vantaq_runtime_config *config);
size_t vantaq_runtime_evidence_store_max_records(const struct vantaq_runtime_config *config);
size_t vantaq_runtime_evidence_store_max_record_bytes(const struct vantaq_runtime_config *config);
bool vantaq_runtime_evidence_store_fsync_on_append(const struct vantaq_runtime_config *config);

#endif
