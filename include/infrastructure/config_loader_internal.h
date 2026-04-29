// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_INFRASTRUCTURE_CONFIG_LOADER_INTERNAL_H
#define VANTAQ_INFRASTRUCTURE_CONFIG_LOADER_INTERNAL_H

#include "infrastructure/config_loader.h"
#include <stdatomic.h>

struct vantaq_runtime_config {
    size_t cbSize;
    _Atomic int ref_count;

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
    char measurement_firmware_path[VANTAQ_MAX_FIELD_LEN];
    char measurement_security_config_path[VANTAQ_MAX_FIELD_LEN];
    char measurement_agent_binary_path[VANTAQ_MAX_FIELD_LEN];
    char measurement_boot_state_path[VANTAQ_MAX_FIELD_LEN];
    size_t measurement_max_file_bytes;

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
    bool has_measurement_firmware_path;
    bool has_measurement_security_config_path;
    bool has_measurement_agent_binary_path;
    bool has_measurement_boot_state_path;
    bool has_measurement_max_file_bytes;
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

#endif
