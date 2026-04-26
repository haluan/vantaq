// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_INFRASTRUCTURE_CONFIG_LOADER_H
#define VANTAQ_INFRASTRUCTURE_CONFIG_LOADER_H

#include <stddef.h>

#define VANTAQ_DEFAULT_CONFIG_PATH "/etc/vantaqd/vantaqd.yaml"

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
struct vantaq_runtime_config;

struct vantaq_config_loader *vantaq_config_loader_create(void);
void vantaq_config_loader_destroy(struct vantaq_config_loader *loader);

enum vantaq_config_status vantaq_config_loader_load(struct vantaq_config_loader *loader, const char *path);
const char *vantaq_config_loader_last_error(const struct vantaq_config_loader *loader);
const struct vantaq_runtime_config *vantaq_config_loader_config(const struct vantaq_config_loader *loader);

const char *vantaq_runtime_service_listen_host(const struct vantaq_runtime_config *config);
int vantaq_runtime_service_listen_port(const struct vantaq_runtime_config *config);
const char *vantaq_runtime_service_version(const struct vantaq_runtime_config *config);

const char *vantaq_runtime_device_id(const struct vantaq_runtime_config *config);
const char *vantaq_runtime_device_model(const struct vantaq_runtime_config *config);
const char *vantaq_runtime_device_serial_number(const struct vantaq_runtime_config *config);
const char *vantaq_runtime_device_manufacturer(const struct vantaq_runtime_config *config);
const char *vantaq_runtime_device_firmware_version(const struct vantaq_runtime_config *config);

size_t vantaq_runtime_capability_count(const struct vantaq_runtime_config *config, enum vantaq_capability_list list);
const char *vantaq_runtime_capability_item(const struct vantaq_runtime_config *config, enum vantaq_capability_list list,
                                           size_t index);
size_t vantaq_runtime_allowed_subnet_count(const struct vantaq_runtime_config *config);
const char *vantaq_runtime_allowed_subnet_item(const struct vantaq_runtime_config *config, size_t index);
int vantaq_runtime_dev_allow_all_networks(const struct vantaq_runtime_config *config);

#endif
