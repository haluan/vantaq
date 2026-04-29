// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/config_loader.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>

#define YAML_SERVER_VALID                                                                          \
    "server:\n"                                                                                    \
    "  listen_address: 0.0.0.0\n"                                                                  \
    "  listen_port: 8080\n"                                                                        \
    "  version: 0.1.0\n"                                                                           \
    "  tls:\n"                                                                                     \
    "    enabled: false\n"                                                                         \
    "    server_cert_path: /etc/hosts\n"                                                           \
    "    server_key_path: /etc/hosts\n"                                                            \
    "    trusted_client_ca_path: /etc/hosts\n"                                                     \
    "    require_client_cert: true\n"

#define YAML_SERVER_MISSING_LISTEN_PORT                                                            \
    "server:\n"                                                                                    \
    "  listen_address: 0.0.0.0\n"                                                                  \
    "  version: 0.1.0\n"                                                                           \
    "  tls:\n"                                                                                     \
    "    enabled: false\n"                                                                         \
    "    server_cert_path: /etc/hosts\n"                                                           \
    "    server_key_path: /etc/hosts\n"                                                            \
    "    trusted_client_ca_path: /etc/hosts\n"                                                     \
    "    require_client_cert: true\n"

#define YAML_SERVER_INVALID_LISTEN_PORT                                                            \
    "server:\n"                                                                                    \
    "  listen_address: 0.0.0.0\n"                                                                  \
    "  listen_port: not_a_number\n"                                                                \
    "  version: 0.1.0\n"                                                                           \
    "  tls:\n"                                                                                     \
    "    enabled: false\n"                                                                         \
    "    server_cert_path: /etc/hosts\n"                                                           \
    "    server_key_path: /etc/hosts\n"                                                            \
    "    trusted_client_ca_path: /etc/hosts\n"                                                     \
    "    require_client_cert: true\n"

#define YAML_VERIFIERS_VALID                                                                       \
    "verifiers:\n"                                                                                 \
    "  - verifier_id: govt-verifier-01\n"                                                          \
    "    cert_subject_cn: govt-verifier-01\n"                                                      \
    "    cert_san_uri: spiffe://vantaqd/verifier/govt-verifier-01\n"                               \
    "    status: active\n"                                                                         \
    "    roles:\n"                                                                                 \
    "      - verifier\n"                                                                           \
    "    allowed_apis:\n"                                                                          \
    "      - GET /v1/health\n"

#define YAML_DEVICE_VALID                                                                          \
    "device_identity:\n"                                                                           \
    "  device_id: edge-gw-001\n"                                                                   \
    "  model: edge-gateway-v1\n"                                                                   \
    "  serial_number: SN-001\n"                                                                    \
    "  manufacturer: ExampleCorp\n"                                                                \
    "  firmware_version: 0.1.0-demo\n"                                                             \
    "  device_priv_key_path: /etc/hosts\n"                                                         \
    "  device_pub_key_path: /etc/hosts\n"

#define YAML_DEVICE_MISSING_ID                                                                     \
    "device_identity:\n"                                                                           \
    "  model: edge-gateway-v1\n"                                                                   \
    "  serial_number: SN-001\n"                                                                    \
    "  manufacturer: ExampleCorp\n"                                                                \
    "  firmware_version: 0.1.0-demo\n"                                                             \
    "  device_priv_key_path: /etc/hosts\n"                                                         \
    "  device_pub_key_path: /etc/hosts\n"

#define YAML_DEVICE_MISSING_MANUFACTURER                                                           \
    "device_identity:\n"                                                                           \
    "  device_id: edge-gw-001\n"                                                                   \
    "  model: edge-gateway-v1\n"                                                                   \
    "  serial_number: SN-001\n"                                                                    \
    "  firmware_version: 0.1.0-demo\n"                                                             \
    "  device_priv_key_path: /etc/hosts\n"                                                         \
    "  device_pub_key_path: /etc/hosts\n"

#define YAML_CAPABILITIES_VALID                                                                    \
    "capabilities:\n"                                                                              \
    "  supported_claims: [device_identity]\n"                                                      \
    "  signature_algorithms: []\n"                                                                 \
    "  evidence_formats: []\n"                                                                     \
    "  challenge_modes: []\n"                                                                      \
    "  storage_modes: []\n"

#define YAML_CAPABILITIES_NO_DEVICE_IDENTITY                                                       \
    "capabilities:\n"                                                                              \
    "  supported_claims: [firmware_hash]\n"                                                        \
    "  signature_algorithms: []\n"                                                                 \
    "  evidence_formats: []\n"                                                                     \
    "  challenge_modes: []\n"                                                                      \
    "  storage_modes: []\n"

#define YAML_MEASUREMENT_VALID                                                                     \
    "measurement:\n"                                                                               \
    "  firmware_path: /opt/vantaqd/firmware/current.bin\n"                                         \
    "  security_config_path: /etc/vantaqd/security.conf\n"                                         \
    "  agent_binary_path: /usr/local/bin/vantaqd\n"                                                \
    "  boot_state_path: /run/vantaqd/boot_state\n"                                                 \
    "  max_measurement_file_bytes: 16777216\n"

static int write_temp_yaml(const char *content, char *path_out, size_t path_out_size) {
    char template[] = "/tmp/vantaq_cfg_XXXXXX.yaml";
    int fd          = mkstemps(template, 5);
    size_t len      = strlen(content);

    if (fd < 0) {
        return -1;
    }

    if (strlen(template) >= path_out_size) {
        close(fd);
        unlink(template);
        return -1;
    }

    if (write(fd, content, len) != (ssize_t)len) {
        close(fd);
        unlink(template);
        return -1;
    }

    close(fd);
    strcpy(path_out, template);
    return 0;
}

static void remove_temp_yaml(const char *path) {
    if (path != NULL && path[0] != '\0') {
        unlink(path);
    }
}

static void test_valid_yaml_loads_successfully(void **state) {
    (void)state;
    const char *yaml = YAML_SERVER_VALID YAML_VERIFIERS_VALID YAML_DEVICE_VALID
        YAML_CAPABILITIES_VALID YAML_MEASUREMENT_VALID
        "network_access:\n"
        "  allowed_subnets: [10.50.10.0/24, 172.20.5.0/24]\n"
        "  dev_allow_all_networks: false\n";
    char path[256] = {0};
    struct vantaq_config_loader *loader;
    const struct vantaq_runtime_config *config;

    assert_int_equal(write_temp_yaml(yaml, path, sizeof(path)), 0);

    loader = vantaq_config_loader_create();
    assert_non_null(loader);
    assert_int_equal(vantaq_config_loader_load(loader, path), VANTAQ_CONFIG_STATUS_OK);

    config = vantaq_config_loader_config(loader);
    assert_string_equal(vantaq_runtime_service_listen_host(config), "0.0.0.0");
    assert_int_equal(vantaq_runtime_service_listen_port(config), 8080);
    assert_true(vantaq_runtime_tls_enabled(config) == false);
    assert_true(vantaq_runtime_tls_require_client_cert(config));
    assert_string_equal(vantaq_runtime_tls_server_cert_path(config), "/etc/hosts");
    assert_string_equal(vantaq_runtime_tls_server_key_path(config), "/etc/hosts");
    assert_string_equal(vantaq_runtime_tls_trusted_client_ca_path(config), "/etc/hosts");
    assert_int_equal(vantaq_runtime_verifier_count(config), 1);
    assert_string_equal(vantaq_runtime_verifier_id(config, 0), "govt-verifier-01");
    assert_string_equal(vantaq_runtime_verifier_cert_subject_cn(config, 0), "govt-verifier-01");
    assert_string_equal(vantaq_runtime_verifier_cert_san_uri(config, 0),
                        "spiffe://vantaqd/verifier/govt-verifier-01");
    assert_string_equal(vantaq_runtime_verifier_status(config, 0), "active");
    assert_int_equal(vantaq_runtime_verifier_role_count(config, 0), 1);
    assert_string_equal(vantaq_runtime_verifier_role_item(config, 0, 0), "verifier");
    assert_int_equal(vantaq_runtime_verifier_allowed_api_count(config, 0), 1);
    assert_string_equal(vantaq_runtime_verifier_allowed_api_item(config, 0, 0), "GET /v1/health");
    assert_string_equal(vantaq_runtime_device_id(config), "edge-gw-001");
    assert_int_equal(vantaq_runtime_capability_count(config, VANTAQ_CAPABILITY_SUPPORTED_CLAIMS),
                     1);
    assert_string_equal(
        vantaq_runtime_capability_item(config, VANTAQ_CAPABILITY_SUPPORTED_CLAIMS, 0),
        "device_identity");
    assert_int_equal(vantaq_runtime_allowed_subnet_count(config), 2);
    assert_string_equal(vantaq_runtime_allowed_subnet_item(config, 0), "10.50.10.0/24");
    assert_string_equal(vantaq_runtime_allowed_subnet_item(config, 1), "172.20.5.0/24");
    assert_true(vantaq_runtime_dev_allow_all_networks(config) == false);

    vantaq_config_loader_destroy(loader);
    remove_temp_yaml(path);
}

static void test_missing_device_id_fails(void **state) {
    (void)state;
    const char *yaml = YAML_SERVER_VALID YAML_VERIFIERS_VALID YAML_DEVICE_MISSING_ID
        YAML_CAPABILITIES_VALID YAML_MEASUREMENT_VALID;
    char path[256] = {0};
    struct vantaq_config_loader *loader;

    assert_int_equal(write_temp_yaml(yaml, path, sizeof(path)), 0);

    loader = vantaq_config_loader_create();
    assert_non_null(loader);
    assert_int_equal(vantaq_config_loader_load(loader, path),
                     VANTAQ_CONFIG_STATUS_VALIDATION_ERROR);
    assert_non_null(strstr(vantaq_config_loader_last_error(loader), "device_identity.device_id"));

    vantaq_config_loader_destroy(loader);
    remove_temp_yaml(path);
}

static void test_missing_listen_port_fails(void **state) {
    (void)state;
    const char *yaml = YAML_SERVER_MISSING_LISTEN_PORT YAML_VERIFIERS_VALID YAML_DEVICE_VALID
        YAML_CAPABILITIES_VALID YAML_MEASUREMENT_VALID;
    char path[256] = {0};
    struct vantaq_config_loader *loader;

    assert_int_equal(write_temp_yaml(yaml, path, sizeof(path)), 0);

    loader = vantaq_config_loader_create();
    assert_non_null(loader);
    assert_int_equal(vantaq_config_loader_load(loader, path),
                     VANTAQ_CONFIG_STATUS_VALIDATION_ERROR);
    assert_non_null(strstr(vantaq_config_loader_last_error(loader), "server.listen_port"));

    vantaq_config_loader_destroy(loader);
    remove_temp_yaml(path);
}

static void test_invalid_port_fails(void **state) {
    (void)state;
    const char *yaml = YAML_SERVER_INVALID_LISTEN_PORT YAML_VERIFIERS_VALID YAML_DEVICE_VALID
        YAML_CAPABILITIES_VALID YAML_MEASUREMENT_VALID;
    char path[256] = {0};
    struct vantaq_config_loader *loader;

    assert_int_equal(write_temp_yaml(yaml, path, sizeof(path)), 0);

    loader = vantaq_config_loader_create();
    assert_non_null(loader);
    assert_int_equal(vantaq_config_loader_load(loader, path), VANTAQ_CONFIG_STATUS_PARSE_ERROR);
    assert_non_null(strstr(vantaq_config_loader_last_error(loader), "server.listen_port"));

    vantaq_config_loader_destroy(loader);
    remove_temp_yaml(path);
}

static void test_missing_required_identity_field_fails(void **state) {
    (void)state;
    const char *yaml = YAML_SERVER_VALID YAML_VERIFIERS_VALID YAML_DEVICE_MISSING_MANUFACTURER
        YAML_CAPABILITIES_VALID YAML_MEASUREMENT_VALID;
    char path[256] = {0};
    struct vantaq_config_loader *loader;

    assert_int_equal(write_temp_yaml(yaml, path, sizeof(path)), 0);

    loader = vantaq_config_loader_create();
    assert_non_null(loader);
    assert_int_equal(vantaq_config_loader_load(loader, path),
                     VANTAQ_CONFIG_STATUS_VALIDATION_ERROR);
    assert_non_null(
        strstr(vantaq_config_loader_last_error(loader), "device_identity.manufacturer"));

    vantaq_config_loader_destroy(loader);
    remove_temp_yaml(path);
}

static void test_missing_capabilities_fails(void **state) {
    (void)state;
    const char *yaml =
        YAML_SERVER_VALID YAML_VERIFIERS_VALID YAML_DEVICE_VALID YAML_MEASUREMENT_VALID;
    char path[256] = {0};
    struct vantaq_config_loader *loader;

    assert_int_equal(write_temp_yaml(yaml, path, sizeof(path)), 0);

    loader = vantaq_config_loader_create();
    assert_non_null(loader);
    assert_int_equal(vantaq_config_loader_load(loader, path),
                     VANTAQ_CONFIG_STATUS_VALIDATION_ERROR);
    assert_non_null(
        strstr(vantaq_config_loader_last_error(loader), "capabilities.supported_claims"));

    vantaq_config_loader_destroy(loader);
    remove_temp_yaml(path);
}

static void test_supported_claims_must_include_device_identity(void **state) {
    (void)state;
    const char *yaml = YAML_SERVER_VALID YAML_VERIFIERS_VALID YAML_DEVICE_VALID
        YAML_CAPABILITIES_NO_DEVICE_IDENTITY YAML_MEASUREMENT_VALID;
    char path[256] = {0};
    struct vantaq_config_loader *loader;

    assert_int_equal(write_temp_yaml(yaml, path, sizeof(path)), 0);

    loader = vantaq_config_loader_create();
    assert_non_null(loader);
    assert_int_equal(vantaq_config_loader_load(loader, path),
                     VANTAQ_CONFIG_STATUS_VALIDATION_ERROR);
    assert_non_null(strstr(vantaq_config_loader_last_error(loader), "device_identity"));

    vantaq_config_loader_destroy(loader);
    remove_temp_yaml(path);
}

static void test_invalid_allowed_subnet_cidr_fails(void **state) {
    (void)state;
    const char *yaml = YAML_SERVER_VALID YAML_VERIFIERS_VALID YAML_DEVICE_VALID
        YAML_CAPABILITIES_VALID YAML_MEASUREMENT_VALID "network_access:\n"
                                                       "  allowed_subnets: [10.50.10.0/99]\n";
    char path[256] = {0};
    struct vantaq_config_loader *loader;

    assert_int_equal(write_temp_yaml(yaml, path, sizeof(path)), 0);

    loader = vantaq_config_loader_create();
    assert_non_null(loader);
    assert_int_equal(vantaq_config_loader_load(loader, path),
                     VANTAQ_CONFIG_STATUS_VALIDATION_ERROR);
    assert_non_null(strstr(vantaq_config_loader_last_error(loader), "10.50.10.0/99"));

    vantaq_config_loader_destroy(loader);
    remove_temp_yaml(path);
}

static void test_empty_allowed_subnets_fail_closed_default(void **state) {
    (void)state;
    const char *yaml = YAML_SERVER_VALID YAML_VERIFIERS_VALID YAML_DEVICE_VALID
        YAML_CAPABILITIES_VALID YAML_MEASUREMENT_VALID "network_access:\n"
                                                       "  allowed_subnets: []\n"
                                                       "  dev_allow_all_networks: false\n";
    char path[256] = {0};
    struct vantaq_config_loader *loader;
    const struct vantaq_runtime_config *config;

    assert_int_equal(write_temp_yaml(yaml, path, sizeof(path)), 0);

    loader = vantaq_config_loader_create();
    assert_non_null(loader);
    assert_int_equal(vantaq_config_loader_load(loader, path), VANTAQ_CONFIG_STATUS_OK);

    config = vantaq_config_loader_config(loader);
    assert_int_equal(vantaq_runtime_allowed_subnet_count(config), 0);
    assert_true(vantaq_runtime_dev_allow_all_networks(config) == false);

    vantaq_config_loader_destroy(loader);
    remove_temp_yaml(path);
}

static void test_empty_allowed_subnets_with_dev_allow_all_succeeds(void **state) {
    (void)state;
    const char *yaml = YAML_SERVER_VALID YAML_VERIFIERS_VALID YAML_DEVICE_VALID
        YAML_CAPABILITIES_VALID YAML_MEASUREMENT_VALID "network_access:\n"
                                                       "  allowed_subnets: []\n"
                                                       "  dev_allow_all_networks: true\n";
    char path[256] = {0};
    struct vantaq_config_loader *loader;
    const struct vantaq_runtime_config *config;

    assert_int_equal(write_temp_yaml(yaml, path, sizeof(path)), 0);

    loader = vantaq_config_loader_create();
    assert_non_null(loader);
    assert_int_equal(vantaq_config_loader_load(loader, path), VANTAQ_CONFIG_STATUS_OK);

    config = vantaq_config_loader_config(loader);
    assert_int_equal(vantaq_runtime_allowed_subnet_count(config), 0);
    assert_true(vantaq_runtime_dev_allow_all_networks(config));

    vantaq_config_loader_destroy(loader);
    remove_temp_yaml(path);
}

static void test_missing_network_access_defaults_to_fail_closed(void **state) {
    (void)state;
    const char *yaml = YAML_SERVER_VALID YAML_VERIFIERS_VALID YAML_DEVICE_VALID
        YAML_CAPABILITIES_VALID YAML_MEASUREMENT_VALID;
    char path[256] = {0};
    struct vantaq_config_loader *loader;
    const struct vantaq_runtime_config *config;

    assert_int_equal(write_temp_yaml(yaml, path, sizeof(path)), 0);

    loader = vantaq_config_loader_create();
    assert_non_null(loader);
    assert_int_equal(vantaq_config_loader_load(loader, path), VANTAQ_CONFIG_STATUS_OK);

    config = vantaq_config_loader_config(loader);
    assert_int_equal(vantaq_runtime_allowed_subnet_count(config), 0);
    assert_true(vantaq_runtime_dev_allow_all_networks(config) == false);

    vantaq_config_loader_destroy(loader);
    remove_temp_yaml(path);
}

static void test_challenge_size_overflow_fails_parse(void **state) {
    (void)state;
    const char *yaml = YAML_SERVER_VALID YAML_VERIFIERS_VALID YAML_DEVICE_VALID
        YAML_CAPABILITIES_VALID YAML_MEASUREMENT_VALID "challenge:\n"
                                                       "  ttl_seconds: 999999999999999999999999\n"
                                                       "  max_global: 100\n"
                                                       "  max_per_verifier: 10\n";
    char path[256] = {0};
    struct vantaq_config_loader *loader;

    assert_int_equal(write_temp_yaml(yaml, path, sizeof(path)), 0);

    loader = vantaq_config_loader_create();
    assert_non_null(loader);
    assert_int_equal(vantaq_config_loader_load(loader, path), VANTAQ_CONFIG_STATUS_PARSE_ERROR);
    assert_non_null(strstr(vantaq_config_loader_last_error(loader), "challenge.ttl_seconds"));

    vantaq_config_loader_destroy(loader);
    remove_temp_yaml(path);
}

static void test_inline_list_supports_quoted_item_with_comma(void **state) {
    (void)state;
    const char *yaml =
        YAML_SERVER_VALID YAML_DEVICE_VALID YAML_CAPABILITIES_VALID YAML_MEASUREMENT_VALID
        "verifiers:\n"
        "  - verifier_id: govt-verifier-01\n"
        "    cert_subject_cn: govt-verifier-01\n"
        "    cert_san_uri: spiffe://vantaqd/verifier/govt-verifier-01\n"
        "    status: active\n"
        "    roles: [verifier]\n"
        "    allowed_apis: [\"GET /v1/health,verbose\"]\n";
    char path[256] = {0};
    struct vantaq_config_loader *loader;
    const struct vantaq_runtime_config *config;

    assert_int_equal(write_temp_yaml(yaml, path, sizeof(path)), 0);
    loader = vantaq_config_loader_create();
    assert_non_null(loader);
    assert_int_equal(vantaq_config_loader_load(loader, path), VANTAQ_CONFIG_STATUS_OK);

    config = vantaq_config_loader_config(loader);
    assert_int_equal(vantaq_runtime_verifier_allowed_api_count(config, 0), 1);
    assert_string_equal(vantaq_runtime_verifier_allowed_api_item(config, 0, 0),
                        "GET /v1/health,verbose");

    vantaq_config_loader_destroy(loader);
    remove_temp_yaml(path);
}

static void test_tab_indentation_is_rejected(void **state) {
    (void)state;
    const char *yaml = "server:\n"
                       "\tlisten_address: 0.0.0.0\n"
                       "  listen_port: 8080\n"
                       "  version: 0.1.0\n"
                       "  tls:\n"
                       "    enabled: false\n"
                       "    server_cert_path: /etc/hosts\n"
                       "    server_key_path: /etc/hosts\n"
                       "    trusted_client_ca_path: /etc/hosts\n"
                       "    require_client_cert: true\n";
    char path[256]   = {0};
    struct vantaq_config_loader *loader;

    assert_int_equal(write_temp_yaml(yaml, path, sizeof(path)), 0);
    loader = vantaq_config_loader_create();
    assert_non_null(loader);
    assert_int_equal(vantaq_config_loader_load(loader, path), VANTAQ_CONFIG_STATUS_PARSE_ERROR);
    assert_non_null(strstr(vantaq_config_loader_last_error(loader), "tabs are not allowed"));

    vantaq_config_loader_destroy(loader);
    remove_temp_yaml(path);
}

static void test_missing_measurement_firmware_path_fails(void **state) {
    (void)state;
    const char *yaml =
        YAML_SERVER_VALID YAML_VERIFIERS_VALID YAML_DEVICE_VALID YAML_CAPABILITIES_VALID
        "measurement:\n"
        "  security_config_path: /etc/vantaqd/security.conf\n"
        "  agent_binary_path: /usr/local/bin/vantaqd\n"
        "  boot_state_path: /run/vantaqd/boot_state\n"
        "  max_measurement_file_bytes: 16777216\n";
    char path[256] = {0};
    struct vantaq_config_loader *loader;

    assert_int_equal(write_temp_yaml(yaml, path, sizeof(path)), 0);
    loader = vantaq_config_loader_create();
    assert_non_null(loader);
    assert_int_equal(vantaq_config_loader_load(loader, path),
                     VANTAQ_CONFIG_STATUS_VALIDATION_ERROR);
    assert_non_null(strstr(vantaq_config_loader_last_error(loader), "measurement.firmware_path"));

    vantaq_config_loader_destroy(loader);
    remove_temp_yaml(path);
}

static void test_invalid_measurement_max_file_bytes_fails(void **state) {
    (void)state;
    const char *yaml =
        YAML_SERVER_VALID YAML_VERIFIERS_VALID YAML_DEVICE_VALID YAML_CAPABILITIES_VALID
        "measurement:\n"
        "  firmware_path: /opt/vantaqd/firmware/current.bin\n"
        "  security_config_path: /etc/vantaqd/security.conf\n"
        "  agent_binary_path: /usr/local/bin/vantaqd\n"
        "  boot_state_path: /run/vantaqd/boot_state\n"
        "  max_measurement_file_bytes: 0\n";
    char path[256] = {0};
    struct vantaq_config_loader *loader;

    assert_int_equal(write_temp_yaml(yaml, path, sizeof(path)), 0);
    loader = vantaq_config_loader_create();
    assert_non_null(loader);
    assert_int_equal(vantaq_config_loader_load(loader, path), VANTAQ_CONFIG_STATUS_PARSE_ERROR);
    assert_non_null(
        strstr(vantaq_config_loader_last_error(loader), "measurement.max_measurement_file_bytes"));

    vantaq_config_loader_destroy(loader);
    remove_temp_yaml(path);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_valid_yaml_loads_successfully),
        cmocka_unit_test(test_missing_device_id_fails),
        cmocka_unit_test(test_missing_listen_port_fails),
        cmocka_unit_test(test_invalid_port_fails),
        cmocka_unit_test(test_missing_required_identity_field_fails),
        cmocka_unit_test(test_missing_capabilities_fails),
        cmocka_unit_test(test_supported_claims_must_include_device_identity),
        cmocka_unit_test(test_invalid_allowed_subnet_cidr_fails),
        cmocka_unit_test(test_empty_allowed_subnets_fail_closed_default),
        cmocka_unit_test(test_empty_allowed_subnets_with_dev_allow_all_succeeds),
        cmocka_unit_test(test_missing_network_access_defaults_to_fail_closed),
        cmocka_unit_test(test_challenge_size_overflow_fails_parse),
        cmocka_unit_test(test_inline_list_supports_quoted_item_with_comma),
        cmocka_unit_test(test_tab_indentation_is_rejected),
        cmocka_unit_test(test_missing_measurement_firmware_path_fails),
        cmocka_unit_test(test_invalid_measurement_max_file_bytes_fails),
    };

    return cmocka_run_group_tests_name("unit_config_loader", tests, NULL, NULL);
}
