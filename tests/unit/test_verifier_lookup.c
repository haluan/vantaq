// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "application/security/verifier_lookup.h"
#include "infrastructure/config_loader.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cmocka.h>

#define TEST_PRIVATE_KEY_PATH "/tmp/vantaq_test_private_key.pem"

#define YAML_BASE                                                                                  \
    "server:\n"                                                                                    \
    "  listen_address: 127.0.0.1\n"                                                                \
    "  listen_port: 8080\n"                                                                        \
    "  version: 0.1.0\n"                                                                           \
    "  tls:\n"                                                                                     \
    "    enabled: false\n"                                                                         \
    "    server_cert_path: /etc/hosts\n"                                                           \
    "    server_key_path: " TEST_PRIVATE_KEY_PATH "\n"                                             \
    "    trusted_client_ca_path: /etc/hosts\n"                                                     \
    "    require_client_cert: true\n"                                                              \
    "device_identity:\n"                                                                           \
    "  device_id: edge-gw-001\n"                                                                   \
    "  model: edge-gateway-v1\n"                                                                   \
    "  serial_number: SN-001\n"                                                                    \
    "  manufacturer: ExampleCorp\n"                                                                \
    "  firmware_version: 0.1.0-demo\n"                                                             \
    "  device_priv_key_path: " TEST_PRIVATE_KEY_PATH "\n"                                          \
    "  device_pub_key_path: /etc/hosts\n"                                                          \
    "capabilities:\n"                                                                              \
    "  supported_claims: [device_identity]\n"                                                      \
    "  signature_algorithms: [ES256]\n"                                                            \
    "  evidence_formats: [eat]\n"                                                                  \
    "  challenge_modes: [nonce]\n"                                                                 \
    "  storage_modes: [volatile]\n"                                                                \
    "measurement:\n"                                                                               \
    "  firmware_path: /opt/vantaqd/firmware/current.bin\n"                                         \
    "  security_config_path: /etc/vantaqd/security.conf\n"                                         \
    "  agent_binary_path: /usr/local/bin/vantaqd\n"                                                \
    "  boot_state_path: /run/vantaqd/boot_state\n"                                                 \
    "  max_measurement_file_bytes: 16777216\n"

// Assert Pattern: s_assert_xyz style macros
#define s_assert_int_equal(s, a, b) assert_int_equal(a, b)

static int write_temp_yaml(const char *content, char *path_out, size_t path_out_size) {
    char template[] = "/tmp/vantaq_ver_lookup_XXXXXX.yaml";
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
    {
        FILE *key_fp = fopen(TEST_PRIVATE_KEY_PATH, "wb");
        if (key_fp == NULL) {
            close(fd);
            unlink(template);
            return -1;
        }
        (void)fputs("dummy-private-key-for-tests\n", key_fp);
        fclose(key_fp);
        if (chmod(TEST_PRIVATE_KEY_PATH, S_IRUSR | S_IWUSR) != 0) {
            unlink(TEST_PRIVATE_KEY_PATH);
            close(fd);
            unlink(template);
            return -1;
        }
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
    unlink(TEST_PRIVATE_KEY_PATH);
}

static enum vantaq_verifier_status_code
load_and_lookup(const char *yaml, const char *lookup_id,
                enum vantaq_config_status *load_status_out) {
    char path[256] = {0};
    struct vantaq_config_loader *loader;
    const struct vantaq_runtime_config *config;
    enum vantaq_verifier_status_code status = VANTAQ_VERIFIER_STATUS_UNKNOWN;

    if (write_temp_yaml(yaml, path, sizeof(path)) != 0) {
        return VANTAQ_VERIFIER_STATUS_INVALID_ARGUMENT;
    }

    loader = vantaq_config_loader_create();
    if (loader == NULL) {
        remove_temp_yaml(path);
        return VANTAQ_VERIFIER_STATUS_INVALID_ARGUMENT;
    }

    *load_status_out = vantaq_config_loader_load(loader, path);
    if (*load_status_out == VANTAQ_CONFIG_STATUS_OK) {
        config = vantaq_config_loader_config(loader);
        status = vantaq_verifier_lookup_status(config, lookup_id);
    }

    vantaq_config_loader_destroy(loader);
    remove_temp_yaml(path);
    return status;
}

static void test_lookup_active(void **state) {
    (void)state;
    enum vantaq_config_status load_status = VANTAQ_CONFIG_STATUS_INVALID_ARGUMENT;
    const char *yaml                      = YAML_BASE "verifiers:\n"
                                                      "  - verifier_id: v-001\n"
                                                      "    cert_subject_cn: v-001\n"
                                                      "    cert_san_uri: spiffe://vantaqd/verifier/v-001\n"
                                                      "    status: active\n"
                                                      "    roles: [verifier]\n"
                                                      "    allowed_apis: [GET /v1/health]\n";

    enum vantaq_verifier_status_code status = load_and_lookup(yaml, "v-001", &load_status);
    s_assert_int_equal(state, load_status, VANTAQ_CONFIG_STATUS_OK);
    s_assert_int_equal(state, status, VANTAQ_VERIFIER_STATUS_ACTIVE);
}

static void test_lookup_inactive(void **state) {
    (void)state;
    enum vantaq_config_status load_status = VANTAQ_CONFIG_STATUS_INVALID_ARGUMENT;
    const char *yaml                      = YAML_BASE "verifiers:\n"
                                                      "  - verifier_id: v-002\n"
                                                      "    cert_subject_cn: v-002\n"
                                                      "    cert_san_uri: spiffe://vantaqd/verifier/v-002\n"
                                                      "    status: inactive\n"
                                                      "    roles: [verifier]\n"
                                                      "    allowed_apis: [GET /v1/health]\n";

    enum vantaq_verifier_status_code status = load_and_lookup(yaml, "v-002", &load_status);
    s_assert_int_equal(state, load_status, VANTAQ_CONFIG_STATUS_OK);
    s_assert_int_equal(state, status, VANTAQ_VERIFIER_STATUS_INACTIVE);
}

static void test_lookup_not_found(void **state) {
    (void)state;
    enum vantaq_config_status load_status = VANTAQ_CONFIG_STATUS_INVALID_ARGUMENT;
    const char *yaml                      = YAML_BASE "verifiers:\n"
                                                      "  - verifier_id: v-001\n"
                                                      "    cert_subject_cn: v-001\n"
                                                      "    cert_san_uri: spiffe://vantaqd/verifier/v-001\n"
                                                      "    status: active\n"
                                                      "    roles: [verifier]\n"
                                                      "    allowed_apis: [GET /v1/health]\n";

    enum vantaq_verifier_status_code status = load_and_lookup(yaml, "v-999", &load_status);
    s_assert_int_equal(state, load_status, VANTAQ_CONFIG_STATUS_OK);
    s_assert_int_equal(state, status, VANTAQ_VERIFIER_STATUS_NOT_FOUND);
}

static void test_lookup_misconfigured_status(void **state) {
    (void)state;
    enum vantaq_config_status load_status = VANTAQ_CONFIG_STATUS_INVALID_ARGUMENT;
    const char *yaml                      = YAML_BASE "verifiers:\n"
                                                      "  - verifier_id: v-003\n"
                                                      "    cert_subject_cn: v-003\n"
                                                      "    cert_san_uri: spiffe://vantaqd/verifier/v-003\n"
                                                      "    status: invalid-status\n"
                                                      "    roles: [verifier]\n"
                                                      "    allowed_apis: [GET /v1/health]\n";

    (void)load_and_lookup(yaml, "v-003", &load_status);
    s_assert_int_equal(state, load_status, VANTAQ_CONFIG_STATUS_VALIDATION_ERROR);
}

static void test_lookup_invalid_args(void **state) {
    (void)state;

    s_assert_int_equal(state, vantaq_verifier_lookup_status(NULL, "v-001"),
                       VANTAQ_VERIFIER_STATUS_INVALID_ARGUMENT);
    s_assert_int_equal(state, vantaq_verifier_lookup_status(NULL, NULL),
                       VANTAQ_VERIFIER_STATUS_INVALID_ARGUMENT);
    s_assert_int_equal(state, vantaq_verifier_lookup_status(NULL, ""),
                       VANTAQ_VERIFIER_STATUS_INVALID_ARGUMENT);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_lookup_active),
        cmocka_unit_test(test_lookup_inactive),
        cmocka_unit_test(test_lookup_not_found),
        cmocka_unit_test(test_lookup_misconfigured_status),
        cmocka_unit_test(test_lookup_invalid_args),
    };

    return cmocka_run_group_tests_name("verifier_lookup_suite", tests, NULL, NULL);
}
