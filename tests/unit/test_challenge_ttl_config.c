// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/config_loader.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cmocka.h>

#define TEST_PRIVATE_KEY_PATH "/tmp/vantaq_test_private_key.pem"

#define YAML_MINIMAL                                                                               \
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
    "  device_id: gw-01\n"                                                                         \
    "  model: m1\n"                                                                                \
    "  serial_number: s1\n"                                                                        \
    "  manufacturer: m1\n"                                                                         \
    "  firmware_version: f1\n"                                                                     \
    "  device_priv_key_path: " TEST_PRIVATE_KEY_PATH "\n"                                          \
    "  device_pub_key_path: /etc/hosts\n"                                                          \
    "capabilities:\n"                                                                              \
    "  supported_claims: [device_identity]\n"                                                      \
    "  signature_algorithms: [ES256]\n"                                                            \
    "  evidence_formats: [eat]\n"                                                                  \
    "  challenge_modes: [nonce]\n"                                                                 \
    "  storage_modes: [volatile]\n"                                                                \
    "measurement:\n"                                                                               \
    "  firmware_path: /etc/hosts\n"                                                                \
    "  security_config_path: /etc/hosts\n"                                                         \
    "  agent_binary_path: /etc/hosts\n"                                                            \
    "  boot_state_path: /etc/hosts\n"                                                              \
    "  max_measurement_file_bytes: 16777216\n"                                                     \
    "verifiers:\n"                                                                                 \
    "  - verifier_id: v1\n"                                                                        \
    "    cert_subject_cn: v1\n"                                                                    \
    "    cert_san_uri: u1\n"                                                                       \
    "    status: active\n"                                                                         \
    "    roles: [verifier]\n"                                                                      \
    "    allowed_apis: [GET /v1/health]\n"

static int write_temp_yaml(const char *content, char *path_out, size_t path_out_size) {
    char template[] = "/tmp/vantaq_ttl_cfg_XXXXXX.yaml";
    int fd          = mkstemps(template, 5);
    size_t len      = strlen(content);
    if (fd < 0)
        return -1;
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

static void test_valid_challenge_ttl_config(void **state) {
    (void)state;
    char path[256];
    struct vantaq_config_loader *loader;
    const char *yaml = YAML_MINIMAL "challenge:\n  ttl_seconds: 45\n";

    assert_int_equal(write_temp_yaml(yaml, path, sizeof(path)), 0);
    loader = vantaq_config_loader_create();
    assert_int_equal(vantaq_config_loader_load(loader, path), VANTAQ_CONFIG_STATUS_OK);

    const struct vantaq_runtime_config *config = vantaq_config_loader_config(loader);
    assert_int_equal(vantaq_runtime_challenge_ttl_seconds(config), 45);

    vantaq_config_loader_destroy(loader);
    remove_temp_yaml(path);
}

static void test_missing_challenge_ttl_uses_default(void **state) {
    (void)state;
    char path[256];
    struct vantaq_config_loader *loader;
    const char *yaml = YAML_MINIMAL;

    assert_int_equal(write_temp_yaml(yaml, path, sizeof(path)), 0);
    loader = vantaq_config_loader_create();
    assert_int_equal(vantaq_config_loader_load(loader, path), VANTAQ_CONFIG_STATUS_OK);

    const struct vantaq_runtime_config *config = vantaq_config_loader_config(loader);
    assert_int_equal(vantaq_runtime_challenge_ttl_seconds(config), 30);

    vantaq_config_loader_destroy(loader);
    remove_temp_yaml(path);
}

static void test_invalid_challenge_ttl_fails(void **state) {
    (void)state;
    char path[256];
    struct vantaq_config_loader *loader;
    const char *yaml = YAML_MINIMAL "challenge:\n  ttl_seconds: abc\n";

    assert_int_equal(write_temp_yaml(yaml, path, sizeof(path)), 0);
    loader = vantaq_config_loader_create();
    assert_int_equal(vantaq_config_loader_load(loader, path), VANTAQ_CONFIG_STATUS_PARSE_ERROR);

    vantaq_config_loader_destroy(loader);
    remove_temp_yaml(path);
}

static void test_invalid_verifier_role_or_api_fails_validation(void **state) {
    (void)state;
    char path[256];
    struct vantaq_config_loader *loader;
    const char *yaml = YAML_MINIMAL "verifiers:\n"
                                    "  - verifier_id: v1\n"
                                    "    cert_subject_cn: v1\n"
                                    "    cert_san_uri: u1\n"
                                    "    status: active\n"
                                    "    roles: [r1]\n"
                                    "    allowed_apis: [a1]\n";

    assert_int_equal(write_temp_yaml(yaml, path, sizeof(path)), 0);
    loader = vantaq_config_loader_create();
    assert_int_equal(vantaq_config_loader_load(loader, path),
                     VANTAQ_CONFIG_STATUS_VALIDATION_ERROR);

    vantaq_config_loader_destroy(loader);
    remove_temp_yaml(path);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_valid_challenge_ttl_config),
        cmocka_unit_test(test_missing_challenge_ttl_uses_default),
        cmocka_unit_test(test_invalid_challenge_ttl_fails),
        cmocka_unit_test(test_invalid_verifier_role_or_api_fails_validation),
    };
    return cmocka_run_group_tests_name("unit_challenge_ttl_config", tests, NULL, NULL);
}
