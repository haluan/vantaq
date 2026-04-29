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

#define YAML_SERVER_HEAD                                                                           \
    "server:\n"                                                                                    \
    "  listen_address: 127.0.0.1\n"                                                                \
    "  listen_port: 8080\n"                                                                        \
    "  version: 0.1.0\n"                                                                           \
    "  tls:\n"

#define YAML_TLS_VALID                                                                             \
    "    enabled: false\n"                                                                         \
    "    server_cert_path: /etc/hosts\n"                                                           \
    "    server_key_path: " TEST_PRIVATE_KEY_PATH "\n"                                             \
    "    trusted_client_ca_path: /etc/hosts\n"                                                     \
    "    require_client_cert: true\n"

#define YAML_DEVICE_AND_CAPABILITIES                                                               \
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
    "  signature_algorithms: []\n"                                                                 \
    "  evidence_formats: []\n"                                                                     \
    "  challenge_modes: []\n"                                                                      \
    "  storage_modes: []\n"                                                                        \
    "measurement:\n"                                                                               \
    "  firmware_path: /opt/vantaqd/firmware/current.bin\n"                                         \
    "  security_config_path: /etc/vantaqd/security.conf\n"                                         \
    "  agent_binary_path: /usr/local/bin/vantaqd\n"                                                \
    "  boot_state_path: /run/vantaqd/boot_state\n"                                                 \
    "  max_measurement_file_bytes: 16777216\n"

#define YAML_VERIFIER_VALID                                                                        \
    "verifiers:\n"                                                                                 \
    "  - verifier_id: govt-verifier-01\n"                                                          \
    "    cert_subject_cn: govt-verifier-01\n"                                                      \
    "    cert_san_uri: spiffe://vantaqd/verifier/govt-verifier-01\n"                               \
    "    status: active\n"                                                                         \
    "    roles: [verifier]\n"                                                                      \
    "    allowed_apis: [GET /v1/health]\n"

static int write_temp_yaml(const char *content, char *path_out, size_t path_out_size) {
    char template[] = "/tmp/vantaq_security_cfg_XXXXXX.yaml";
    int fd          = mkstemps(template, 5);
    size_t len      = strlen(content);

    if (fd < 0) {
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
    unlink(TEST_PRIVATE_KEY_PATH);
}

static void assert_load_status(const char *yaml, enum vantaq_config_status expected_status,
                               const char *err_contains) {
    char path[256] = {0};
    struct vantaq_config_loader *loader;

    assert_int_equal(write_temp_yaml(yaml, path, sizeof(path)), 0);

    loader = vantaq_config_loader_create();
    assert_non_null(loader);

    assert_int_equal(vantaq_config_loader_load(loader, path), expected_status);
    if (err_contains != NULL) {
        assert_non_null(strstr(vantaq_config_loader_last_error(loader), err_contains));
    }

    vantaq_config_loader_destroy(loader);
    remove_temp_yaml(path);
}

static void test_valid_security_config_loads(void **state) {
    (void)state;
    const char *yaml =
        YAML_SERVER_HEAD YAML_TLS_VALID YAML_VERIFIER_VALID YAML_DEVICE_AND_CAPABILITIES;

    assert_load_status(yaml, VANTAQ_CONFIG_STATUS_OK, NULL);
}

static void test_missing_tls_path_fields_fail(void **state) {
    struct missing_case {
        const char *yaml;
        const char *expected;
    } cases[] = {
        {
            YAML_SERVER_HEAD
            "    enabled: false\n"
            "    server_key_path: /etc/hosts\n"
            "    trusted_client_ca_path: /etc/hosts\n"
            "    require_client_cert: true\n" YAML_VERIFIER_VALID YAML_DEVICE_AND_CAPABILITIES,
            "server.tls.server_cert_path",
        },
        {
            YAML_SERVER_HEAD
            "    enabled: false\n"
            "    server_cert_path: /etc/hosts\n"
            "    trusted_client_ca_path: /etc/hosts\n"
            "    require_client_cert: true\n" YAML_VERIFIER_VALID YAML_DEVICE_AND_CAPABILITIES,
            "server.tls.server_key_path",
        },
        {
            YAML_SERVER_HEAD
            "    enabled: false\n"
            "    server_cert_path: /etc/hosts\n"
            "    server_key_path: /etc/hosts\n"
            "    require_client_cert: true\n" YAML_VERIFIER_VALID YAML_DEVICE_AND_CAPABILITIES,
            "server.tls.trusted_client_ca_path",
        },
    };
    size_t i;

    (void)state;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        assert_load_status(cases[i].yaml, VANTAQ_CONFIG_STATUS_VALIDATION_ERROR, cases[i].expected);
    }
}

static void test_unreadable_tls_path_fails(void **state) {
    (void)state;
    const char *yaml = YAML_SERVER_HEAD
        "    enabled: false\n"
        "    server_cert_path: /tmp/vantaq-missing-cert.crt\n"
        "    server_key_path: " TEST_PRIVATE_KEY_PATH "\n"
        "    trusted_client_ca_path: /etc/hosts\n"
        "    require_client_cert: true\n" YAML_VERIFIER_VALID YAML_DEVICE_AND_CAPABILITIES;

    assert_load_status(yaml, VANTAQ_CONFIG_STATUS_VALIDATION_ERROR, "server.tls.server_cert_path");
}

static void test_invalid_verifier_entries_fail(void **state) {
    struct verifier_case {
        const char *yaml;
        const char *expected;
    } cases[] = {
        {
            YAML_SERVER_HEAD YAML_TLS_VALID
            "verifiers:\n"
            "  - verifier_id: govt-verifier-01\n"
            "    cert_san_uri: spiffe://vantaqd/verifier/govt-verifier-01\n"
            "    status: active\n"
            "    roles: [verifier]\n"
            "    allowed_apis: [GET /v1/health]\n" YAML_DEVICE_AND_CAPABILITIES,
            "verifiers[0].cert_subject_cn",
        },
        {
            YAML_SERVER_HEAD YAML_TLS_VALID
            "verifiers:\n"
            "  - verifier_id: govt-verifier-01\n"
            "    cert_subject_cn: govt-verifier-01\n"
            "    cert_san_uri: spiffe://vantaqd/verifier/govt-verifier-01\n"
            "    status: disabled\n"
            "    roles: [verifier]\n"
            "    allowed_apis: [GET /v1/health]\n" YAML_DEVICE_AND_CAPABILITIES,
            "verifiers[0].status",
        },
        {
            YAML_SERVER_HEAD YAML_TLS_VALID
            "verifiers:\n"
            "  - verifier_id: govt-verifier-01\n"
            "    cert_subject_cn: govt-verifier-01\n"
            "    cert_san_uri: spiffe://vantaqd/verifier/govt-verifier-01\n"
            "    status: active\n"
            "    roles: []\n"
            "    allowed_apis: [GET /v1/health]\n" YAML_DEVICE_AND_CAPABILITIES,
            "verifiers[0].roles",
        },
        {
            YAML_SERVER_HEAD YAML_TLS_VALID
            "verifiers:\n"
            "  - verifier_id: govt-verifier-01\n"
            "    cert_subject_cn: govt-verifier-01\n"
            "    cert_san_uri: spiffe://vantaqd/verifier/govt-verifier-01\n"
            "    status: active\n"
            "    roles: [verifier]\n"
            "    allowed_apis: []\n" YAML_DEVICE_AND_CAPABILITIES,
            "verifiers[0].allowed_apis",
        },
        {
            YAML_SERVER_HEAD YAML_TLS_VALID
            "verifiers:\n"
            "  - verifier_id: govt-verifier-01\n"
            "    cert_subject_cn: govt-verifier-01\n"
            "    cert_san_uri: spiffe://vantaqd/verifier/govt-verifier-01\n"
            "    status: active\n"
            "    roles: [verifier]\n"
            "    allowed_apis: [GET /v1/health]\n"
            "  - verifier_id: govt-verifier-01\n"
            "    cert_subject_cn: govt-verifier-02\n"
            "    cert_san_uri: spiffe://vantaqd/verifier/govt-verifier-02\n"
            "    status: active\n"
            "    roles: [verifier]\n"
            "    allowed_apis: [GET /v1/health]\n" YAML_DEVICE_AND_CAPABILITIES,
            "duplicate verifier_id",
        },
    };
    size_t i;

    (void)state;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        assert_load_status(cases[i].yaml, VANTAQ_CONFIG_STATUS_VALIDATION_ERROR, cases[i].expected);
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_valid_security_config_loads),
        cmocka_unit_test(test_missing_tls_path_fields_fail),
        cmocka_unit_test(test_unreadable_tls_path_fails),
        cmocka_unit_test(test_invalid_verifier_entries_fail),
    };

    return cmocka_run_group_tests_name("unit_security_config", tests, NULL, NULL);
}
