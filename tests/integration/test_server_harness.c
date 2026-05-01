// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "test_server_harness.h"
#include "infrastructure/config_loader.h"
#include "infrastructure/memory/zero_struct.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int first_available_port(void) {
    int port;

    for (port = 18080; port < 18160; port++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr;
        int one = 1;

        if (sock < 0) {
            continue;
        }

        VANTAQ_ZERO_STRUCT(addr);
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port        = htons((uint16_t)port);
        (void)setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

        if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            close(sock);
            return port;
        }

        close(sock);
    }

    return -1;
}

int reserve_ephemeral_port(void) {
    int direct_port = first_available_port();
    int sock        = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    if (direct_port > 0) {
        return direct_port;
    }

    if (sock < 0) {
        return -1;
    }

    VANTAQ_ZERO_STRUCT(addr);
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = htons(0);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock);
        return -1;
    }

    if (getsockname(sock, (struct sockaddr *)&addr, &len) != 0) {
        close(sock);
        return -1;
    }

    close(sock);
    if ((int)ntohs(addr.sin_port) > 0) {
        return (int)ntohs(addr.sin_port);
    }

    return -1;
}

int write_temp_yaml(int port, const char *allowed_subnets, const char *dev_allow_all,
                    char *path_out, size_t path_out_size) {
    const char *yaml_fmt = "server:\n"
                           "  listen_address: 127.0.0.1\n"
                           "  listen_port: %d\n"
                           "  version: 0.1.0\n"
                           "  tls:\n"
                           "    enabled: false\n"
                           "    server_cert_path: /etc/hosts\n"
                           "    server_key_path: /etc/hosts\n"
                           "    trusted_client_ca_path: /etc/hosts\n"
                           "    require_client_cert: true\n"
                           "\n"
                           "verifiers:\n"
                           "  - verifier_id: govt-verifier-01\n"
                           "    cert_subject_cn: govt-verifier-01\n"
                           "    cert_san_uri: spiffe://vantaqd/verifier/govt-verifier-01\n"
                           "    status: active\n"
                           "    roles:\n"
                           "      - verifier\n"
                           "    allowed_apis:\n"
                           "      - GET /v1/health\n"
                           "\n"
                           "device_identity:\n"
                           "  device_id: edge-gw-001\n"
                           "  model: edge-gateway-v1\n"
                           "  serial_number: SN-001\n"
                           "  manufacturer: ExampleCorp\n"
                           "  firmware_version: 0.1.0-demo\n"
                           "  device_priv_key_path: config/certs/device-server.key\n"
                           "  device_pub_key_path: config/certs/device-server.crt\n"
                           "\n"
                           "capabilities:\n"
                           "  supported_claims:\n"
                           "    - device_identity\n"
                           "  signature_algorithms: []\n"
                           "  evidence_formats: []\n"
                           "  challenge_modes: []\n"
                           "  storage_modes: []\n"
                           "measurement:\n"
                           "  firmware_path: /etc/hosts\n"
                           "  security_config_path: /etc/hosts\n"
                           "  agent_binary_path: /etc/hosts\n"
                           "  boot_state_path: /etc/hosts\n"
                           "  max_measurement_file_bytes: 16777216\n"
                           "network_access:\n"
                           "  allowed_subnets: [%s]\n"
                           "  dev_allow_all_networks: %s\n";
    char template[]      = "/tmp/vantaq_t05_XXXXXX.yaml";
    char yaml_buf[1024];
    int fd;
    int n;

    fd = mkstemps(template, 5);
    if (fd < 0) {
        return -1;
    }

    if (allowed_subnets == NULL || dev_allow_all == NULL) {
        close(fd);
        unlink(template);
        return -1;
    }

    n = snprintf(yaml_buf, sizeof(yaml_buf), yaml_fmt, port, allowed_subnets, dev_allow_all);
    if (n <= 0 || (size_t)n >= sizeof(yaml_buf)) {
        close(fd);
        unlink(template);
        return -1;
    }

    if (write(fd, yaml_buf, (size_t)n) != n) {
        close(fd);
        unlink(template);
        return -1;
    }

    close(fd);

    if (strlen(template) >= path_out_size) {
        unlink(template);
        return -1;
    }

    strcpy(path_out, template);
    return 0;
}

int make_temp_audit_path(char *path_out, size_t path_out_size) {
    char template[] = "/tmp/vantaq_audit_it_XXXXXX.log";
    int fd          = mkstemps(template, 4);

    if (fd < 0) {
        return -1;
    }
    close(fd);

    if (strlen(template) >= path_out_size) {
        unlink(template);
        return -1;
    }

    strcpy(path_out, template);
    return 0;
}

static int make_temp_ring_path(char *path_out, size_t path_out_size) {
    char template[] = "/tmp/vantaq_evidence_ring_XXXXXX.ring";
    int fd          = mkstemps(template, 5);

    if (fd < 0) {
        return -1;
    }
    close(fd);

    if (strlen(template) >= path_out_size) {
        unlink(template);
        return -1;
    }

    strcpy(path_out, template);
    return 0;
}

int wait_for_server_ready(int port, int timeout_ms) {
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 50 * 1000 * 1000};
    int attempts          = 1;
    int i;

    if (timeout_ms > 50) {
        attempts += (timeout_ms / 50);
    }

    for (i = 0; i < attempts; i++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr;

        if (sock < 0) {
            return -1;
        }

        VANTAQ_ZERO_STRUCT(addr);
        addr.sin_family = AF_INET;
        addr.sin_port   = htons((uint16_t)port);
        if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
            close(sock);
            return -1;
        }

        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            close(sock);
            return 0;
        }

        close(sock);
        if (i + 1 < attempts) {
            nanosleep(&delay, NULL);
        }
    }

    return -1;
}

int request_status_and_body(int port, const char *request, int *status_out, char *body_out,
                            size_t body_out_size) {
    int sock;
    struct sockaddr_in addr;
    char response[1024];
    ssize_t n;
    char *header_end;
    int status = -1;

    if (status_out == NULL || body_out == NULL || body_out_size == 0) {
        return -1;
    }

    body_out[0] = '\0';
    sock        = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }

    VANTAQ_ZERO_STRUCT(addr);
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock);
        return -1;
    }

    if (write(sock, request, strlen(request)) < 0) {
        close(sock);
        return -1;
    }

    n = read(sock, response, sizeof(response) - 1);
    close(sock);
    if (n <= 0) {
        return -1;
    }

    response[n] = '\0';
    if (sscanf(response, "HTTP/1.1 %d", &status) != 1) {
        return -1;
    }

    header_end = strstr(response, "\r\n\r\n");
    if (header_end == NULL) {
        return -1;
    }
    header_end += 4;

    if (strlen(header_end) >= body_out_size) {
        return -1;
    }

    strcpy(body_out, header_end);
    *status_out = status;
    return 0;
}

static int read_text_file(const char *path, char *out, size_t out_size) {
    FILE *file;
    size_t n;

    if (path == NULL || out == NULL || out_size == 0) {
        return -1;
    }

    file = fopen(path, "rb");
    if (file == NULL) {
        return -1;
    }

    n      = fread(out, 1, out_size - 1, file);
    out[n] = '\0';
    fclose(file);
    return 0;
}

static void classify_setup_failure(const char *stderr_text, int child_status, const char *fallback,
                                   char *err, size_t err_len) {
    const char *reason = fallback;

    if (stderr_text != NULL) {
        if (strstr(stderr_text, "bind failed") != NULL) {
            reason = "bind_failed";
        } else if (strstr(stderr_text, "config load failed") != NULL) {
            reason = "config_invalid";
        } else if (strstr(stderr_text, "tls init failed") != NULL) {
            reason = "config_invalid";
        } else if (strstr(stderr_text, "override is not allowed") != NULL) {
            reason = "config_invalid";
        } else if (strstr(stderr_text, "config path is not a regular file") != NULL) {
            reason = "config_invalid";
        }
    }

    if (WIFEXITED(child_status) && WEXITSTATUS(child_status) == 127) {
        reason = "exec_failed";
    }

    if (err != NULL && err_len > 0) {
        if (stderr_text != NULL && stderr_text[0] != '\0') {
            (void)snprintf(err, err_len, "%s: %s", reason, stderr_text);
        } else {
            (void)snprintf(err, err_len, "%s", reason);
        }
    }
}

static int write_server_config(const struct vantaq_test_server_opts *opts, int port,
                               const char *test_tls_key_path, const char *audit_log_path,
                               char *path_out, size_t path_out_size) {
    char template[] = "/tmp/vantaq_it_XXXXXX.yaml";
    char yaml_buf[4096];
    const char *apis;
    const char *allowed_subnets;
    const char *dev_allow_all;
    const char *cert_path;
    const char *supported_claims_yaml;
    const char *measurement_firmware_path;
    const char *measurement_security_config_path;
    const char *measurement_agent_binary_path;
    const char *measurement_boot_state_path;
    const char *device_priv_key_path;
    const char *device_pub_key_path;
    const char *evidence_store_file_path;
    const char *evidence_store_max_records;
    const char *evidence_store_max_record_bytes;
    const char *evidence_store_fsync_on_append;
    int fd;
    int n;

    const char *yaml_fmt = "server:\n"
                           "  listen_address: 127.0.0.1\n"
                           "  listen_port: %d\n"
                           "  version: 0.1.0\n"
                           "  tls:\n"
                           "    enabled: %s\n"
                           "    server_cert_path: %s\n"
                           "    server_key_path: %s\n"
                           "    trusted_client_ca_path: %s\n"
                           "    require_client_cert: %s\n"
                           "\n"
                           "verifiers:\n"
                           "  - verifier_id: govt-verifier-01\n"
                           "    cert_subject_cn: govt-verifier-01\n"
                           "    cert_san_uri: spiffe://vantaqd/verifier/govt-verifier-01\n"
                           "    status: active\n"
                           "    roles:\n"
                           "      - verifier\n"
                           "    allowed_apis:\n"
                           "%s"
                           "\n"
                           "device_identity:\n"
                           "  device_id: edge-gw-001\n"
                           "  model: edge-gateway-v1\n"
                           "  serial_number: SN-001\n"
                           "  manufacturer: ExampleCorp\n"
                           "  firmware_version: 0.1.0-demo\n"
                           "  device_priv_key_path: %s\n"
                           "  device_pub_key_path: %s\n"
                           "\n"
                           "capabilities:\n"
                           "  supported_claims:\n"
                           "%s"
                           "  signature_algorithms: []\n"
                           "  evidence_formats: []\n"
                           "  challenge_modes: []\n"
                           "  storage_modes: []\n"
                           "measurement:\n"
                           "  firmware_path: %s\n"
                           "  security_config_path: %s\n"
                           "  agent_binary_path: %s\n"
                           "  boot_state_path: %s\n"
                           "  max_measurement_file_bytes: 16777216\n"
                           "network_access:\n"
                           "  allowed_subnets: [%s]\n"
                           "  dev_allow_all_networks: %s\n"
                           "audit:\n"
                           "  max_bytes: 1048576\n"
                           "  path: %s\n"
                           "evidence_store:\n"
                           "  file_path: %s\n"
                           "  max_records: %s\n"
                           "  max_record_bytes: %s\n"
                           "  fsync_on_append: %s\n"
                           "%s";

    apis = opts->allowed_apis_yaml != NULL ? opts->allowed_apis_yaml : "      - GET /v1/health\n";
    allowed_subnets = opts->allowed_subnets != NULL ? opts->allowed_subnets : "127.0.0.1/32";
    dev_allow_all   = opts->dev_allow_all_networks != NULL ? opts->dev_allow_all_networks : "false";
    cert_path       = opts->tls_enabled ? "config/certs/device-server.crt" : "/etc/hosts";
    supported_claims_yaml = opts->supported_claims_yaml != NULL ? opts->supported_claims_yaml
                                                                : "    - device_identity\n";
    measurement_firmware_path =
        opts->measurement_firmware_path != NULL ? opts->measurement_firmware_path : "/etc/hosts";
    measurement_security_config_path = opts->measurement_security_config_path != NULL
                                           ? opts->measurement_security_config_path
                                           : "/etc/hosts";
    measurement_agent_binary_path    = opts->measurement_agent_binary_path != NULL
                                           ? opts->measurement_agent_binary_path
                                           : "/etc/hosts";
    measurement_boot_state_path      = opts->measurement_boot_state_path != NULL
                                           ? opts->measurement_boot_state_path
                                           : "/etc/hosts";
    device_priv_key_path = opts->device_priv_key_path != NULL ? opts->device_priv_key_path
                                                              : "config/certs/device-server.key";
    device_pub_key_path  = opts->device_pub_key_path != NULL ? opts->device_pub_key_path
                                                             : "config/certs/device-server.crt";
    evidence_store_file_path = opts->evidence_store_file_path != NULL
                                   ? opts->evidence_store_file_path
                                   : "/tmp/vantaq_evidence_default.ring";
    evidence_store_max_records =
        opts->evidence_store_max_records != NULL ? opts->evidence_store_max_records : "1024";
    evidence_store_max_record_bytes = opts->evidence_store_max_record_bytes != NULL
                                          ? opts->evidence_store_max_record_bytes
                                          : "8192";
    evidence_store_fsync_on_append  = opts->evidence_store_fsync_on_append != NULL
                                          ? opts->evidence_store_fsync_on_append
                                          : "true";

    fd = mkstemps(template, 5);
    if (fd < 0) {
        return -1;
    }

    n = snprintf(yaml_buf, sizeof(yaml_buf), yaml_fmt, port, opts->tls_enabled ? "true" : "false",
                 cert_path,
                 opts->tls_enabled ? "config/certs/device-server.key" : test_tls_key_path,
                 opts->tls_enabled ? "config/certs/verifier-ca.crt" : "/etc/hosts",
                 opts->require_client_cert ? "true" : "false", apis, device_priv_key_path,
                 device_pub_key_path, supported_claims_yaml, measurement_firmware_path,
                 measurement_security_config_path, measurement_agent_binary_path,
                 measurement_boot_state_path, allowed_subnets, dev_allow_all, audit_log_path,
                 evidence_store_file_path, evidence_store_max_records,
                 evidence_store_max_record_bytes, evidence_store_fsync_on_append,
                 opts->include_challenge
                     ? "challenge:\n  ttl_seconds: 60\n  max_global: 100\n  max_per_verifier: 10\n"
                     : "");
    if (n <= 0 || (size_t)n >= sizeof(yaml_buf)) {
        close(fd);
        unlink(template);
        return -1;
    }

    if (write(fd, yaml_buf, (size_t)n) != n) {
        close(fd);
        unlink(template);
        return -1;
    }

    close(fd);

    if (strlen(template) >= path_out_size) {
        unlink(template);
        return -1;
    }

    strcpy(path_out, template);
    return 0;
}

static int make_temp_log_path(char *path_out, size_t path_out_size) {
    char template[] = "/tmp/vantaq_it_stderr_XXXXXX.log";
    int fd          = mkstemps(template, 4);

    if (fd < 0) {
        return -1;
    }
    close(fd);

    if (strlen(template) >= path_out_size) {
        unlink(template);
        return -1;
    }

    strcpy(path_out, template);
    return 0;
}

static int make_temp_private_key_path(char *path_out, size_t path_out_size) {
    char template[]                 = "/tmp/vantaq_it_key_XXXXXX.pem";
    int fd                          = mkstemps(template, 4);
    static const char k_dummy_key[] = "dummy-private-key-for-tests\n";

    if (fd < 0) {
        return -1;
    }

    if (write(fd, k_dummy_key, sizeof(k_dummy_key) - 1) != (ssize_t)(sizeof(k_dummy_key) - 1)) {
        close(fd);
        unlink(template);
        return -1;
    }
    close(fd);

    if (chmod(template, S_IRUSR | S_IWUSR) != 0) {
        unlink(template);
        return -1;
    }

    if (strlen(template) >= path_out_size) {
        unlink(template);
        return -1;
    }

    strcpy(path_out, template);
    return 0;
}

int vantaq_test_server_start(const struct vantaq_test_server_opts *opts,
                             struct vantaq_test_server_handle *handle, char *err, size_t err_len) {
    struct vantaq_test_server_opts defaults;
    bool has_fixed_evidence_store_path;
    int retries;
    int attempt;

    if (opts == NULL || handle == NULL) {
        return -1;
    }

    VANTAQ_ZERO_STRUCT(defaults);
    defaults.tls_enabled                      = false;
    defaults.require_client_cert              = true;
    defaults.include_challenge                = false;
    defaults.allowed_subnets                  = "127.0.0.1/32";
    defaults.dev_allow_all_networks           = "false";
    defaults.allowed_apis_yaml                = "      - GET /v1/health\n";
    defaults.supported_claims_yaml            = "    - device_identity\n";
    defaults.measurement_firmware_path        = "/etc/hosts";
    defaults.measurement_security_config_path = "/etc/hosts";
    defaults.measurement_agent_binary_path    = "/etc/hosts";
    defaults.measurement_boot_state_path      = "/etc/hosts";
    defaults.device_priv_key_path             = "config/certs/device-server.key";
    defaults.device_pub_key_path              = "config/certs/device-server.crt";
    defaults.evidence_store_file_path         = NULL;
    defaults.evidence_store_max_records       = "1024";
    defaults.evidence_store_max_record_bytes  = "8192";
    defaults.evidence_store_fsync_on_append   = "true";
    defaults.startup_timeout_ms               = 0;
    defaults.max_start_retries                = 1;

    if (opts->allowed_subnets == NULL) {
        defaults.allowed_subnets = "127.0.0.1/32";
    } else {
        defaults.allowed_subnets = opts->allowed_subnets;
    }
    if (opts->dev_allow_all_networks != NULL) {
        defaults.dev_allow_all_networks = opts->dev_allow_all_networks;
    }
    if (opts->allowed_apis_yaml != NULL) {
        defaults.allowed_apis_yaml = opts->allowed_apis_yaml;
    }
    if (opts->supported_claims_yaml != NULL) {
        defaults.supported_claims_yaml = opts->supported_claims_yaml;
    }
    if (opts->measurement_firmware_path != NULL) {
        defaults.measurement_firmware_path = opts->measurement_firmware_path;
    }
    if (opts->measurement_security_config_path != NULL) {
        defaults.measurement_security_config_path = opts->measurement_security_config_path;
    }
    if (opts->measurement_agent_binary_path != NULL) {
        defaults.measurement_agent_binary_path = opts->measurement_agent_binary_path;
    }
    if (opts->measurement_boot_state_path != NULL) {
        defaults.measurement_boot_state_path = opts->measurement_boot_state_path;
    }
    if (opts->device_priv_key_path != NULL) {
        defaults.device_priv_key_path = opts->device_priv_key_path;
    }
    if (opts->device_pub_key_path != NULL) {
        defaults.device_pub_key_path = opts->device_pub_key_path;
    }
    if (opts->evidence_store_file_path != NULL) {
        defaults.evidence_store_file_path = opts->evidence_store_file_path;
    }
    if (opts->evidence_store_max_records != NULL) {
        defaults.evidence_store_max_records = opts->evidence_store_max_records;
    }
    if (opts->evidence_store_max_record_bytes != NULL) {
        defaults.evidence_store_max_record_bytes = opts->evidence_store_max_record_bytes;
    }
    if (opts->evidence_store_fsync_on_append != NULL) {
        defaults.evidence_store_fsync_on_append = opts->evidence_store_fsync_on_append;
    }
    defaults.tls_enabled         = opts->tls_enabled;
    defaults.require_client_cert = opts->require_client_cert;
    defaults.include_challenge   = opts->include_challenge;
    if (opts->startup_timeout_ms > 0) {
        defaults.startup_timeout_ms = opts->startup_timeout_ms;
    }
    if (opts->max_start_retries > 0) {
        defaults.max_start_retries = opts->max_start_retries;
    }
    has_fixed_evidence_store_path = defaults.evidence_store_file_path != NULL;
    VANTAQ_ZERO_STRUCT(*handle);
    retries = defaults.max_start_retries;

    for (attempt = 0; attempt < retries; attempt++) {
        int port;
        int stderr_fd;
        int status;
        char stderr_text[2048];

        if (!has_fixed_evidence_store_path) {
            defaults.evidence_store_file_path = NULL;
        }

        port = reserve_ephemeral_port();
        if (port <= 0) {
            if (err != NULL && err_len > 0) {
                (void)snprintf(err, err_len, "startup_timeout: unable to reserve port");
            }
            return -1;
        }

        if (make_temp_private_key_path(handle->tls_key_path, sizeof(handle->tls_key_path)) != 0 ||
            make_temp_audit_path(handle->audit_path, sizeof(handle->audit_path)) != 0 ||
            strlen(handle->audit_path) >= VANTAQ_MAX_FIELD_LEN) {
            if (err != NULL && err_len > 0) {
                (void)snprintf(err, err_len, "config_invalid: failed to create temp files");
            }
            vantaq_test_server_stop(handle);
            return -1;
        }

        if (defaults.evidence_store_file_path == NULL) {
            if (make_temp_ring_path(handle->ring_path, sizeof(handle->ring_path)) != 0 ||
                strlen(handle->ring_path) >= VANTAQ_MAX_FIELD_LEN) {
                if (err != NULL && err_len > 0) {
                    (void)snprintf(err, err_len, "config_invalid: failed to create temp ring path");
                }
                vantaq_test_server_stop(handle);
                return -1;
            }
            defaults.evidence_store_file_path = handle->ring_path;
        }
        if (write_server_config(&defaults, port, handle->tls_key_path, handle->audit_path,
                                handle->cfg_path, sizeof(handle->cfg_path)) != 0 ||
            make_temp_log_path(handle->stderr_path, sizeof(handle->stderr_path)) != 0) {
            if (err != NULL && err_len > 0) {
                (void)snprintf(err, err_len, "config_invalid: failed to create temp files");
            }
            vantaq_test_server_stop(handle);
            return -1;
        }

        handle->port      = port;
        handle->child_pid = fork();
        if (handle->child_pid < 0) {
            if (err != NULL && err_len > 0) {
                (void)snprintf(err, err_len, "fork_failed");
            }
            vantaq_test_server_stop(handle);
            return -1;
        }

        if (handle->child_pid == 0) {
            stderr_fd = open(handle->stderr_path, O_WRONLY | O_TRUNC);
            if (stderr_fd >= 0) {
                (void)dup2(stderr_fd, STDOUT_FILENO);
                (void)dup2(stderr_fd, STDERR_FILENO);
                close(stderr_fd);
            }

            execl("./bin/vantaqd", "vantaqd", "--config", handle->cfg_path, (char *)NULL);
            _exit(127);
        }

        if (wait_for_server_ready(handle->port, defaults.startup_timeout_ms) == 0) {
            handle->running = true;
            if (err != NULL && err_len > 0) {
                err[0] = '\0';
            }
            return 0;
        }

        (void)kill(handle->child_pid, SIGTERM);
        (void)waitpid(handle->child_pid, &status, 0);

        if (read_text_file(handle->stderr_path, stderr_text, sizeof(stderr_text)) != 0) {
            stderr_text[0] = '\0';
        }
        classify_setup_failure(stderr_text, status, "startup_timeout", err, err_len);

        vantaq_test_server_stop(handle);

        if (strstr(err != NULL ? err : "", "bind_failed") == NULL &&
            strstr(err != NULL ? err : "", "startup_timeout") == NULL) {
            return -1;
        }
    }

    return -1;
}

void vantaq_test_server_stop(struct vantaq_test_server_handle *handle) {
    if (handle == NULL) {
        return;
    }

    if (handle->running && handle->child_pid > 0) {
        (void)kill(handle->child_pid, SIGTERM);
        (void)waitpid(handle->child_pid, NULL, 0);
    }

    if (handle->cfg_path[0] != '\0') {
        (void)unlink(handle->cfg_path);
    }
    if (handle->audit_path[0] != '\0') {
        (void)unlink(handle->audit_path);
    }
    if (handle->ring_path[0] != '\0') {
        (void)unlink(handle->ring_path);
    }
    if (handle->stderr_path[0] != '\0') {
        (void)unlink(handle->stderr_path);
    }
    if (handle->tls_key_path[0] != '\0') {
        (void)unlink(handle->tls_key_path);
    }

    VANTAQ_ZERO_STRUCT(*handle);
}
