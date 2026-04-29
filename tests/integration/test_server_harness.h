// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#ifndef VANTAQ_TEST_SERVER_HARNESS_H
#define VANTAQ_TEST_SERVER_HARNESS_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

struct vantaq_test_server_opts {
    bool tls_enabled;
    bool require_client_cert;
    bool include_challenge;
    const char *allowed_subnets;
    const char *dev_allow_all_networks;
    const char *allowed_apis_yaml;
    const char *supported_claims_yaml;
    const char *measurement_firmware_path;
    const char *measurement_security_config_path;
    const char *measurement_agent_binary_path;
    const char *measurement_boot_state_path;
    int startup_timeout_ms;
    int max_start_retries;
};

struct vantaq_test_server_handle {
    int port;
    pid_t child_pid;
    bool running;
    char cfg_path[256];
    char audit_path[256];
    char stderr_path[256];
    char tls_key_path[256];
};

int reserve_ephemeral_port(void);
int wait_for_server_ready(int port, int timeout_ms);
int request_status_and_body(int port, const char *request, int *status_out, char *body_out,
                            size_t body_out_size);
int write_temp_yaml(int port, const char *allowed_subnets, const char *dev_allow_all,
                    char *path_out, size_t path_out_size);
int make_temp_audit_path(char *path_out, size_t path_out_size);

int vantaq_test_server_start(const struct vantaq_test_server_opts *opts,
                             struct vantaq_test_server_handle *handle, char *err, size_t err_len);
void vantaq_test_server_stop(struct vantaq_test_server_handle *handle);

#endif
