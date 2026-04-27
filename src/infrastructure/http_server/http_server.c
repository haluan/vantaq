// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#define _POSIX_C_SOURCE 200809L

#include "infrastructure/http_server.h"
#include "application/security/verifier_context.h"
#include "application/security/verifier_lookup.h"
#include "domain/verifier_access/verifier_policy.h"
#include "infrastructure/audit_log.h"
#include "infrastructure/config_loader.h"
#include "infrastructure/socket_peer.h"
#include "infrastructure/subnet_policy.h"
#include "infrastructure/tls/client_cert.h"
#include "infrastructure/tls_server.h"
#include <openssl/x509.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define VANTAQ_HTTP_REQ_BUF_SIZE 2048
#define VANTAQ_HTTP_RECV_TIMEOUT_SECONDS 5

static volatile sig_atomic_t g_stop_requested = 0;
static volatile int g_listener_fd             = -1;

// Rule: Response JSON buffers must be sized based on maximum possible field lengths
// Each field can be up to VANTAQ_MAX_FIELD_LEN, plus escaping overhead.
// We use a safe multiplier to account for JSON escaping (\uXXXX etc).
#define VANTAQ_JSON_ESC_FACTOR 6
#define VANTAQ_JSON_FIELD_MAX (VANTAQ_MAX_FIELD_LEN * VANTAQ_JSON_ESC_FACTOR)

#define VANTAQ_HEALTH_JSON_BUF_SIZE (VANTAQ_JSON_FIELD_MAX * 2 + 256)
#define VANTAQ_IDENTITY_JSON_BUF_SIZE (VANTAQ_JSON_FIELD_MAX * 5 + 512)
// For capabilities, we have 5 lists of up to VANTAQ_MAX_LIST_ITEMS strings.
#define VANTAQ_CAPABILITIES_JSON_BUF_SIZE (VANTAQ_MAX_LIST_ITEMS * VANTAQ_JSON_FIELD_MAX * 5 + 2048)

#define VANTAQ_ZERO_STRUCT(s) memset(&(s), 0, sizeof(s))

#include "http_server_internal.h"

static int log_text(vantaq_http_log_fn logger, void *ctx, const char *text) {
    if (logger != NULL && text != NULL) {
        return logger(ctx, text);
    }
    return 0;
}

static void handle_term_signal(int signum) {
    (void)signum;
    g_stop_requested = 1;
    int fd           = g_listener_fd;
    if (fd >= 0) {
        g_listener_fd = -1;
        (void)close(fd);
    }
}

static ssize_t connection_read(struct vantaq_http_connection *connection, void *buf, size_t len) {
    if (connection == NULL || buf == NULL || len == 0) {
        errno = EINVAL;
        return -1;
    }

    if (connection->tls_connection != NULL) {
        return vantaq_tls_connection_read(connection->tls_connection, buf, len);
    }

    return recv(connection->fd, buf, len, 0);
}

static ssize_t connection_write(struct vantaq_http_connection *connection, const void *buf,
                                size_t len) {
    if (connection == NULL || buf == NULL || len == 0) {
        errno = EINVAL;
        return -1;
    }

    if (connection->tls_connection != NULL) {
        return vantaq_tls_connection_write(connection->tls_connection, buf, len);
    }

    return send(connection->fd, buf, len, 0);
}

int vantaq_http_write_all(struct vantaq_http_connection *connection, const char *buf, size_t len) {
    size_t sent = 0;

    while (sent < len) {
        ssize_t n = connection_write(connection, buf + sent, len - sent);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        sent += (size_t)n;
    }

    return 0;
}

int vantaq_http_send_status_response(struct vantaq_http_connection *connection, int status_code) {
    const char *status_text = "Internal Server Error";
    char response[160];
    int n;

    if (status_code == 404) {
        status_text = "Not Found";
    } else if (status_code == 405) {
        status_text = "Method Not Allowed";
    } else if (status_code == 400) {
        status_text = "Bad Request";
    } else if (status_code == 403) {
        status_text = "Forbidden";
    }

    n = snprintf(response, sizeof(response),
                 "HTTP/1.1 %d %s\r\n"
                 "Content-Length: 0\r\n"
                 "Connection: close\r\n"
                 "\r\n",
                 status_code, status_text);
    if (n <= 0 || (size_t)n >= sizeof(response)) {
        return -1;
    }
    return vantaq_http_write_all(connection, response, (size_t)n);
}

static int send_subnet_denied_response(struct vantaq_http_connection *connection,
                                       const char *request_id) {
    char json_body[256];
    char response[512];
    int n_body, n_resp;

    if (request_id == NULL) {
        request_id = "unknown";
    }

    n_body = snprintf(json_body, sizeof(json_body),
                      "{\"error\":{\"code\":\"SUBNET_NOT_ALLOWED\","
                      "\"message\":\"Requester source network is not allowed.\","
                      "\"request_id\":\"%s\"}}\n",
                      request_id);
    if (n_body <= 0 || (size_t)n_body >= sizeof(json_body)) {
        return -1;
    }

    n_resp = snprintf(response, sizeof(response),
                      "HTTP/1.1 403 Forbidden\r\n"
                      "Content-Type: application/json\r\n"
                      "Content-Length: %d\r\n"
                      "Connection: close\r\n"
                      "\r\n"
                      "%s",
                      n_body, json_body);
    if (n_resp <= 0 || (size_t)n_resp >= sizeof(response)) {
        return -1;
    }

    return vantaq_http_write_all(connection, response, (size_t)n_resp);
}

static int send_mtls_required_response(struct vantaq_http_connection *connection) {
    char json_body[192];
    char response[384];
    int n_body;
    int n_resp;

    n_body = snprintf(json_body, sizeof(json_body),
                      "{\"error\":{\"code\":\"MTLS_REQUIRED\","
                      "\"message\":\"Valid verifier client certificate is required.\"}}\n");
    if (n_body <= 0 || (size_t)n_body >= sizeof(json_body)) {
        return -1;
    }

    n_resp = snprintf(response, sizeof(response),
                      "HTTP/1.1 401 Unauthorized\r\n"
                      "Content-Type: application/json\r\n"
                      "Content-Length: %d\r\n"
                      "Connection: close\r\n"
                      "\r\n"
                      "%s",
                      n_body, json_body);
    if (n_resp <= 0 || (size_t)n_resp >= sizeof(response)) {
        return -1;
    }

    return vantaq_http_write_all(connection, response, (size_t)n_resp);
}

static long long elapsed_seconds_since(const struct timespec *started_at) {
    struct timespec now;
    long long sec;

    if (started_at == NULL || clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }

    sec = (long long)(now.tv_sec - started_at->tv_sec);
    if (sec < 0) {
        return 0;
    }
    return sec;
}

static int append_jsonf(char *buf, size_t buf_size, size_t *used, const char *fmt, ...) {
    va_list args;
    int n;

    if (buf == NULL || used == NULL || fmt == NULL || *used >= buf_size) {
        return -1;
    }

    va_start(args, fmt);
    n = vsnprintf(buf + *used, buf_size - *used, fmt, args);
    va_end(args);
    if (n < 0 || (size_t)n >= buf_size - *used) {
        return -1;
    }

    *used += (size_t)n;
    return 0;
}

static int append_json_str(char *buf, size_t buf_size, size_t *used, const char *str) {
    if (buf == NULL || used == NULL || str == NULL) {
        return -1;
    }

    if (append_jsonf(buf, buf_size, used, "\"") != 0) {
        return -1;
    }

    while (*str != '\0') {
        const char *esc = NULL;
        switch (*str) {
        case '\"':
            esc = "\\\"";
            break;
        case '\\':
            esc = "\\\\";
            break;
        case '\b':
            esc = "\\b";
            break;
        case '\f':
            esc = "\\f";
            break;
        case '\n':
            esc = "\\n";
            break;
        case '\r':
            esc = "\\r";
            break;
        case '\t':
            esc = "\\t";
            break;
        default:
            if ((unsigned char)*str < 32) {
                if (append_jsonf(buf, buf_size, used, "\\u%04x", (unsigned char)*str) != 0) {
                    return -1;
                }
            } else {
                if (*used >= buf_size - 1) {
                    return -1;
                }
                buf[(*used)++] = *str;
                buf[*used]     = '\0';
            }
            break;
        }
        if (esc != NULL) {
            if (append_jsonf(buf, buf_size, used, "%s", esc) != 0) {
                return -1;
            }
        }
        str++;
    }

    if (append_jsonf(buf, buf_size, used, "\"") != 0) {
        return -1;
    }

    return 0;
}

static int append_json_string_array(char *buf, size_t json_size, size_t *used, const char *key,
                                    const char *const *items, size_t count, bool trailing_comma) {
    size_t i;

    if (append_jsonf(buf, json_size, used, "\"%s\":[", key) != 0) {
        return -1;
    }

    for (i = 0; i < count; i++) {
        if (append_json_str(buf, json_size, used, items[i]) != 0) {
            return -1;
        }

        if (i < count - 1) {
            if (append_jsonf(buf, json_size, used, ",") != 0) {
                return -1;
            }
        }
    }

    if (trailing_comma) {
        return append_jsonf(buf, json_size, used, "],");
    }
    return append_jsonf(buf, json_size, used, "]");
}

static int send_health_response(struct vantaq_http_connection *connection,
                                const struct vantaq_http_health_context *ctx) {
    char json[VANTAQ_HEALTH_JSON_BUF_SIZE];
    char response[VANTAQ_HEALTH_JSON_BUF_SIZE + 256];
    int json_n;
    int response_n;
    long long uptime_seconds;
    size_t used;

    VANTAQ_ZERO_STRUCT(json);
    VANTAQ_ZERO_STRUCT(response);

    if (ctx == NULL || ctx->service_name == NULL || ctx->service_version == NULL) {
        return -1;
    }

    uptime_seconds = elapsed_seconds_since(&ctx->started_at);
    used           = 0;

    if (append_jsonf(json, sizeof(json), &used, "{\"status\":\"ok\",\"service\":") != 0 ||
        append_json_str(json, sizeof(json), &used, ctx->service_name) != 0 ||
        append_jsonf(json, sizeof(json), &used, ",\"version\":") != 0 ||
        append_json_str(json, sizeof(json), &used, ctx->service_version) != 0 ||
        append_jsonf(json, sizeof(json), &used, ",\"uptime_seconds\":%lld}\n", uptime_seconds) !=
            0) {
        return -1;
    }

    json_n = (int)used;

    response_n = snprintf(response, sizeof(response),
                          "HTTP/1.1 200 OK\r\n"
                          "Content-Type: application/json\r\n"
                          "Content-Length: %d\r\n"
                          "Connection: close\r\n"
                          "\r\n"
                          "%s",
                          json_n, json);
    if (response_n <= 0 || (size_t)response_n >= sizeof(response)) {
        return -1;
    }

    return vantaq_http_write_all(connection, response, (size_t)response_n);
}

static int send_identity_response(struct vantaq_http_connection *connection,
                                  const struct vantaq_http_health_context *ctx) {
    char json[VANTAQ_IDENTITY_JSON_BUF_SIZE];
    char response[VANTAQ_IDENTITY_JSON_BUF_SIZE + 256];
    int json_n;
    int response_n;
    size_t used;

    VANTAQ_ZERO_STRUCT(json);
    VANTAQ_ZERO_STRUCT(response);

    if (ctx == NULL || ctx->device_id == NULL || ctx->device_model == NULL ||
        ctx->device_serial_number == NULL || ctx->device_manufacturer == NULL ||
        ctx->device_firmware_version == NULL) {
        return -1;
    }

    used = 0;
    if (append_jsonf(json, sizeof(json), &used, "{\"device_id\":") != 0 ||
        append_json_str(json, sizeof(json), &used, ctx->device_id) != 0 ||
        append_jsonf(json, sizeof(json), &used, ",\"model\":") != 0 ||
        append_json_str(json, sizeof(json), &used, ctx->device_model) != 0 ||
        append_jsonf(json, sizeof(json), &used, ",\"serial_number\":") != 0 ||
        append_json_str(json, sizeof(json), &used, ctx->device_serial_number) != 0 ||
        append_jsonf(json, sizeof(json), &used, ",\"manufacturer\":") != 0 ||
        append_json_str(json, sizeof(json), &used, ctx->device_manufacturer) != 0 ||
        append_jsonf(json, sizeof(json), &used, ",\"firmware_version\":") != 0 ||
        append_json_str(json, sizeof(json), &used, ctx->device_firmware_version) != 0 ||
        append_jsonf(json, sizeof(json), &used, "}\n") != 0) {
        return -1;
    }

    json_n = (int)used;

    response_n = snprintf(response, sizeof(response),
                          "HTTP/1.1 200 OK\r\n"
                          "Content-Type: application/json\r\n"
                          "Content-Length: %d\r\n"
                          "Connection: close\r\n"
                          "\r\n"
                          "%s",
                          json_n, json);
    if (response_n <= 0 || (size_t)response_n >= sizeof(response)) {
        return -1;
    }

    return vantaq_http_write_all(connection, response, (size_t)response_n);
}

static int send_capabilities_response(struct vantaq_http_connection *connection,
                                      const struct vantaq_http_health_context *ctx) {
    char *json;
    char response_header[512];
    size_t used = 0;
    int header_n, json_n;
    int result = 0;

    if (ctx == NULL || ctx->supported_claims == NULL || ctx->signature_algorithms == NULL ||
        ctx->evidence_formats == NULL || ctx->challenge_modes == NULL ||
        ctx->storage_modes == NULL) {
        return -1;
    }

    json = (char *)malloc(VANTAQ_CAPABILITIES_JSON_BUF_SIZE);
    if (json == NULL) {
        return -1;
    }

    VANTAQ_ZERO_STRUCT(response_header);
    json[0] = '\0';

    if (append_jsonf(json, VANTAQ_CAPABILITIES_JSON_BUF_SIZE, &used, "{") != 0 ||
        append_json_string_array(json, VANTAQ_CAPABILITIES_JSON_BUF_SIZE, &used, "supported_claims",
                                 ctx->supported_claims, ctx->supported_claims_count, true) != 0 ||
        append_json_string_array(json, VANTAQ_CAPABILITIES_JSON_BUF_SIZE, &used,
                                 "signature_algorithms", ctx->signature_algorithms,
                                 ctx->signature_algorithms_count, true) != 0 ||
        append_json_string_array(json, VANTAQ_CAPABILITIES_JSON_BUF_SIZE, &used, "evidence_formats",
                                 ctx->evidence_formats, ctx->evidence_formats_count, true) != 0 ||
        append_json_string_array(json, VANTAQ_CAPABILITIES_JSON_BUF_SIZE, &used, "challenge_modes",
                                 ctx->challenge_modes, ctx->challenge_modes_count, true) != 0 ||
        append_json_string_array(json, VANTAQ_CAPABILITIES_JSON_BUF_SIZE, &used, "storage_modes",
                                 ctx->storage_modes, ctx->storage_modes_count, false) != 0 ||
        append_jsonf(json, VANTAQ_CAPABILITIES_JSON_BUF_SIZE, &used, "}\n") != 0) {
        free(json);
        return -1;
    }

    json_n   = (int)used;
    header_n = snprintf(response_header, sizeof(response_header),
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: application/json\r\n"
                        "Content-Length: %d\r\n"
                        "Connection: close\r\n"
                        "\r\n",
                        json_n);

    if (header_n <= 0 || (size_t)header_n >= sizeof(response_header)) {
        free(json);
        return -1;
    }

    if (vantaq_http_write_all(connection, response_header, (size_t)header_n) != 0) {
        free(json);
        return -1;
    }

    result = vantaq_http_write_all(connection, json, (size_t)json_n);
    free(json);
    return result;
}

static int parse_request_line(const char *buf, char *method, size_t method_size, char *path,
                              size_t path_size) {
    char fmt[32];

    if (method == NULL || method_size == 0 || path == NULL || path_size == 0) {
        return -1;
    }

    // We dynamically construct the sscanf format string using the provided buffer sizes
    // to prevent overflows if the caller ever changes the buffer definitions.
    // method_size - 1 and path_size - 1 account for the NUL terminator.
    const char *const sscanf_fmt_template = "%%%zus %%%zus";
    if (snprintf(fmt, sizeof(fmt), sscanf_fmt_template, method_size - 1, path_size - 1) <= 0) {
        return -1;
    }

    if (sscanf(buf, fmt, method, path) != 2) {
        return -1;
    }

    return 0;
}

static int get_route_info(const char *method, const char *path, bool *is_protected) {
    if (is_protected != NULL) {
        *is_protected = false;
    }

    if (strcmp(path, "/v1/health") == 0) {
        if (strcmp(method, "GET") == 0) {
            if (is_protected != NULL) {
                *is_protected = true;
            }
            return 200;
        }
        return 405;
    }

    if (strcmp(path, "/v1/device/identity") == 0) {
        if (strcmp(method, "GET") == 0) {
            if (is_protected != NULL) {
                *is_protected = true;
            }
            return 200;
        }
        return 405;
    }

    if (strcmp(path, "/v1/device/capabilities") == 0) {
        if (strcmp(method, "GET") == 0) {
            if (is_protected != NULL) {
                *is_protected = true;
            }
            return 200;
        }
        return 405;
    }

    if (strncmp(path, "/v1/security/verifiers/", 23) == 0) {
        if (strcmp(method, "GET") == 0) {
            if (is_protected != NULL) {
                *is_protected = true;
            }
            return 200;
        }
        return 405;
    }

    return 404;
}

static void handle_client(struct vantaq_http_connection *connection,
                          const struct vantaq_http_health_context *health_ctx) {
    char req_buf[VANTAQ_HTTP_REQ_BUF_SIZE];
    size_t total_read = 0;
    char method[16];
    char path[256];
    char log_buf[512];
    struct vantaq_http_request_context request_ctx;
    struct vantaq_subnet_policy_input subnet_input;
    enum vantaq_subnet_policy_decision subnet_decision;
    enum vantaq_subnet_policy_status subnet_status;
    enum vantaq_audit_log_status audit_status;
    int status_code;
    struct timeval tv;

    VANTAQ_ZERO_STRUCT(req_buf);
    VANTAQ_ZERO_STRUCT(method);
    VANTAQ_ZERO_STRUCT(path);
    VANTAQ_ZERO_STRUCT(log_buf);
    VANTAQ_ZERO_STRUCT(request_ctx);
    VANTAQ_ZERO_STRUCT(subnet_input);

    request_ctx.peer_status = vantaq_peer_address_get_ipv4(connection->fd, request_ctx.peer_ipv4,
                                                           sizeof(request_ctx.peer_ipv4));
    request_ctx.peer_ip_ok  = (request_ctx.peer_status == VANTAQ_PEER_ADDRESS_STATUS_OK);
    request_ctx.verifier_auth.cbSize = sizeof(request_ctx.verifier_auth);
    request_ctx.verifier_auth.status = VANTAQ_VERIFIER_AUTH_STATUS_UNAUTHENTICATED;
    if (vantaq_tls_connection_peer_cert_verified(connection->tls_connection)) {
        void *peer_cert;
        request_ctx.verifier_auth.status = VANTAQ_VERIFIER_AUTH_STATUS_AUTHENTICATED;
        peer_cert = vantaq_tls_connection_get_peer_certificate(connection->tls_connection);
        if (peer_cert != NULL) {
            (void)vantaq_tls_extract_verifier_id(peer_cert, &request_ctx.verifier_auth.identity);
            vantaq_tls_connection_free_peer_certificate(peer_cert);
        }
    }

    tv.tv_sec  = VANTAQ_HTTP_RECV_TIMEOUT_SECONDS;
    tv.tv_usec = 0;
    if (setsockopt(connection->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        goto cleanup;
    }

    while (total_read < sizeof(req_buf) - 1) {
        ssize_t n =
            connection_read(connection, req_buf + total_read, sizeof(req_buf) - 1 - total_read);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                (void)snprintf(log_buf, sizeof(log_buf), "http server: recv timeout from %s\n",
                               request_ctx.peer_ip_ok ? request_ctx.peer_ipv4 : "unknown");
                (void)log_text(health_ctx->err_logger, health_ctx->io_ctx, log_buf);
            }
            goto cleanup;
        }
        if (n == 0) {
            break;
        }

        total_read += (size_t)n;
        req_buf[total_read] = '\0';
        if (strstr(req_buf, "\n") != NULL) {
            break;
        }
    }

    if (total_read == 0) {
        goto cleanup;
    }

    if (parse_request_line(req_buf, method, sizeof(method), path, sizeof(path)) != 0) {
        (void)vantaq_http_send_status_response(connection, 400);
        goto cleanup;
    }

    subnet_input.cbSize                 = sizeof(subnet_input);
    status_code                         = get_route_info(method, path, &subnet_input.is_protected);
    subnet_input.peer_status            = request_ctx.peer_status;
    subnet_input.peer_ipv4              = request_ctx.peer_ip_ok ? request_ctx.peer_ipv4 : NULL;
    subnet_input.allowed_subnets        = health_ctx->allowed_subnets;
    subnet_input.allowed_subnets_count  = health_ctx->allowed_subnets_count;
    subnet_input.dev_allow_all_networks = health_ctx->dev_allow_all_networks;

    subnet_status = vantaq_subnet_policy_evaluate(&subnet_input, &subnet_decision);
    if (subnet_status != VANTAQ_SUBNET_POLICY_STATUS_OK) {
        (void)snprintf(log_buf, sizeof(log_buf), "http server: subnet policy failed: %s\n",
                       vantaq_subnet_policy_status_text(subnet_status));
        (void)log_text(health_ctx->err_logger, health_ctx->io_ctx, log_buf);
        (void)vantaq_http_send_status_response(connection, 500);
        goto cleanup;
    }

    if (subnet_decision == VANTAQ_SUBNET_POLICY_DECISION_DENY) {
        static uint64_t request_counter = 0;
        char request_id[32];
        struct vantaq_audit_event audit_event;
        const char *peer_text = request_ctx.peer_ip_ok
                                    ? request_ctx.peer_ipv4
                                    : vantaq_peer_address_status_text(request_ctx.peer_status);

        (void)snprintf(request_id, sizeof(request_id), "req-%06llu",
                       (unsigned long long)++request_counter);

        VANTAQ_ZERO_STRUCT(audit_event);
        audit_event.cbSize                 = sizeof(audit_event);
        audit_event.time_utc_epoch_seconds = time(NULL);
        audit_event.source_ip  = request_ctx.peer_ip_ok ? request_ctx.peer_ipv4 : "unknown";
        audit_event.method     = method;
        audit_event.path       = path;
        audit_event.result     = "DENY";
        audit_event.reason     = "SUBNET_NOT_ALLOWED";
        audit_event.request_id = request_id;

        audit_status = vantaq_audit_log_append(health_ctx->audit_log, &audit_event);
        if (audit_status != VANTAQ_AUDIT_LOG_STATUS_OK) {
            const char *last_error = vantaq_audit_log_last_error(health_ctx->audit_log);
            (void)snprintf(log_buf, sizeof(log_buf), "http server: audit append failed: %s (%s)\n",
                           vantaq_audit_log_status_text(audit_status),
                           last_error != NULL ? last_error : "unknown");
            (void)log_text(health_ctx->err_logger, health_ctx->io_ctx, log_buf);
        }

        (void)snprintf(log_buf, sizeof(log_buf), "http server: subnet denied %s %s peer=%s\n",
                       method, path, peer_text);
        (void)log_text(health_ctx->err_logger, health_ctx->io_ctx, log_buf);

        if (send_subnet_denied_response(connection, request_id) != 0) {
            (void)log_text(health_ctx->err_logger, health_ctx->io_ctx,
                           "http server: failed to send subnet denied response\n");
        }
        goto cleanup;
    }

    if (status_code == 200 &&
        (strcmp(path, "/v1/health") == 0 || strcmp(path, "/v1/device/identity") == 0 ||
         strcmp(path, "/v1/device/capabilities") == 0)) {
        if (!vantaq_verifier_auth_is_authenticated(&request_ctx.verifier_auth)) {
            if (send_mtls_required_response(connection) != 0) {
                (void)log_text(health_ctx->err_logger, health_ctx->io_ctx,
                               "http server: failed to send mtls-required response\n");
                (void)vantaq_http_send_status_response(connection, 500);
            }
            goto cleanup;
        }

        // Enforce verifier allowlist
        {
            enum vantaq_verifier_status_code v_status = vantaq_verifier_lookup_status(
                health_ctx->runtime_config, request_ctx.verifier_auth.identity.id);
            enum vantaq_verifier_policy_decision decision =
                vantaq_verifier_policy_evaluate(&request_ctx.verifier_auth.identity, v_status);

            if (decision != VANTAQ_VERIFIER_POLICY_ALLOW) {
                const char *reason = "VERIFIER_NOT_ALLOWED";
                if (decision == VANTAQ_VERIFIER_POLICY_REJECT_INACTIVE) {
                    reason = "VERIFIER_INACTIVE";
                } else if (decision == VANTAQ_VERIFIER_POLICY_REJECT_MISSING_ID) {
                    reason = "VERIFIER_ID_MISSING";
                }

                (void)snprintf(log_buf, sizeof(log_buf),
                               "http server: verifier denied %s %s reason=%s\n", method, path,
                               reason);
                (void)log_text(health_ctx->err_logger, health_ctx->io_ctx, log_buf);

                // For simplicity, we use vantaq_http_send_status_response(403) or a more specific
                // one if we want generic body. The task says "Keep error messages generic".
                (void)vantaq_http_send_status_response(connection, 403);
                goto cleanup;
            }
        }
    }

    if (status_code == 200) {
        int rc;
        if (strcmp(path, "/v1/device/identity") == 0) {
            rc = send_identity_response(connection, health_ctx);
        } else if (strcmp(path, "/v1/device/capabilities") == 0) {
            rc = send_capabilities_response(connection, health_ctx);
        } else if (strncmp(path, "/v1/security/verifiers/", 23) == 0) {
            rc = send_verifier_metadata_response(connection, health_ctx, &request_ctx, path + 23);
        } else {
            rc = send_health_response(connection, health_ctx);
        }

        if (rc != 0) {
            (void)log_text(health_ctx->err_logger, health_ctx->io_ctx,
                           "http server: failed to send response\n");
            (void)vantaq_http_send_status_response(connection, 500);
        }
        goto cleanup;
    }

    if (vantaq_http_send_status_response(connection, status_code) != 0) {
        (void)log_text(health_ctx->err_logger, health_ctx->io_ctx,
                       "http server: failed to send status response\n");
    }

cleanup:
    return;
}

static int create_listener(const char *host, int port, vantaq_http_log_fn err_logger, void *ctx) {
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *rp;
    char port_text[16];
    int listener = -1;
    int rc;
    int one = 1;
    char msg[192];

    VANTAQ_ZERO_STRUCT(hints);
    VANTAQ_ZERO_STRUCT(port_text);
    VANTAQ_ZERO_STRUCT(msg);
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_NUMERICSERV;

    rc = snprintf(port_text, sizeof(port_text), "%d", port);
    if (rc <= 0 || (size_t)rc >= sizeof(port_text)) {
        log_text(err_logger, ctx, "http server: invalid port\n");
        return -1;
    }

    rc = getaddrinfo(host, port_text, &hints, &result);
    if (rc != 0) {
        (void)snprintf(msg, sizeof(msg), "http server: address resolution failed: %s\n",
                       gai_strerror(rc));
        log_text(err_logger, ctx, msg);
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        listener = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listener < 0) {
            continue;
        }

        (void)setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

        if (bind(listener, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }

        (void)close(listener);
        listener = -1;
    }

    freeaddrinfo(result);

    if (listener < 0) {
        log_text(err_logger, ctx, "http server: bind failed\n");
        return -1;
    }

    if (listen(listener, 16) != 0) {
        (void)close(listener);
        log_text(err_logger, ctx, "http server: listen failed\n");
        return -1;
    }

    return listener;
}

static void restore_signal(const struct sigaction *old_term, const struct sigaction *old_int) {
    (void)sigaction(SIGTERM, old_term, NULL);
    (void)sigaction(SIGINT, old_int, NULL);
}

enum vantaq_http_server_status
vantaq_http_server_run(const struct vantaq_http_server_options *options) {
    int listener;
    size_t i;
    struct vantaq_audit_log *audit_log   = NULL;
    struct vantaq_tls_server *tls_server = NULL;
    enum vantaq_audit_log_status audit_create_status;
    enum vantaq_tls_server_status tls_status;
    struct sigaction sa;
    struct sigaction old_term;
    struct sigaction old_int;
    char startup[224];
    char tls_msg[256];
    struct vantaq_http_health_context health_ctx;

    VANTAQ_ZERO_STRUCT(health_ctx);
    VANTAQ_ZERO_STRUCT(startup);
    VANTAQ_ZERO_STRUCT(tls_msg);

    if (options == NULL || options->cbSize < sizeof(struct vantaq_http_server_options) ||
        options->listen_host == NULL || options->listen_host[0] == '\0' ||
        options->listen_port <= 0 || options->listen_port > 65535 ||
        options->service_name == NULL || options->service_name[0] == '\0' ||
        options->service_version == NULL || options->service_version[0] == '\0' ||
        options->device_id == NULL || options->device_id[0] == '\0' ||
        options->device_model == NULL || options->device_model[0] == '\0' ||
        options->device_serial_number == NULL || options->device_serial_number[0] == '\0' ||
        options->device_manufacturer == NULL || options->device_manufacturer[0] == '\0' ||
        options->device_firmware_version == NULL || options->device_firmware_version[0] == '\0' ||
        options->supported_claims == NULL || options->supported_claims_count == 0 ||
        (options->supported_claims_count > 0 && options->supported_claims == NULL) ||
        (options->signature_algorithms_count > 0 && options->signature_algorithms == NULL) ||
        (options->evidence_formats_count > 0 && options->evidence_formats == NULL) ||
        (options->challenge_modes_count > 0 && options->challenge_modes == NULL) ||
        (options->storage_modes_count > 0 && options->storage_modes == NULL) ||
        (options->allowed_subnets_count > 0 && options->allowed_subnets == NULL) ||
        options->audit_log_path == NULL || options->audit_log_path[0] == '\0' ||
        options->audit_log_max_bytes == 0) {
        return VANTAQ_HTTP_SERVER_STATUS_INVALID_ARGUMENT;
    }
    if (options->tls_enabled &&
        (options->tls_server_cert_path == NULL || options->tls_server_cert_path[0] == '\0' ||
         options->tls_server_key_path == NULL || options->tls_server_key_path[0] == '\0' ||
         options->tls_trusted_client_ca_path == NULL ||
         options->tls_trusted_client_ca_path[0] == '\0')) {
        return VANTAQ_HTTP_SERVER_STATUS_INVALID_ARGUMENT;
    }
    for (i = 0; i < options->allowed_subnets_count; i++) {
        if (options->allowed_subnets[i] == NULL || options->allowed_subnets[i][0] == '\0') {
            return VANTAQ_HTTP_SERVER_STATUS_INVALID_ARGUMENT;
        }
    }

    audit_create_status =
        vantaq_audit_log_create(options->audit_log_path, options->audit_log_max_bytes, &audit_log);
    if (audit_create_status != VANTAQ_AUDIT_LOG_STATUS_OK) {
        log_text(options->write_err, options->io_ctx,
                 "http server: failed to initialize audit log\n");
        return VANTAQ_HTTP_SERVER_STATUS_RUNTIME_ERROR;
    }

    listener = create_listener(options->listen_host, options->listen_port, options->write_err,
                               options->io_ctx);
    if (listener < 0) {
        vantaq_audit_log_destroy(audit_log);
        return VANTAQ_HTTP_SERVER_STATUS_BIND_ERROR;
    }

    if (options->tls_enabled) {
        struct vantaq_tls_server_options tls_options;
        VANTAQ_ZERO_STRUCT(tls_options);
        tls_options.cbSize                 = sizeof(tls_options);
        tls_options.server_cert_path       = options->tls_server_cert_path;
        tls_options.server_key_path        = options->tls_server_key_path;
        tls_options.trusted_client_ca_path = options->tls_trusted_client_ca_path;
        tls_options.require_client_cert    = options->tls_require_client_cert;

        tls_status = vantaq_tls_server_create(&tls_options, &tls_server);
        if (tls_status != VANTAQ_TLS_SERVER_STATUS_OK) {
            (void)snprintf(tls_msg, sizeof(tls_msg), "http server: tls init failed: %s\n",
                           vantaq_tls_server_status_text(tls_status));
            log_text(options->write_err, options->io_ctx, tls_msg);
            (void)close(listener);
            vantaq_audit_log_destroy(audit_log);
            return VANTAQ_HTTP_SERVER_STATUS_TLS_INIT_ERROR;
        }
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_term_signal;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGTERM);
    sigaddset(&sa.sa_mask, SIGINT);
    // Note: sa_flags is intentionally 0 (no SA_RESTART). We want accept()
    // and other blocking calls to return EINTR so that we can check
    // g_stop_requested and shut down gracefully.
    sa.sa_flags = 0;

    if (sigaction(SIGTERM, &sa, &old_term) != 0 || sigaction(SIGINT, &sa, &old_int) != 0) {
        (void)close(listener);
        log_text(options->write_err, options->io_ctx,
                 "http server: failed to set signal handlers\n");
        vantaq_tls_server_destroy(tls_server);
        vantaq_audit_log_destroy(audit_log);
        return VANTAQ_HTTP_SERVER_STATUS_RUNTIME_ERROR;
    }

    g_stop_requested                      = 0;
    g_listener_fd                         = listener;
    health_ctx.runtime_config             = options->runtime_config;
    health_ctx.service_name               = options->service_name;
    health_ctx.service_version            = options->service_version;
    health_ctx.device_id                  = options->device_id;
    health_ctx.device_model               = options->device_model;
    health_ctx.device_serial_number       = options->device_serial_number;
    health_ctx.device_manufacturer        = options->device_manufacturer;
    health_ctx.device_firmware_version    = options->device_firmware_version;
    health_ctx.supported_claims           = options->supported_claims;
    health_ctx.supported_claims_count     = options->supported_claims_count;
    health_ctx.signature_algorithms       = options->signature_algorithms;
    health_ctx.signature_algorithms_count = options->signature_algorithms_count;
    health_ctx.evidence_formats           = options->evidence_formats;
    health_ctx.evidence_formats_count     = options->evidence_formats_count;
    health_ctx.challenge_modes            = options->challenge_modes;
    health_ctx.challenge_modes_count      = options->challenge_modes_count;
    health_ctx.storage_modes              = options->storage_modes;
    health_ctx.storage_modes_count        = options->storage_modes_count;
    health_ctx.allowed_subnets            = options->allowed_subnets;
    health_ctx.allowed_subnets_count      = options->allowed_subnets_count;
    health_ctx.dev_allow_all_networks     = options->dev_allow_all_networks;
    health_ctx.audit_log                  = audit_log;
    health_ctx.err_logger                 = options->write_err;
    health_ctx.io_ctx                     = options->io_ctx;
    if (clock_gettime(CLOCK_MONOTONIC, &health_ctx.started_at) != 0) {
        health_ctx.started_at.tv_sec  = 0;
        health_ctx.started_at.tv_nsec = 0;
    }

    if (snprintf(startup, sizeof(startup), "%s server listening on %s:%d\n",
                 options->tls_enabled ? "https" : "http", options->listen_host,
                 options->listen_port) > 0) {
        log_text(options->write_out, options->io_ctx, startup);
    }

    while (!g_stop_requested) {
        int client_fd = accept(listener, NULL, NULL);

        if (client_fd < 0) {
            if (g_stop_requested || errno == EINTR || errno == EBADF) {
                break;
            }
            log_text(options->write_err, options->io_ctx, "http server: accept failed\n");
            (void)usleep(100000);
            continue;
        }

        {
            struct vantaq_http_connection connection;
            VANTAQ_ZERO_STRUCT(connection);
            connection.fd = client_fd;

            if (tls_server != NULL) {
                tls_status =
                    vantaq_tls_server_handshake(tls_server, client_fd, &connection.tls_connection);
                if (tls_status != VANTAQ_TLS_SERVER_STATUS_OK) {
                    (void)snprintf(tls_msg, sizeof(tls_msg),
                                   "http server: tls handshake failed: %s\n",
                                   vantaq_tls_server_status_text(tls_status));
                    log_text(options->write_err, options->io_ctx, tls_msg);
                    (void)close(client_fd);
                    continue;
                }
            }

            handle_client(&connection, &health_ctx);
            if (connection.tls_connection != NULL) {
                vantaq_tls_connection_destroy(connection.tls_connection);
            }
        }
        (void)close(client_fd);
    }

    {
        sigset_t set, oldset;
        int fd;

        sigemptyset(&set);
        sigaddset(&set, SIGTERM);
        sigaddset(&set, SIGINT);
        (void)sigprocmask(SIG_BLOCK, &set, &oldset);

        fd            = g_listener_fd;
        g_listener_fd = -1;

        (void)sigprocmask(SIG_SETMASK, &oldset, NULL);

        if (fd >= 0) {
            (void)close(fd);
        }
    }

    restore_signal(&old_term, &old_int);
    vantaq_tls_server_destroy(tls_server);
    vantaq_audit_log_destroy(audit_log);

    return VANTAQ_HTTP_SERVER_STATUS_OK;
}

const char *vantaq_http_server_status_text(enum vantaq_http_server_status status) {
    switch (status) {
    case VANTAQ_HTTP_SERVER_STATUS_OK:
        return "ok";
    case VANTAQ_HTTP_SERVER_STATUS_INVALID_ARGUMENT:
        return "invalid argument";
    case VANTAQ_HTTP_SERVER_STATUS_BIND_ERROR:
        return "bind/listen failed";
    case VANTAQ_HTTP_SERVER_STATUS_LISTEN_ERROR:
        return "listen failed";
    case VANTAQ_HTTP_SERVER_STATUS_TLS_INIT_ERROR:
        return "tls init failed";
    case VANTAQ_HTTP_SERVER_STATUS_RUNTIME_ERROR:
        return "runtime error";
    default:
        return "unknown";
    }
}
