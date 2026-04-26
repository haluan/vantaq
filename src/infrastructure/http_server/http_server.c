// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#define _POSIX_C_SOURCE 200809L

#include "infrastructure/http_server.h"
#include "infrastructure/audit_log.h"
#include "infrastructure/config_loader.h"
#include "infrastructure/socket_peer.h"
#include "infrastructure/subnet_policy.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define VANTAQ_HTTP_REQ_BUF_SIZE 2048

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

struct vantaq_http_health_context {
    const char *service_name;
    const char *service_version;
    const char *device_id;
    const char *device_model;
    const char *device_serial_number;
    const char *device_manufacturer;
    const char *device_firmware_version;
    const char *const *supported_claims;
    size_t supported_claims_count;
    const char *const *signature_algorithms;
    size_t signature_algorithms_count;
    const char *const *evidence_formats;
    size_t evidence_formats_count;
    const char *const *challenge_modes;
    size_t challenge_modes_count;
    const char *const *storage_modes;
    size_t storage_modes_count;
    const char *const *allowed_subnets;
    size_t allowed_subnets_count;
    int dev_allow_all_networks;
    struct vantaq_audit_log *audit_log;
    struct timespec started_at;
    vantaq_http_log_fn err_logger;
    void *io_ctx;
};

struct vantaq_http_request_context {
    char peer_ipv4[INET_ADDRSTRLEN];
    bool peer_ip_ok;
    enum vantaq_peer_address_status peer_status;
};

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

static int write_all(int fd, const char *buf, size_t len) {
    size_t sent = 0;

    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, 0);
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

static int send_status_response(int fd, int status_code) {
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
    return write_all(fd, response, (size_t)n);
}

static int send_subnet_denied_response(int fd) {
    static const char json_body[] = "{\"error\":{\"code\":\"SUBNET_NOT_ALLOWED\","
                                    "\"message\":\"Requester source network is not allowed.\","
                                    "\"request_id\":\"req-000001\"}}\n";
    char response[512];
    int n;

    n = snprintf(response, sizeof(response),
                 "HTTP/1.1 403 Forbidden\r\n"
                 "Content-Type: application/json\r\n"
                 "Content-Length: %zu\r\n"
                 "Connection: close\r\n"
                 "\r\n"
                 "%s",
                 strlen(json_body), json_body);
    if (n <= 0 || (size_t)n >= sizeof(response)) {
        return -1;
    }

    return write_all(fd, response, (size_t)n);
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

static int send_health_response(int fd, const struct vantaq_http_health_context *ctx) {
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

    return write_all(fd, response, (size_t)response_n);
}

static int send_identity_response(int fd, const struct vantaq_http_health_context *ctx) {
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

    return write_all(fd, response, (size_t)response_n);
}

static int send_capabilities_response(int fd, const struct vantaq_http_health_context *ctx) {
    // Note: This buffer can be large (up to ~240KB with 64 items of 128 chars).
    // In a production environment, dynamic allocation might be preferred.
    static char json[VANTAQ_CAPABILITIES_JSON_BUF_SIZE];
    char response_header[512];
    size_t used = 0;

    VANTAQ_ZERO_STRUCT(response_header);
    // static json is zeroed by default, but we should clear it for safety if reused
    memset(json, 0, sizeof(json));

    if (ctx == NULL || ctx->supported_claims == NULL || ctx->signature_algorithms == NULL ||
        ctx->evidence_formats == NULL || ctx->challenge_modes == NULL ||
        ctx->storage_modes == NULL) {
        return -1;
    }

    if (append_jsonf(json, sizeof(json), &used, "{") != 0 ||
        append_json_string_array(json, sizeof(json), &used, "supported_claims",
                                 ctx->supported_claims, ctx->supported_claims_count, true) != 0 ||
        append_json_string_array(json, sizeof(json), &used, "signature_algorithms",
                                 ctx->signature_algorithms, ctx->signature_algorithms_count,
                                 true) != 0 ||
        append_json_string_array(json, sizeof(json), &used, "evidence_formats",
                                 ctx->evidence_formats, ctx->evidence_formats_count, true) != 0 ||
        append_json_string_array(json, sizeof(json), &used, "challenge_modes", ctx->challenge_modes,
                                 ctx->challenge_modes_count, true) != 0 ||
        append_json_string_array(json, sizeof(json), &used, "storage_modes", ctx->storage_modes,
                                 ctx->storage_modes_count, false) != 0 ||
        append_jsonf(json, sizeof(json), &used, "}\n") != 0) {
        return -1;
    }

    int json_n   = (int)used;
    int header_n = snprintf(response_header, sizeof(response_header),
                            "HTTP/1.1 200 OK\r\n"
                            "Content-Type: application/json\r\n"
                            "Content-Length: %d\r\n"
                            "Connection: close\r\n"
                            "\r\n",
                            json_n);

    if (header_n <= 0 || (size_t)header_n >= sizeof(response_header)) {
        return -1;
    }

    if (write_all(fd, response_header, (size_t)header_n) != 0) {
        return -1;
    }

    return write_all(fd, json, (size_t)json_n);
}

static int parse_request_line(const char *buf, char *method, size_t method_size, char *path,
                              size_t path_size) {
    (void)method_size;
    (void)path_size;
    // We use sscanf to parse without mutating the input buffer.
    // This preserves the raw request for diagnostic logging if needed.
    if (sscanf(buf, "%15s %255s", method, path) != 2) {
        return -1;
    }

    return 0;
}

static int route_status_code(const char *method, const char *path) {
    if (strcmp(path, "/v1/health") == 0) {
        if (strcmp(method, "GET") != 0) {
            return 405;
        }
        return 200;
    }
    if (strcmp(path, "/v1/device/identity") == 0) {
        if (strcmp(method, "GET") != 0) {
            return 405;
        }
        return 200;
    }
    if (strcmp(path, "/v1/device/capabilities") == 0) {
        if (strcmp(method, "GET") != 0) {
            return 405;
        }
        return 200;
    }

    return 404;
}

static void handle_client(int client_fd, const struct vantaq_http_health_context *health_ctx) {
    char req_buf[VANTAQ_HTTP_REQ_BUF_SIZE];
    size_t total_read = 0;
    char method[16];
    char path[256];
    char log_buf[192];
    struct vantaq_http_request_context request_ctx;
    struct vantaq_subnet_policy_input subnet_input;
    enum vantaq_subnet_policy_decision subnet_decision;
    enum vantaq_subnet_policy_status subnet_status;
    enum vantaq_audit_log_status audit_status;
    int status_code;

    VANTAQ_ZERO_STRUCT(req_buf);
    VANTAQ_ZERO_STRUCT(method);
    VANTAQ_ZERO_STRUCT(path);
    VANTAQ_ZERO_STRUCT(log_buf);
    VANTAQ_ZERO_STRUCT(request_ctx);
    VANTAQ_ZERO_STRUCT(subnet_input);

    request_ctx.peer_status = vantaq_peer_address_get_ipv4(client_fd, request_ctx.peer_ipv4,
                                                           sizeof(request_ctx.peer_ipv4));
    request_ctx.peer_ip_ok  = (request_ctx.peer_status == VANTAQ_PEER_ADDRESS_STATUS_OK);

    while (total_read < sizeof(req_buf) - 1) {
        ssize_t n = recv(client_fd, req_buf + total_read, sizeof(req_buf) - 1 - total_read, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
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
        return;
    }

    if (parse_request_line(req_buf, method, sizeof(method), path, sizeof(path)) != 0) {
        (void)send_status_response(client_fd, 400);
        return;
    }

    subnet_input.method                 = method;
    subnet_input.path                   = path;
    subnet_input.peer_status            = request_ctx.peer_status;
    subnet_input.peer_ipv4              = request_ctx.peer_ip_ok ? request_ctx.peer_ipv4 : NULL;
    subnet_input.allowed_subnets        = health_ctx->allowed_subnets;
    subnet_input.allowed_subnets_count  = health_ctx->allowed_subnets_count;
    subnet_input.dev_allow_all_networks = health_ctx->dev_allow_all_networks;

    subnet_status = vantaq_subnet_policy_evaluate(&subnet_input, &subnet_decision);
    if (subnet_status != VANTAQ_SUBNET_POLICY_STATUS_OK) {
        (void)snprintf(log_buf, sizeof(log_buf), "http server: subnet policy failed: %s\n",
                       vantaq_subnet_policy_status_text(subnet_status));
        log_text(health_ctx->err_logger, health_ctx->io_ctx, log_buf);
        (void)send_status_response(client_fd, 500);
        return;
    }

    if (subnet_decision == VANTAQ_SUBNET_POLICY_DECISION_DENY) {
        struct vantaq_audit_event audit_event;
        const char *peer_text = request_ctx.peer_ip_ok
                                    ? request_ctx.peer_ipv4
                                    : vantaq_peer_address_status_text(request_ctx.peer_status);

        VANTAQ_ZERO_STRUCT(audit_event);
        audit_event.time_utc_epoch_seconds = time(NULL);
        audit_event.source_ip = request_ctx.peer_ip_ok ? request_ctx.peer_ipv4 : "unknown";
        audit_event.method    = method;
        audit_event.path      = path;
        audit_event.result    = "DENY";
        audit_event.reason    = "SUBNET_NOT_ALLOWED";

        audit_status = vantaq_audit_log_append(health_ctx->audit_log, &audit_event);
        if (audit_status != VANTAQ_AUDIT_LOG_STATUS_OK) {
            const char *last_error = vantaq_audit_log_last_error(health_ctx->audit_log);
            (void)snprintf(log_buf, sizeof(log_buf), "http server: audit append failed: %s (%s)\n",
                           vantaq_audit_log_status_text(audit_status),
                           last_error != NULL ? last_error : "unknown");
            log_text(health_ctx->err_logger, health_ctx->io_ctx, log_buf);
        }

        (void)snprintf(log_buf, sizeof(log_buf), "http server: subnet denied %s %s peer=%s\n",
                       method, path, peer_text);
        log_text(health_ctx->err_logger, health_ctx->io_ctx, log_buf);

        if (send_subnet_denied_response(client_fd) != 0) {
            log_text(health_ctx->err_logger, health_ctx->io_ctx,
                     "http server: failed to send subnet denied response\n");
        }
        return;
    }

    status_code = route_status_code(method, path);
    if (status_code == 200) {
        int rc;
        if (strcmp(path, "/v1/device/identity") == 0) {
            rc = send_identity_response(client_fd, health_ctx);
        } else if (strcmp(path, "/v1/device/capabilities") == 0) {
            rc = send_capabilities_response(client_fd, health_ctx);
        } else {
            rc = send_health_response(client_fd, health_ctx);
        }

        if (rc != 0) {
            log_text(health_ctx->err_logger, health_ctx->io_ctx,
                     "http server: failed to send response\n");
            (void)send_status_response(client_fd, 500);
        }
        return;
    }

    if (send_status_response(client_fd, status_code) != 0) {
        log_text(health_ctx->err_logger, health_ctx->io_ctx,
                 "http server: failed to send status response\n");
    }
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
    struct vantaq_audit_log *audit_log = NULL;
    enum vantaq_audit_log_status audit_create_status;
    struct sigaction sa;
    struct sigaction old_term;
    struct sigaction old_int;
    char startup[192];
    struct vantaq_http_health_context health_ctx;

    VANTAQ_ZERO_STRUCT(health_ctx);
    VANTAQ_ZERO_STRUCT(startup);

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
        (options->dev_allow_all_networks != 0 && options->dev_allow_all_networks != 1) ||
        options->audit_log_path == NULL || options->audit_log_path[0] == '\0' ||
        options->audit_log_max_bytes == 0) {
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
        vantaq_audit_log_destroy(audit_log);
        return VANTAQ_HTTP_SERVER_STATUS_RUNTIME_ERROR;
    }

    g_stop_requested                      = 0;
    g_listener_fd                         = listener;
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

    if (snprintf(startup, sizeof(startup), "http server listening on %s:%d\n", options->listen_host,
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

        handle_client(client_fd, &health_ctx);
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
    case VANTAQ_HTTP_SERVER_STATUS_RUNTIME_ERROR:
        return "runtime error";
    default:
        return "unknown";
    }
}
