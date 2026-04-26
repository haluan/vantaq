// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#define _POSIX_C_SOURCE 200809L

#include "infrastructure/http_server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define VANTAQ_HTTP_REQ_BUF_SIZE 2048

static volatile sig_atomic_t g_stop_requested = 0;
static volatile sig_atomic_t g_listener_fd    = -1;

struct vantaq_http_health_context {
    const char *service_name;
    const char *service_version;
    struct timespec started_at;
};

static void log_text(vantaq_http_log_fn logger, void *ctx, const char *text) {
    if (logger != NULL && text != NULL) {
        logger(ctx, text);
    }
}

static void handle_term_signal(int signum) {
    (void)signum;
    g_stop_requested = 1;
    if (g_listener_fd >= 0) {
        (void)close((int)g_listener_fd);
        g_listener_fd = -1;
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

static int send_health_response(int fd, const struct vantaq_http_health_context *ctx) {
    char json[512];
    char response[768];
    int json_n;
    int response_n;
    long long uptime_seconds;

    if (ctx == NULL || ctx->service_name == NULL || ctx->service_version == NULL) {
        return -1;
    }

    uptime_seconds = elapsed_seconds_since(&ctx->started_at);
    json_n         = snprintf(
        json, sizeof(json),
        "{\"status\":\"ok\",\"service\":\"%s\",\"version\":\"%s\",\"uptime_seconds\":%lld}\n",
        ctx->service_name, ctx->service_version, uptime_seconds);
    if (json_n <= 0 || (size_t)json_n >= sizeof(json)) {
        return -1;
    }

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

static int parse_request_line(char *buf, const char **method_out, const char **path_out) {
    char *line_end;
    char *method;
    char *path;
    char *version;

    line_end = strstr(buf, "\r\n");
    if (line_end == NULL) {
        line_end = strchr(buf, '\n');
    }
    if (line_end == NULL) {
        return -1;
    }
    *line_end = '\0';

    method  = strtok(buf, " ");
    path    = strtok(NULL, " ");
    version = strtok(NULL, " ");

    if (method == NULL || path == NULL || version == NULL) {
        return -1;
    }

    *method_out = method;
    *path_out   = path;
    return 0;
}

static int route_status_code(const char *method, const char *path) {
    if (strcmp(path, "/v1/health") == 0) {
        if (strcmp(method, "GET") != 0) {
            return 405;
        }
        return 200;
    }

    return 404;
}

static void handle_client(int client_fd, const struct vantaq_http_health_context *health_ctx) {
    char req_buf[VANTAQ_HTTP_REQ_BUF_SIZE];
    ssize_t nread;
    const char *method;
    const char *path;
    int status_code;

    nread = recv(client_fd, req_buf, sizeof(req_buf) - 1, 0);
    if (nread <= 0) {
        return;
    }

    req_buf[nread] = '\0';

    if (parse_request_line(req_buf, &method, &path) != 0) {
        (void)send_status_response(client_fd, 400);
        return;
    }

    status_code = route_status_code(method, path);
    if (status_code == 200) {
        (void)send_health_response(client_fd, health_ctx);
        return;
    }
    (void)send_status_response(client_fd, status_code);
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

    memset(&hints, 0, sizeof(hints));
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
    struct sigaction sa;
    struct sigaction old_term;
    struct sigaction old_int;
    char startup[192];
    struct vantaq_http_health_context health_ctx;

    if (options == NULL || options->listen_host == NULL || options->listen_host[0] == '\0' ||
        options->listen_port <= 0 || options->listen_port > 65535 ||
        options->service_name == NULL || options->service_name[0] == '\0' ||
        options->service_version == NULL || options->service_version[0] == '\0') {
        return VANTAQ_HTTP_SERVER_STATUS_INVALID_ARGUMENT;
    }

    listener = create_listener(options->listen_host, options->listen_port, options->write_err,
                               options->io_ctx);
    if (listener < 0) {
        return VANTAQ_HTTP_SERVER_STATUS_BIND_ERROR;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_term_signal;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGTERM, &sa, &old_term) != 0 || sigaction(SIGINT, &sa, &old_int) != 0) {
        (void)close(listener);
        log_text(options->write_err, options->io_ctx,
                 "http server: failed to set signal handlers\n");
        return VANTAQ_HTTP_SERVER_STATUS_RUNTIME_ERROR;
    }

    g_stop_requested           = 0;
    g_listener_fd              = listener;
    health_ctx.service_name    = options->service_name;
    health_ctx.service_version = options->service_version;
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
            continue;
        }

        handle_client(client_fd, &health_ctx);
        (void)close(client_fd);
    }

    g_listener_fd = -1;
    (void)close(listener);
    restore_signal(&old_term, &old_int);

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
