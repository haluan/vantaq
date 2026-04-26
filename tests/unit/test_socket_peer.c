// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/socket_peer.h"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cmocka.h>

static void close_if_open(int fd) {
    if (fd >= 0) {
        (void)close(fd);
    }
}

static void test_get_ipv4_from_tcp_socket_succeeds(void **state) {
    (void)state;
    int listener_fd = -1;
    int client_fd   = -1;
    int accepted_fd = -1;
    struct sockaddr_in bind_addr;
    struct sockaddr_in listen_addr;
    socklen_t listen_addr_len = sizeof(listen_addr);
    char peer_ip[INET_ADDRSTRLEN];

    listener_fd = socket(AF_INET, SOCK_STREAM, 0);
    assert_true(listener_fd >= 0);

    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family      = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind_addr.sin_port        = htons(0);

    assert_int_equal(bind(listener_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)), 0);
    assert_int_equal(getsockname(listener_fd, (struct sockaddr *)&listen_addr, &listen_addr_len),
                     0);
    assert_int_equal(listen(listener_fd, 1), 0);

    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    assert_true(client_fd >= 0);
    assert_int_equal(connect(client_fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)), 0);

    accepted_fd = accept(listener_fd, NULL, NULL);
    assert_true(accepted_fd >= 0);

    memset(peer_ip, 0, sizeof(peer_ip));
    assert_int_equal(vantaq_peer_address_get_ipv4(accepted_fd, peer_ip, sizeof(peer_ip)),
                     VANTAQ_PEER_ADDRESS_STATUS_OK);
    assert_string_equal(peer_ip, "127.0.0.1");

    close_if_open(accepted_fd);
    close_if_open(client_fd);
    close_if_open(listener_fd);
}

static void test_invalid_fd_returns_invalid_argument(void **state) {
    (void)state;
    char peer_ip[INET_ADDRSTRLEN];
    memset(peer_ip, 0, sizeof(peer_ip));

    assert_int_equal(vantaq_peer_address_get_ipv4(-1, peer_ip, sizeof(peer_ip)),
                     VANTAQ_PEER_ADDRESS_STATUS_INVALID_ARGUMENT);
}

static void test_non_ipv4_peer_returns_unsupported_family(void **state) {
    (void)state;
    int fds[2] = {-1, -1};
    char peer_ip[INET_ADDRSTRLEN];

    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    memset(peer_ip, 0, sizeof(peer_ip));

    assert_int_equal(vantaq_peer_address_get_ipv4(fds[0], peer_ip, sizeof(peer_ip)),
                     VANTAQ_PEER_ADDRESS_STATUS_UNSUPPORTED_FAMILY);

    close_if_open(fds[0]);
    close_if_open(fds[1]);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_get_ipv4_from_tcp_socket_succeeds),
        cmocka_unit_test(test_invalid_fd_returns_invalid_argument),
        cmocka_unit_test(test_non_ipv4_peer_returns_unsupported_family),
    };

    return cmocka_run_group_tests_name("unit_socket_peer", tests, NULL, NULL);
}
