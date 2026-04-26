// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "domain/network_access/ipv4_cidr.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <cmocka.h>

static void test_cidr_parse_valid_ipv4(void **state) {
    vantaq_ipv4_cidr_t *cidr = NULL;

    (void)state;
    assert_int_equal(vantaq_ipv4_cidr_create("10.50.10.0/24", &cidr), VANTAQ_IPV4_CIDR_STATUS_OK);
    assert_int_equal(vantaq_ipv4_cidr_prefix_len(cidr), 24);
    assert_int_equal(vantaq_ipv4_cidr_mask(cidr), 0xFFFFFF00U);
    assert_int_equal(vantaq_ipv4_cidr_network(cidr), 0x0A320A00U);
    vantaq_ipv4_cidr_destroy(cidr);

    assert_int_equal(vantaq_ipv4_cidr_create("0.0.0.0/0", &cidr), VANTAQ_IPV4_CIDR_STATUS_OK);
    assert_int_equal(vantaq_ipv4_cidr_prefix_len(cidr), 0);
    assert_int_equal(vantaq_ipv4_cidr_mask(cidr), 0x00000000U);
    assert_int_equal(vantaq_ipv4_cidr_network(cidr), 0x00000000U);
    vantaq_ipv4_cidr_destroy(cidr);

    assert_int_equal(vantaq_ipv4_cidr_create("10.50.10.20/32", &cidr), VANTAQ_IPV4_CIDR_STATUS_OK);
    assert_int_equal(vantaq_ipv4_cidr_prefix_len(cidr), 32);
    assert_int_equal(vantaq_ipv4_cidr_mask(cidr), 0xFFFFFFFFU);
    assert_int_equal(vantaq_ipv4_cidr_network(cidr), 0x0A320A14U);
    vantaq_ipv4_cidr_destroy(cidr);
}

static void test_cidr_parse_invalid_ipv4(void **state) {
    vantaq_ipv4_cidr_t *cidr = NULL;

    (void)state;
    assert_int_equal(vantaq_ipv4_cidr_create("300.50.10.0/24", &cidr),
                     VANTAQ_IPV4_CIDR_STATUS_INVALID_IPV4);
    assert_int_equal(vantaq_ipv4_cidr_create("10.50.10.0", &cidr),
                     VANTAQ_IPV4_CIDR_STATUS_INVALID_CIDR_FORMAT);
    assert_int_equal(vantaq_ipv4_cidr_create("10.50.10.0/abc", &cidr),
                     VANTAQ_IPV4_CIDR_STATUS_INVALID_PREFIX);
    assert_int_equal(vantaq_ipv4_cidr_create("10.50.10.0/33", &cidr),
                     VANTAQ_IPV4_CIDR_STATUS_INVALID_PREFIX);
}

static void test_cidr_parse_non_canonical(void **state) {
    vantaq_ipv4_cidr_t *cidr = NULL;

    (void)state;
    // 10.50.10.5/24 has '5' in the host part
    assert_int_equal(vantaq_ipv4_cidr_create("10.50.10.5/24", &cidr),
                     VANTAQ_IPV4_CIDR_STATUS_NON_CANONICAL);
}

static void test_cidr_match_exact_subnet(void **state) {
    vantaq_ipv4_cidr_t *cidr = NULL;
    uint32_t ip;

    (void)state;
    assert_int_equal(vantaq_ipv4_cidr_create("10.50.10.0/24", &cidr), VANTAQ_IPV4_CIDR_STATUS_OK);
    assert_int_equal(vantaq_ipv4_parse_u32("10.50.10.20", &ip), VANTAQ_IPV4_CIDR_STATUS_OK);
    assert_true(vantaq_ipv4_cidr_match(cidr, ip));
    vantaq_ipv4_cidr_destroy(cidr);
}

static void test_cidr_match_outside_subnet(void **state) {
    vantaq_ipv4_cidr_t *cidr = NULL;
    uint32_t ip;

    (void)state;
    assert_int_equal(vantaq_ipv4_cidr_create("10.50.10.0/24", &cidr), VANTAQ_IPV4_CIDR_STATUS_OK);
    assert_int_equal(vantaq_ipv4_parse_u32("10.50.11.20", &ip), VANTAQ_IPV4_CIDR_STATUS_OK);
    assert_false(vantaq_ipv4_cidr_match(cidr, ip));
    vantaq_ipv4_cidr_destroy(cidr);
}

static void test_cidr_match_boundary_addresses(void **state) {
    vantaq_ipv4_cidr_t *cidr = NULL;
    uint32_t ip;

    (void)state;
    assert_int_equal(vantaq_ipv4_cidr_create("10.50.10.0/24", &cidr), VANTAQ_IPV4_CIDR_STATUS_OK);

    assert_int_equal(vantaq_ipv4_parse_u32("10.50.10.0", &ip), VANTAQ_IPV4_CIDR_STATUS_OK);
    assert_true(vantaq_ipv4_cidr_match(cidr, ip));

    assert_int_equal(vantaq_ipv4_parse_u32("10.50.10.255", &ip), VANTAQ_IPV4_CIDR_STATUS_OK);
    assert_true(vantaq_ipv4_cidr_match(cidr, ip));
    vantaq_ipv4_cidr_destroy(cidr);

    assert_int_equal(vantaq_ipv4_cidr_create("10.50.10.20/32", &cidr), VANTAQ_IPV4_CIDR_STATUS_OK);
    assert_int_equal(vantaq_ipv4_parse_u32("10.50.10.20", &ip), VANTAQ_IPV4_CIDR_STATUS_OK);
    assert_true(vantaq_ipv4_cidr_match(cidr, ip));
    assert_int_equal(vantaq_ipv4_parse_u32("10.50.10.21", &ip), VANTAQ_IPV4_CIDR_STATUS_OK);
    assert_false(vantaq_ipv4_cidr_match(cidr, ip));
    vantaq_ipv4_cidr_destroy(cidr);

    assert_int_equal(vantaq_ipv4_cidr_create("0.0.0.0/0", &cidr), VANTAQ_IPV4_CIDR_STATUS_OK);
    assert_int_equal(vantaq_ipv4_parse_u32("203.0.113.99", &ip), VANTAQ_IPV4_CIDR_STATUS_OK);
    assert_true(vantaq_ipv4_cidr_match(cidr, ip));
    vantaq_ipv4_cidr_destroy(cidr);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_cidr_parse_valid_ipv4),
        cmocka_unit_test(test_cidr_parse_invalid_ipv4),
        cmocka_unit_test(test_cidr_parse_non_canonical),
        cmocka_unit_test(test_cidr_match_exact_subnet),
        cmocka_unit_test(test_cidr_match_outside_subnet),
        cmocka_unit_test(test_cidr_match_boundary_addresses),
    };

    return cmocka_run_group_tests_name("unit_ipv4_cidr", tests, NULL, NULL);
}
