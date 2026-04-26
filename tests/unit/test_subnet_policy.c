// SPDX-FileCopyrightText: 2026 Haluan Irsad
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#include "infrastructure/subnet_policy.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>

#include <cmocka.h>

static void test_allows_matching_health_subnet(void **state) {
    (void)state;
    const char *allowed_subnets[] = {"127.0.0.1/32"};
    struct vantaq_subnet_policy_input input;
    enum vantaq_subnet_policy_decision decision;

    input.method                 = "GET";
    input.path                   = "/v1/health";
    input.peer_status            = VANTAQ_PEER_ADDRESS_STATUS_OK;
    input.peer_ipv4              = "127.0.0.1";
    input.allowed_subnets        = allowed_subnets;
    input.allowed_subnets_count  = 1;
    input.dev_allow_all_networks = 0;

    assert_int_equal(vantaq_subnet_policy_evaluate(&input, &decision),
                     VANTAQ_SUBNET_POLICY_STATUS_OK);
    assert_int_equal(decision, VANTAQ_SUBNET_POLICY_DECISION_ALLOW);
}

static void test_denies_health_when_peer_not_in_subnet(void **state) {
    (void)state;
    const char *allowed_subnets[] = {"10.50.10.0/24"};
    struct vantaq_subnet_policy_input input;
    enum vantaq_subnet_policy_decision decision;

    input.method                 = "GET";
    input.path                   = "/v1/health";
    input.peer_status            = VANTAQ_PEER_ADDRESS_STATUS_OK;
    input.peer_ipv4              = "127.0.0.1";
    input.allowed_subnets        = allowed_subnets;
    input.allowed_subnets_count  = 1;
    input.dev_allow_all_networks = 0;

    assert_int_equal(vantaq_subnet_policy_evaluate(&input, &decision),
                     VANTAQ_SUBNET_POLICY_STATUS_OK);
    assert_int_equal(decision, VANTAQ_SUBNET_POLICY_DECISION_DENY);
}

static void test_denies_health_when_peer_detection_fails(void **state) {
    (void)state;
    const char *allowed_subnets[] = {"127.0.0.1/32"};
    struct vantaq_subnet_policy_input input;
    enum vantaq_subnet_policy_decision decision;

    input.method                 = "GET";
    input.path                   = "/v1/health";
    input.peer_status            = VANTAQ_PEER_ADDRESS_STATUS_GETPEERNAME_FAILED;
    input.peer_ipv4              = NULL;
    input.allowed_subnets        = allowed_subnets;
    input.allowed_subnets_count  = 1;
    input.dev_allow_all_networks = 0;

    assert_int_equal(vantaq_subnet_policy_evaluate(&input, &decision),
                     VANTAQ_SUBNET_POLICY_STATUS_OK);
    assert_int_equal(decision, VANTAQ_SUBNET_POLICY_DECISION_DENY);
}

static void test_allows_health_when_dev_override_enabled(void **state) {
    (void)state;
    struct vantaq_subnet_policy_input input;
    enum vantaq_subnet_policy_decision decision;

    input.method                 = "GET";
    input.path                   = "/v1/health";
    input.peer_status            = VANTAQ_PEER_ADDRESS_STATUS_GETPEERNAME_FAILED;
    input.peer_ipv4              = NULL;
    input.allowed_subnets        = NULL;
    input.allowed_subnets_count  = 0;
    input.dev_allow_all_networks = 1;

    assert_int_equal(vantaq_subnet_policy_evaluate(&input, &decision),
                     VANTAQ_SUBNET_POLICY_STATUS_OK);
    assert_int_equal(decision, VANTAQ_SUBNET_POLICY_DECISION_ALLOW);
}

static void test_denies_health_fail_closed_with_empty_subnets(void **state) {
    (void)state;
    struct vantaq_subnet_policy_input input;
    enum vantaq_subnet_policy_decision decision;

    input.method                 = "GET";
    input.path                   = "/v1/health";
    input.peer_status            = VANTAQ_PEER_ADDRESS_STATUS_OK;
    input.peer_ipv4              = "127.0.0.1";
    input.allowed_subnets        = NULL;
    input.allowed_subnets_count  = 0;
    input.dev_allow_all_networks = 0;

    assert_int_equal(vantaq_subnet_policy_evaluate(&input, &decision),
                     VANTAQ_SUBNET_POLICY_STATUS_OK);
    assert_int_equal(decision, VANTAQ_SUBNET_POLICY_DECISION_DENY);
}

static void test_non_health_paths_are_not_enforced(void **state) {
    (void)state;
    struct vantaq_subnet_policy_input input;
    enum vantaq_subnet_policy_decision decision;

    input.method                 = "GET";
    input.path                   = "/v1/device/identity";
    input.peer_status            = VANTAQ_PEER_ADDRESS_STATUS_GETPEERNAME_FAILED;
    input.peer_ipv4              = NULL;
    input.allowed_subnets        = NULL;
    input.allowed_subnets_count  = 0;
    input.dev_allow_all_networks = 0;

    assert_int_equal(vantaq_subnet_policy_evaluate(&input, &decision),
                     VANTAQ_SUBNET_POLICY_STATUS_OK);
    assert_int_equal(decision, VANTAQ_SUBNET_POLICY_DECISION_ALLOW);
}

static void test_non_get_health_is_not_enforced(void **state) {
    (void)state;
    struct vantaq_subnet_policy_input input;
    enum vantaq_subnet_policy_decision decision;

    input.method                 = "POST";
    input.path                   = "/v1/health";
    input.peer_status            = VANTAQ_PEER_ADDRESS_STATUS_GETPEERNAME_FAILED;
    input.peer_ipv4              = NULL;
    input.allowed_subnets        = NULL;
    input.allowed_subnets_count  = 0;
    input.dev_allow_all_networks = 0;

    assert_int_equal(vantaq_subnet_policy_evaluate(&input, &decision),
                     VANTAQ_SUBNET_POLICY_STATUS_OK);
    assert_int_equal(decision, VANTAQ_SUBNET_POLICY_DECISION_ALLOW);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_allows_matching_health_subnet),
        cmocka_unit_test(test_denies_health_when_peer_not_in_subnet),
        cmocka_unit_test(test_denies_health_when_peer_detection_fails),
        cmocka_unit_test(test_allows_health_when_dev_override_enabled),
        cmocka_unit_test(test_denies_health_fail_closed_with_empty_subnets),
        cmocka_unit_test(test_non_health_paths_are_not_enforced),
        cmocka_unit_test(test_non_get_health_is_not_enforced),
    };

    return cmocka_run_group_tests_name("unit_subnet_policy", tests, NULL, NULL);
}
