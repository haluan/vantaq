cmake_minimum_required(VERSION 3.20)

project(vantaqd LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
option(VANTAQ_BUILD_TESTS "Build CMocka tests" OFF)

set(VANTAQ_COMMON_SOURCES
  src/application/app.c
  src/domain/version.c
  src/domain/network_access/ipv4_cidr.c
  src/infrastructure/stdio_io.c
  src/infrastructure/audit_log/audit_log.c
  src/infrastructure/socket_peer/peer_address.c
  src/infrastructure/subnet_policy/subnet_policy.c
  src/infrastructure/config_loader/config_loader.c
  src/infrastructure/tls/tls_server.c
  src/infrastructure/http_server/http_server.c
  src/infrastructure/tls/client_cert.c
  src/domain/verifier_access/verifier_policy.c
  src/application/security/verifier_lookup.c
  src/application/security/get_verifier_metadata.c
  src/infrastructure/http_server/routes_verifiers.c
  src/domain/attestation_challenge/challenge.c
  src/infrastructure/crypto/nonce_random.c
  src/infrastructure/memory/challenge_store_memory.c
  src/application/attestation_challenge/create_challenge.c
  src/application/evidence/create_evidence.c
  src/application/evidence/latest_evidence_store.c
  src/infrastructure/http_server/routes_attestation.c
  src/infrastructure/http_server/json_utils.c
  src/domain/evidence/evidence.c
  src/domain/evidence/evidence_canonical.c
  src/domain/measurement/measurement.c
  src/domain/measurement/supported_claims.c
  src/infrastructure/linux_measurement/file_sha256_measurement.c
  src/infrastructure/linux_measurement/firmware_hash.c
  src/infrastructure/linux_measurement/config_hash.c
  src/infrastructure/linux_measurement/agent_integrity.c
  src/infrastructure/linux_measurement/boot_state.c
  src/infrastructure/crypto/device_key_loader.c
  src/infrastructure/crypto/evidence_signer.c
)

add_library(vantaq_core STATIC ${VANTAQ_COMMON_SOURCES})
target_include_directories(vantaq_core PUBLIC include)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
target_link_libraries(vantaq_core PRIVATE OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

if(MSVC)
  target_compile_options(vantaq_core PRIVATE /W4)
else()
  target_compile_options(vantaq_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(NOT MSVC)
  target_compile_definitions(vantaq_core PRIVATE _GNU_SOURCE)
endif()

add_executable(vantaqd src/main.c)
target_link_libraries(vantaqd PRIVATE vantaq_core)
set_target_properties(vantaqd PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin"
)

if(VANTAQ_BUILD_TESTS)
  enable_testing()
  include(cmake/Dependencies.cmake)
  vantaq_resolve_cmocka(VANTAQ_CMOCKA_TARGET)

  add_executable(test_app_version tests/unit/test_app_version.c)
  target_link_libraries(test_app_version PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME unit_app_version COMMAND test_app_version)

  add_executable(test_config_loader tests/unit/test_config_loader.c)
  target_link_libraries(test_config_loader PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME unit_config_loader COMMAND test_config_loader)

  add_executable(test_security_config tests/unit/test_security_config.c)
  target_link_libraries(test_security_config PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME unit_security_config COMMAND test_security_config)

  add_executable(test_socket_peer tests/unit/test_socket_peer.c)
  target_link_libraries(test_socket_peer PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME unit_socket_peer COMMAND test_socket_peer)

  add_executable(test_audit_log tests/unit/test_audit_log.c)
  target_link_libraries(test_audit_log PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME unit_audit_log COMMAND test_audit_log)

  add_executable(test_subnet_policy tests/unit/test_subnet_policy.c)
  target_link_libraries(test_subnet_policy PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME unit_subnet_policy COMMAND test_subnet_policy)

  add_executable(test_ipv4_cidr tests/unit/test_ipv4_cidr.c)
  target_link_libraries(test_ipv4_cidr PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME unit_ipv4_cidr COMMAND test_ipv4_cidr)

  add_executable(test_app_startup_config tests/unit/test_app_startup_config.c)
  target_link_libraries(test_app_startup_config PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME unit_app_startup_config COMMAND test_app_startup_config)
  set_tests_properties(unit_app_startup_config PROPERTIES
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  )

  add_executable(test_client_cert_identity tests/unit/test_client_cert_identity.c)
  target_link_libraries(test_client_cert_identity PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET} OpenSSL::SSL OpenSSL::Crypto)
  add_test(NAME unit_client_cert_identity COMMAND test_client_cert_identity)

  add_executable(test_verifier_policy tests/unit/test_verifier_policy.c)
  target_link_libraries(test_verifier_policy PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME unit_verifier_policy COMMAND test_verifier_policy)

  add_executable(test_verifier_lookup tests/unit/test_verifier_lookup.c)
  target_link_libraries(test_verifier_lookup PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME unit_verifier_lookup COMMAND test_verifier_lookup)

  add_executable(test_challenge_domain tests/unit/test_challenge_domain.c)
  target_link_libraries(test_challenge_domain PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME unit_challenge_domain COMMAND test_challenge_domain)

  add_executable(test_nonce_random tests/unit/test_nonce_random.c)
  target_link_libraries(test_nonce_random PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET} OpenSSL::Crypto)
  add_test(NAME unit_nonce_random COMMAND test_nonce_random)

  add_executable(test_challenge_store_memory tests/unit/test_challenge_store_memory.c)
  target_link_libraries(test_challenge_store_memory PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME unit_challenge_store_memory COMMAND test_challenge_store_memory)

  add_executable(test_challenge_ttl_config tests/unit/test_challenge_ttl_config.c)
  target_link_libraries(test_challenge_ttl_config PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME unit_challenge_ttl_config COMMAND test_challenge_ttl_config)

  set(VANTAQ_TEST_SERVER_HARNESS_SRC tests/integration/test_server_harness.c)

  add_executable(test_cli_smoke tests/integration/test_cli_smoke.c ${VANTAQ_TEST_SERVER_HARNESS_SRC})
  target_link_libraries(test_cli_smoke PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME integration_cli_smoke COMMAND test_cli_smoke)
  set_tests_properties(integration_cli_smoke PROPERTIES
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  )

  add_executable(test_capabilities_mtls tests/integration/test_capabilities_mtls.c ${VANTAQ_TEST_SERVER_HARNESS_SRC})
  target_link_libraries(test_capabilities_mtls PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME integration_capabilities_mtls COMMAND test_capabilities_mtls)
  set_tests_properties(integration_capabilities_mtls PROPERTIES
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  )

  add_executable(test_valid_evidence_request tests/integration/test_valid_evidence_request.c ${VANTAQ_TEST_SERVER_HARNESS_SRC})
  target_link_libraries(test_valid_evidence_request PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME integration_valid_evidence_request COMMAND test_valid_evidence_request)
  set_tests_properties(integration_valid_evidence_request PROPERTIES
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  )

  add_executable(test_evidence_firmware_hash_claim tests/integration/test_evidence_firmware_hash_claim.c ${VANTAQ_TEST_SERVER_HARNESS_SRC})
  target_link_libraries(test_evidence_firmware_hash_claim PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME integration_evidence_firmware_hash_claim COMMAND test_evidence_firmware_hash_claim)
  set_tests_properties(integration_evidence_firmware_hash_claim PROPERTIES
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  )

  add_executable(test_firmware_hash_change tests/integration/test_firmware_hash_change.c ${VANTAQ_TEST_SERVER_HARNESS_SRC})
  target_link_libraries(test_firmware_hash_change PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME integration_firmware_hash_change COMMAND test_firmware_hash_change)
  set_tests_properties(integration_firmware_hash_change PROPERTIES
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  )

  add_executable(test_config_hash_change tests/integration/test_config_hash_change.c ${VANTAQ_TEST_SERVER_HARNESS_SRC})
  target_link_libraries(test_config_hash_change PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME integration_config_hash_change COMMAND test_config_hash_change)
  set_tests_properties(integration_config_hash_change PROPERTIES
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  )

  add_executable(test_evidence_config_hash_claim tests/integration/test_evidence_config_hash_claim.c ${VANTAQ_TEST_SERVER_HARNESS_SRC})
  target_link_libraries(test_evidence_config_hash_claim PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME integration_evidence_config_hash_claim COMMAND test_evidence_config_hash_claim)
  set_tests_properties(integration_evidence_config_hash_claim PROPERTIES
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  )

  add_executable(test_evidence_agent_integrity_claim tests/integration/test_evidence_agent_integrity_claim.c ${VANTAQ_TEST_SERVER_HARNESS_SRC})
  target_link_libraries(test_evidence_agent_integrity_claim PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME integration_evidence_agent_integrity_claim COMMAND test_evidence_agent_integrity_claim)
  set_tests_properties(integration_evidence_agent_integrity_claim PROPERTIES
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  )

  add_executable(test_evidence_boot_state_claim tests/integration/test_evidence_boot_state_claim.c ${VANTAQ_TEST_SERVER_HARNESS_SRC})
  target_link_libraries(test_evidence_boot_state_claim PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME integration_evidence_boot_state_claim COMMAND test_evidence_boot_state_claim)
  set_tests_properties(integration_evidence_boot_state_claim PROPERTIES
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  )

  add_executable(test_claim_selector_validation tests/integration/test_claim_selector_validation.c ${VANTAQ_TEST_SERVER_HARNESS_SRC})
  target_link_libraries(test_claim_selector_validation PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME integration_claim_selector_validation COMMAND test_claim_selector_validation)
  set_tests_properties(integration_claim_selector_validation PROPERTIES
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  )

  add_executable(test_selected_claims_only tests/integration/test_selected_claims_only.c ${VANTAQ_TEST_SERVER_HARNESS_SRC})
  target_link_libraries(test_selected_claims_only PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME integration_selected_claims_only COMMAND test_selected_claims_only)
  set_tests_properties(integration_selected_claims_only PROPERTIES
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  )

  add_executable(test_replayed_challenge tests/integration/test_replayed_challenge.c ${VANTAQ_TEST_SERVER_HARNESS_SRC})
  target_link_libraries(test_replayed_challenge PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME integration_replayed_challenge COMMAND test_replayed_challenge)
  set_tests_properties(integration_replayed_challenge PROPERTIES
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  )

  add_executable(test_malformed_evidence_request tests/integration/test_malformed_evidence_request.c ${VANTAQ_TEST_SERVER_HARNESS_SRC})
  target_link_libraries(test_malformed_evidence_request PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME integration_malformed_evidence_request COMMAND test_malformed_evidence_request)
  set_tests_properties(integration_malformed_evidence_request PROPERTIES
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  )

  add_executable(test_evidence_domain tests/unit/test_evidence_domain.c)
  target_link_libraries(test_evidence_domain PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME unit_evidence_domain COMMAND test_evidence_domain)

  add_executable(test_device_key_loader tests/unit/test_device_key_loader.c)
  target_link_libraries(test_device_key_loader PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME unit_device_key_loader COMMAND test_device_key_loader)

  add_executable(test_evidence_canonical tests/unit/test_evidence_canonical.c)
  target_link_libraries(test_evidence_canonical PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME unit_evidence_canonical COMMAND test_evidence_canonical)

  add_executable(test_evidence_signer tests/unit/test_evidence_signer.c)
  target_link_libraries(test_evidence_signer PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET} OpenSSL::Crypto)
  add_test(NAME unit_evidence_signer COMMAND test_evidence_signer)

  add_executable(test_create_evidence tests/unit/test_create_evidence.c)
  target_link_libraries(test_create_evidence PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET} OpenSSL::Crypto)
  add_test(NAME unit_create_evidence COMMAND test_create_evidence)

  add_executable(test_latest_evidence_store tests/unit/test_latest_evidence_store.c)
  target_link_libraries(test_latest_evidence_store PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME unit_latest_evidence_store COMMAND test_latest_evidence_store)

  add_executable(test_measurement_domain tests/unit/test_measurement_domain.c)
  target_link_libraries(test_measurement_domain PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME unit_measurement_domain COMMAND test_measurement_domain)

  add_executable(test_firmware_hash_measurement tests/unit/test_firmware_hash_measurement.c)
  target_link_libraries(test_firmware_hash_measurement PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET} OpenSSL::Crypto)
  add_test(NAME unit_firmware_hash_measurement COMMAND test_firmware_hash_measurement)

  add_executable(test_config_hash_measurement tests/unit/test_config_hash_measurement.c)
  target_link_libraries(test_config_hash_measurement PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET} OpenSSL::Crypto)
  add_test(NAME unit_config_hash_measurement COMMAND test_config_hash_measurement)

  add_executable(test_agent_integrity_measurement tests/unit/test_agent_integrity_measurement.c)
  target_link_libraries(test_agent_integrity_measurement PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET} OpenSSL::Crypto)
  add_test(NAME unit_agent_integrity_measurement COMMAND test_agent_integrity_measurement)

  add_executable(test_boot_state_measurement tests/unit/test_boot_state_measurement.c)
  target_link_libraries(test_boot_state_measurement PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME unit_boot_state_measurement COMMAND test_boot_state_measurement)

  add_executable(test_json_utils tests/unit/test_json_utils.c)
  target_include_directories(test_json_utils PRIVATE src/infrastructure/http_server)
  target_link_libraries(test_json_utils PRIVATE vantaq_core ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME unit_json_utils COMMAND test_json_utils)
endif()

option(VANTAQ_BUILD_TOOLS "Build CLI tools" ON)

if(VANTAQ_BUILD_TOOLS AND EXISTS "${CMAKE_SOURCE_DIR}/tools/verifier-cli/verify_evidence.c")
  # Tools
  add_executable(verify_evidence tools/verifier-cli/verify_evidence.c)
  target_link_libraries(verify_evidence PRIVATE vantaq_core OpenSSL::Crypto OpenSSL::SSL)
  set_target_properties(verify_evidence PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin"
  )
endif()
