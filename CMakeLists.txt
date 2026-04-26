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
  src/infrastructure/http_server/http_server.c
)

add_library(vantaq_core STATIC ${VANTAQ_COMMON_SOURCES})
target_include_directories(vantaq_core PUBLIC include)

if(MSVC)
  target_compile_options(vantaq_core PRIVATE /W4)
else()
  target_compile_options(vantaq_core PRIVATE -Wall -Wextra -Wpedantic)
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

  add_executable(test_cli_smoke tests/integration/test_cli_smoke.c)
  target_link_libraries(test_cli_smoke PRIVATE ${VANTAQ_CMOCKA_TARGET})
  add_test(NAME integration_cli_smoke COMMAND test_cli_smoke)
  set_tests_properties(integration_cli_smoke PROPERTIES
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  )
endif()
