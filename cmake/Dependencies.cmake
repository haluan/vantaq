include(FetchContent)

function(vantaq_resolve_cmocka out_target)
  find_package(cmocka CONFIG QUIET)

  if(cmocka_FOUND AND TARGET cmocka::cmocka)
    set(${out_target} cmocka::cmocka PARENT_SCOPE)
    return()
  endif()

  FetchContent_Declare(
    cmocka
    GIT_REPOSITORY https://gitlab.com/cmocka/cmocka.git
    GIT_TAG cmocka-1.1.7
  )

  set(WITH_EXAMPLES OFF CACHE BOOL "" FORCE)
  set(WITH_STATIC_LIB OFF CACHE BOOL "" FORCE)
  set(WITH_CMOCKERY_SUPPORT OFF CACHE BOOL "" FORCE)
  set(WITH_CMOCKA_TESTS OFF CACHE BOOL "" FORCE)

  FetchContent_MakeAvailable(cmocka)

  if(TARGET cmocka::cmocka)
    set(${out_target} cmocka::cmocka PARENT_SCOPE)
    return()
  endif()

  if(TARGET cmocka)
    add_library(cmocka::cmocka ALIAS cmocka)
    set(${out_target} cmocka::cmocka PARENT_SCOPE)
    return()
  endif()

  message(FATAL_ERROR "Failed to resolve cmocka target")
endfunction()
