cmake_minimum_required(VERSION 3.20)
project(zpsync VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

string(COMPARE EQUAL "${CMAKE_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}" _zpsync_is_top_level)
option(ZPSYNC_BUILD_TESTS "Build ZPSync CTest suite" ${_zpsync_is_top_level})
option(ZPSYNC_BUILD_EXAMPLES "Build ZPSync CLI peer example" ${_zpsync_is_top_level})
option(ZPSYNC_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
option(ZPSYNC_AUTO_FETCH "Automatically download zcrudp when not found locally" ON)

set(ZCRUDP_GIT_REPO "https://github.com/i-Charlys/zcrudp.git" CACHE STRING "Git repository URL for zcrudp auto-fetch")
set(ZCRUDP_GIT_TAG "main" CACHE STRING "Git branch/tag for zcrudp auto-fetch")
set(ZCRUDP_DIR "" CACHE PATH "Path to zcrudp repository (optional; auto-detected or auto-fetched)")

# Locate zcrudp: explicit cache/env -> sibling ../zcrudp -> deps/zcrudp -> auto-fetch into build/_deps/zcrudp-src
set(_zpsync_zcrudp_candidates "")
if(DEFINED ZPSYNC_ZCRUDP_DIR AND NOT "${ZPSYNC_ZCRUDP_DIR}" STREQUAL "")
  list(APPEND _zpsync_zcrudp_candidates "${ZPSYNC_ZCRUDP_DIR}")
endif()
if(NOT "${ZCRUDP_DIR}" STREQUAL "")
  list(APPEND _zpsync_zcrudp_candidates "${ZCRUDP_DIR}")
endif()
if(DEFINED ENV{ZCRUDP_DIR} AND NOT "$ENV{ZCRUDP_DIR}" STREQUAL "")
  list(APPEND _zpsync_zcrudp_candidates "$ENV{ZCRUDP_DIR}")
endif()
list(APPEND _zpsync_zcrudp_candidates
  "${CMAKE_CURRENT_SOURCE_DIR}/../zcrudp"
  "${CMAKE_CURRENT_SOURCE_DIR}/deps/zcrudp"
  "${CMAKE_CURRENT_BINARY_DIR}/_deps/zcrudp-src"
)

set(_zpsync_zcrudp_found "")
foreach(_cand IN LISTS _zpsync_zcrudp_candidates)
  if(EXISTS "${_cand}/include/rudp_crypto.h")
    set(_zpsync_zcrudp_found "${_cand}")
    break()
  endif()
endforeach()

if("${_zpsync_zcrudp_found}" STREQUAL "" AND ZPSYNC_AUTO_FETCH)
  set(_zpsync_fetch_dir "${CMAKE_CURRENT_BINARY_DIR}/_deps/zcrudp-src")
  file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/_deps")
  find_package(Git QUIET)
  set(_fetch_ok FALSE)
  if(GIT_FOUND)
    message(STATUS "zpsync: zcrudp not found locally, cloning ${ZCRUDP_GIT_REPO} (${ZCRUDP_GIT_TAG})...")
    file(REMOVE_RECURSE "${_zpsync_fetch_dir}")
    execute_process(
      COMMAND "${GIT_EXECUTABLE}" clone --depth 1 --branch "${ZCRUDP_GIT_TAG}" "${ZCRUDP_GIT_REPO}" "${_zpsync_fetch_dir}"
      RESULT_VARIABLE _git_rc
    )
    if(_git_rc EQUAL 0 AND EXISTS "${_zpsync_fetch_dir}/include/rudp_crypto.h")
      set(_fetch_ok TRUE)
    else()
      file(REMOVE_RECURSE "${_zpsync_fetch_dir}")
    endif()
  endif()
  if(NOT _fetch_ok)
    string(REGEX REPLACE "\\.git$" "" _repo_base "${ZCRUDP_GIT_REPO}")
    set(_archive_url "${_repo_base}/archive/refs/heads/${ZCRUDP_GIT_TAG}.zip")
    set(_archive_file "${CMAKE_CURRENT_BINARY_DIR}/_deps/zcrudp.zip")
    set(_extract_dir "${CMAKE_CURRENT_BINARY_DIR}/_deps/_extract_zcrudp")
    message(STATUS "zpsync: downloading ${_archive_url}...")
    file(DOWNLOAD "${_archive_url}" "${_archive_file}" STATUS _dl_status TIMEOUT 60)
    list(GET _dl_status 0 _dl_code)
    if(_dl_code EQUAL 0)
      file(REMOVE_RECURSE "${_extract_dir}" "${_zpsync_fetch_dir}")
      file(MAKE_DIRECTORY "${_extract_dir}")
      file(ARCHIVE_EXTRACT INPUT "${_archive_file}" DESTINATION "${_extract_dir}")
      file(GLOB _extracted_dirs LIST_DIRECTORIES true "${_extract_dir}/*")
      foreach(_d IN LISTS _extracted_dirs)
        if(EXISTS "${_d}/include/rudp_crypto.h")
          file(RENAME "${_d}" "${_zpsync_fetch_dir}")
          set(_fetch_ok TRUE)
          break()
        endif()
      endforeach()
      file(REMOVE_RECURSE "${_extract_dir}" "${_archive_file}")
    endif()
  endif()
  if(_fetch_ok)
    set(_zpsync_zcrudp_found "${_zpsync_fetch_dir}")
  endif()
endif()

if("${_zpsync_zcrudp_found}" STREQUAL "")
  message(FATAL_ERROR
    "zcrudp not found. Place it at ../zcrudp, pass -DZCRUDP_DIR=<path>, or enable -DZPSYNC_AUTO_FETCH=ON with internet access."
  )
endif()
set(ZCRUDP_DIR "${_zpsync_zcrudp_found}")
message(STATUS "zpsync: using zcrudp at ${ZCRUDP_DIR}")

set(ZCRUDP_CORE_SOURCES
  "${ZCRUDP_DIR}/src/codec.c"
  "${ZCRUDP_DIR}/src/reliability.c"
  "${ZCRUDP_DIR}/src/session.c"
  "${ZCRUDP_DIR}/src/session_tx.c"
  "${ZCRUDP_DIR}/src/session_rx.c"
  "${ZCRUDP_DIR}/src/rx.c"
  "${ZCRUDP_DIR}/src/io.c"
  "${ZCRUDP_DIR}/src/crypto.c"
)

add_library(zcrudp_core STATIC ${ZCRUDP_CORE_SOURCES})
target_include_directories(zcrudp_core PUBLIC "${ZCRUDP_DIR}/include")
target_compile_definitions(zcrudp_core PUBLIC RUDP_WINDOW_SIZE=64 RUDP_MAX_CHANNELS=4)

set(ZPSYNC_SOURCES
  src/zpsync_net.c
  src/zpsync_crypto.c
  src/zpsync_stun.c
  src/zpsync_dht.c
  src/zpsync_sentinel.c
  src/zpsync_punch.c
  src/zpsync_cruise.c
  src/zpsync.c
)

add_library(zpsync STATIC ${ZPSYNC_SOURCES})
add_library(zpsync::zpsync ALIAS zpsync)

target_include_directories(zpsync
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(zpsync PUBLIC zcrudp_core)

if(WIN32)
  target_link_libraries(zpsync PUBLIC ws2_32 iphlpapi)
  target_compile_definitions(zpsync PRIVATE _WIN32_WINNT=0x0601 WIN32_LEAN_AND_MEAN)
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(zpsync PRIVATE -Wall -Wextra -pedantic)
  if(ZPSYNC_WARNINGS_AS_ERRORS)
    target_compile_options(zpsync PRIVATE -Werror)
  endif()
elseif(MSVC)
  target_compile_options(zpsync PRIVATE /W4)
endif()

if(ZPSYNC_BUILD_EXAMPLES)
  add_executable(zpsync_peer examples/zpsync_peer.c)
  target_link_libraries(zpsync_peer PRIVATE zpsync)
  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(zpsync_peer PRIVATE -Wall -Wextra -pedantic)
  endif()
endif()

if(ZPSYNC_BUILD_TESTS)
  enable_testing()

  set(ZPSYNC_TESTS
    test_crypto_derivation
    test_dht_bencode
    test_stun_codec
    test_sentinel_icmp
    test_punch_loopback
    test_nobel_breakthroughs
  )

  foreach(test_name IN LISTS ZPSYNC_TESTS)
    add_executable(${test_name} tests/${test_name}.c)
    target_link_libraries(${test_name} PRIVATE zpsync)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
      target_compile_options(${test_name} PRIVATE -Wall -Wextra -pedantic -UNDEBUG)
    elseif(MSVC)
      target_compile_options(${test_name} PRIVATE /UNDEBUG)
    endif()
    add_test(NAME ${test_name} COMMAND ${test_name})
  endforeach()
endif()
