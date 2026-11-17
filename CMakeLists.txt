cmake_minimum_required(VERSION 3.20)
project(zpsync VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(ZPSYNC_BUILD_TESTS "Build ZPSync CTest suite" ON)
option(ZPSYNC_BUILD_EXAMPLES "Build ZPSync CLI peer example" ON)
option(ZPSYNC_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

# Locate sibling zcrudp library (same layout as ../streaming)
set(ZCRUDP_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../zcrudp" CACHE PATH "Path to zcrudp repository")
if(NOT EXISTS "${ZCRUDP_DIR}/include/rudp_crypto.h")
  message(FATAL_ERROR "zcrudp not found at ${ZCRUDP_DIR}. Set -DZPSYNC_ZCRUDP_DIR or -DZCRUDP_DIR.")
endif()

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
  )

  foreach(test_name IN LISTS ZPSYNC_TESTS)
    add_executable(${test_name} tests/${test_name}.c)
    target_link_libraries(${test_name} PRIVATE zpsync)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
      target_compile_options(${test_name} PRIVATE -Wall -Wextra -pedantic)
    endif()
    add_test(NAME ${test_name} COMMAND ${test_name})
  endforeach()
endif()
