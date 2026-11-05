cmake_minimum_required(VERSION 3.24)

project(reality_vision_cpp LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(RV_BUILD_TESTS "Register tests with CTest" ON)
option(RV_ENABLE_PRIVILEGED_TESTS "Register Linux network namespace tests that require root" OFF)
set(RV_XRAY_EXECUTABLE "" CACHE FILEPATH "Path to the Xray executable for interop tests")

find_package(Boost REQUIRED CONFIG COMPONENTS program_options system)
find_package(spdlog REQUIRED)
find_package(Threads REQUIRED)

# BoringSSL 以 submodule 固定版本源码构建；只链接 libcrypto，不注册其测试。
set(BUILD_TESTING OFF)
add_subdirectory(third/boringssl EXCLUDE_FROM_ALL)

set(RV_LWIP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third/lwip)
file(
  GLOB RV_LWIP_SOURCES
  CONFIGURE_DEPENDS
  ${RV_LWIP_DIR}/src/core/*.c
  ${RV_LWIP_DIR}/src/core/ipv4/*.c
  ${RV_LWIP_DIR}/src/core/ipv6/*.c
  ${RV_LWIP_DIR}/src/api/err.c
  ${RV_LWIP_DIR}/src/ports/lib/mem.c
  src/lwip_port.c)

add_library(rv_lwip STATIC ${RV_LWIP_SOURCES})
target_include_directories(
  rv_lwip SYSTEM
  PUBLIC ${RV_LWIP_DIR}/src/include ${RV_LWIP_DIR}/src/ports/include)
if(MSVC)
  target_compile_options(rv_lwip PRIVATE /W0)
else()
  target_compile_options(rv_lwip PRIVATE -Wno-conversion -Wno-sign-conversion)
endif()

add_executable(
  reality_vision
  src/base64.cpp
  src/config.cpp
  src/crypto.cpp
  src/hex.cpp
  src/main.cpp
  src/network_address.cpp
  src/protocol_tests.cpp
  src/proxy_common.cpp
  src/reality_client_hello.cpp
  src/reality_handshake.cpp
  src/reality_record.cpp
  src/reality_stream.cpp
  src/service.cpp
  src/socks5_protocol.cpp
  src/sniffer.cpp
  src/tcp_byte_stream.cpp
  src/tcp_proxy.cpp
  src/transparent.cpp
  src/tun_device.cpp
  src/tun_inbound.cpp
  src/tun_lwip.cpp
  src/tun_tcp_session.cpp
  src/tun_udp_session.cpp
  src/udp_proxy.cpp
  src/vision_codec.cpp
  src/vision_stream.cpp
  src/vless_header.cpp
  src/vless_stream.cpp
  src/xudp_codec.cpp
  src/xudp_stream.cpp)

target_compile_definitions(reality_vision PRIVATE BOOST_ASIO_NO_DEPRECATED)
target_include_directories(reality_vision PRIVATE src)
target_link_libraries(
  reality_vision
  PRIVATE Boost::headers
          Boost::program_options
          Boost::system
          crypto
          spdlog::spdlog
          Threads::Threads
          rv_lwip)

if(MSVC)
  target_compile_options(reality_vision PRIVATE /W4 /permissive-)
else()
  target_compile_options(reality_vision PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(RV_BUILD_TESTS)
  enable_testing()
  if(RV_ENABLE_PRIVILEGED_TESTS AND NOT RV_XRAY_EXECUTABLE)
    message(FATAL_ERROR "RV_ENABLE_PRIVILEGED_TESTS requires RV_XRAY_EXECUTABLE")
  endif()
  add_test(NAME rv_protocol_tests COMMAND reality_vision --self_test)
  add_test(NAME rv_help COMMAND reality_vision --help)
  add_test(NAME rv_invalid_config COMMAND reality_vision --server localhost)
  set_tests_properties(rv_invalid_config PROPERTIES WILL_FAIL TRUE)
  if(RV_XRAY_EXECUTABLE)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_test(
      NAME rv_xray_interop
      COMMAND
        Python3::Interpreter
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop/run_xray_interop.py
        --xray ${RV_XRAY_EXECUTABLE}
        --client $<TARGET_FILE:reality_vision>
        --work-dir ${CMAKE_CURRENT_BINARY_DIR}/xray-interop)

    if(RV_ENABLE_PRIVILEGED_TESTS)
      add_test(
        NAME rv_transparent_interop
        COMMAND
          Python3::Interpreter
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop/run_transparent_interop.py
          run
          --xray ${RV_XRAY_EXECUTABLE}
          --client $<TARGET_FILE:reality_vision>
          --work-dir ${CMAKE_CURRENT_BINARY_DIR}/transparent-interop)
      set_tests_properties(rv_transparent_interop PROPERTIES LABELS "interop;privileged" RUN_SERIAL TRUE TIMEOUT 90)
      add_test(
        NAME rv_tun_interop
        COMMAND
          Python3::Interpreter
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/interop/run_tun_interop.py
          run
          --xray ${RV_XRAY_EXECUTABLE}
          --client $<TARGET_FILE:reality_vision>
          --work-dir ${CMAKE_CURRENT_BINARY_DIR}/tun-interop)
      set_tests_properties(rv_tun_interop PROPERTIES LABELS "interop;privileged" TIMEOUT 90)
    endif()
  endif()
endif()
