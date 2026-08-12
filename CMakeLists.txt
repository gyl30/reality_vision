cmake_minimum_required(VERSION 3.24)

project(reality_vision_cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(RV_BUILD_TESTS "Register tests with CTest" ON)
option(RV_ENABLE_PRIVILEGED_TESTS "Register Linux network namespace tests that require root" OFF)
set(RV_XRAY_EXECUTABLE "" CACHE FILEPATH "Path to the Xray executable for interop tests")

find_package(Boost REQUIRED CONFIG COMPONENTS program_options system)
find_package(OpenSSL REQUIRED CONFIG)
find_package(spdlog REQUIRED)
find_package(Threads REQUIRED)

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
  src/udp_proxy.cpp
  src/vision_codec.cpp
  src/vision_stream.cpp
  src/vless_header.cpp
  src/vless_stream.cpp
  src/vless_udp_stream.cpp)

target_compile_definitions(reality_vision PRIVATE BOOST_ASIO_NO_DEPRECATED)
target_include_directories(reality_vision PRIVATE src)
target_link_libraries(
  reality_vision
  PRIVATE Boost::headers
          Boost::program_options
          Boost::system
          OpenSSL::SSL
          OpenSSL::Crypto
          spdlog::spdlog
          Threads::Threads)

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
  add_test(
    NAME rv_invalid_resource_limit
    COMMAND
      reality_vision
      --server 127.0.0.1
      --port 443
      --server_name example.com
      --server_public_key uL4rG3uX_6B359RLXYFNTmSWnrBSLVv1PIG6NUWjMVk
      --short_id 01234567
      --uuid b831381d-6324-4d53-ad4f-8cda48b30811
      --socks_port 1080
      --max_tcp_sessions 0)
  set_tests_properties(rv_invalid_resource_limit PROPERTIES WILL_FAIL TRUE)

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
    endif()
  endif()
endif()
