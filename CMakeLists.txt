cmake_minimum_required(VERSION 3.24)

project(reality_vision_cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(RV_BUILD_TESTS "Register tests with CTest" ON)
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
  src/protocol_tests.cpp
  src/reality_client_hello.cpp
  src/reality_handshake.cpp
  src/reality_record.cpp
  src/reality_stream.cpp
  src/socks5_protocol.cpp
  src/tcp_byte_stream.cpp
  src/vision_codec.cpp
  src/vision_stream.cpp
  src/vless_header.cpp
  src/vless_stream.cpp)

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
  add_test(NAME rv_protocol_tests COMMAND reality_vision --self_test)

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
  endif()
endif()
