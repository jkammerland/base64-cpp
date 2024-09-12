cmake_minimum_required(VERSION 3.28)

project(test_base64 CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror -Wpedantic")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Og -fno-omit-frame-pointer")

include(FetchContent)
FetchContent_Declare(googletest URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt
    ON
    CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

find_package(fmt REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(test_base64 test_base64.cpp)
target_include_directories(test_base64 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_base64 PRIVATE fmt::fmt OpenSSL::SSL OpenSSL::Crypto gtest_main)
target_compile_options(test_base64 PRIVATE -fsanitize=address)
target_link_options(test_base64 PRIVATE -fsanitize=address)
add_test(NAME test_base64 COMMAND run_test_base64)

add_executable(test_sha256 test_sha256.cpp)
target_include_directories(test_sha256 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_sha256 PRIVATE fmt::fmt OpenSSL::SSL OpenSSL::Crypto gtest_main)
target_compile_options(test_sha256 PRIVATE -fsanitize=address)
target_link_options(test_sha256 PRIVATE -fsanitize=address)
add_test(NAME test_sha256 COMMAND run_test_sha256)

add_executable(test_asn1 rs_to_der.cpp)
target_include_directories(test_asn1 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_asn1 PRIVATE fmt::fmt OpenSSL::SSL OpenSSL::Crypto gtest_main)
target_compile_options(test_asn1 PRIVATE -fsanitize=address)
target_link_options(test_asn1 PRIVATE -fsanitize=address)
