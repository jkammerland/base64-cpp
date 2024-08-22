cmake_minimum_required(VERSION 3.15)

find_package(fmt REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json REQUIRED)

add_executable(test_base64 test_base64.cpp)
target_include_directories(test_base64 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_base64 PRIVATE fmt::fmt OpenSSL::SSL OpenSSL::Crypto nlohmann_json::nlohmann_json)
target_compile_options(test_base64 PRIVATE -fsanitize=address)
target_link_options(test_base64 PRIVATE -fsanitize=address)
add_test(NAME test_base64 COMMAND run_test_base64)
