cmake_minimum_required(VERSION 3.14)
project(HMACRouting C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Include directories
include_directories(inc)
find_package(OpenSSL REQUIRED)

# Collect main executable sources
file(GLOB SOURCES "src/*.c")

# Create the main executable
add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Enable testing
enable_testing()

# Add HMAC routing test
add_executable(test_hmac_routing tests/test_hmac_routing.c)
target_include_directories(test_hmac_routing PRIVATE inc)
target_link_libraries(test_hmac_routing PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Register with CTest
add_test(NAME test_hmac_routing COMMAND test_hmac_routing)
