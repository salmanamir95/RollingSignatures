cmake_minimum_required(VERSION 3.14)
project(RollingSignatures C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Include directories
include_directories(inc)
find_package(OpenSSL REQUIRED)

# Collect main executable sources
file(GLOB SOURCES "src/*.c")

# Create the main executable
add_executable(${PROJECT_NAME} ${SOURCES})

# Enable testing
enable_testing()

# Add test executable directly in the root CMakeLists.txt
add_executable(test_rolling tests/test_main.c src/rolling.c)
target_include_directories(test_rolling PRIVATE inc)

# Add packet test
add_executable(test_packet tests/test_packet.c)
target_include_directories(test_packet PRIVATE inc)
target_link_libraries(test_packet PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Register with CTest
add_test(NAME test_rolling COMMAND test_rolling)
add_test(NAME test_packet COMMAND test_packet)
