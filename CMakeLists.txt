cmake_minimum_required(VERSION 3.14)
project(RollingSignatures C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Include directories
include_directories(inc)

# Collect main executable sources
file(GLOB SOURCES "src/*.c")

# Create the main executable
add_executable(${PROJECT_NAME} ${SOURCES})

# Enable testing
enable_testing()

# Add test executable directly in the root CMakeLists.txt
add_executable(test_rolling tests/test_main.c src/rolling.c)
target_include_directories(test_rolling PRIVATE inc)

# Register with CTest
add_test(NAME test_rolling COMMAND test_rolling)
