cmake_minimum_required(VERSION 3.20)

project(RollingSignatures LANGUAGES C CXX)

# -------------------------------------------------
# Header-only library (NO compilation)
# -------------------------------------------------
add_library(RollingSignatures INTERFACE)

# -------------------------------------------------
# Include directories
# -------------------------------------------------
target_include_directories(RollingSignatures INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
)

# -------------------------------------------------
# Dependency: shared (crypto + core utilities)
# -------------------------------------------------
target_link_libraries(RollingSignatures INTERFACE shared)

# -------------------------------------------------
# Language standard
# -------------------------------------------------
target_compile_features(RollingSignatures INTERFACE cxx_std_23)
