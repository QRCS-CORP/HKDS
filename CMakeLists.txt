cmake_minimum_required(VERSION 3.12)

project(HKDS C)

# Project version
set(HKDS_VERSION_MAJOR 1)
set(HKDS_VERSION_MINOR 0)
set(HKDS_VERSION_PATCH 0)
set(HKDS_VERSION "${HKDS_VERSION_MAJOR}.${HKDS_VERSION_MINOR}.${HKDS_VERSION_PATCH}")

# Set default to Release if not specified
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler features
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Source files
file(GLOB_RECURSE HKDS_SOURCES "Source/HKDS/*.c")
file(GLOB_RECURSE HKDS_HEADERS "Source/HKDS/*.h")

# Add library target
add_library(hkds STATIC ${HKDS_SOURCES} ${HKDS_HEADERS})
target_include_directories(hkds PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Enable warnings
if(MSVC)
  target_compile_options(hkds PRIVATE /W4)
else()
  target_compile_options(hkds PRIVATE -Wall -Wextra -pedantic -Werror)
endif()

# Install rules
install(TARGETS hkds DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)

# Testing support
enable_testing()
# add_subdirectory(HKDSTest)
