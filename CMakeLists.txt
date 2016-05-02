cmake_minimum_required (VERSION 2.6)
project (securefs)

set (CMAKE_CXX_FLAGS "-O3 -std=c++11 -Wall -Wextra -pedantic -D_FILE_OFFSET_BITS=64")

set (CRYPTOPP_DIR "${PROJECT_SOURCE_DIR}/cryptopp")
include_directories("${PROJECT_SOURCE_DIR}/sources")
include_directories("${CRYPTOPP_DIR}/include")

file (GLOB SOURCES "${PROJECT_SOURCE_DIR}/sources/*.cpp")
add_executable(securefs ${SOURCES} main.cpp)

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
find_package(FUSE REQUIRED)
include_directories("${FUSE_INCLUDE_DIR}")
target_link_libraries(securefs "${FUSE_LIBRARIES}")

add_subdirectory("${PROJECT_SOURCE_DIR}/cryptopp")
target_link_libraries(securefs cryptopp-static)
