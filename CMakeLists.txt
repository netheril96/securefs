cmake_minimum_required (VERSION 2.6)
project (securefs)

set (CMAKE_CXX_FLAGS "-O3 -std=c++11 -Wall -Wextra -pedantic -D_FILE_OFFSET_BITS=64")

set (CRYPTOPP_DIR "${PROJECT_SOURCE_DIR}/cryptopp")
include_directories("${PROJECT_SOURCE_DIR}/sources")
include_directories("${PROJECT_SOURCE_DIR}")

file (GLOB SOURCES "${PROJECT_SOURCE_DIR}/sources/*.cpp")
file (GLOB TEST_SOURCES "${PROJECT_SOURCE_DIR}/test/*.cpp")
add_executable(securefs ${SOURCES} main.cpp)
add_executable(securefs_test ${SOURCES} ${TEST_SOURCES})

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
find_package(FUSE REQUIRED)
include_directories("${FUSE_INCLUDE_DIR}")
target_link_libraries(securefs "${FUSE_LIBRARIES}")
target_link_libraries(securefs_test "${FUSE_LIBRARIES}")

add_subdirectory("${PROJECT_SOURCE_DIR}/cryptopp")
target_link_libraries(securefs cryptopp-static)
target_link_libraries(securefs_test cryptopp-static)

enable_testing()
add_test(NAME sec_test COMMAND securefs_test)
add_test(NAME simple_test COMMAND "${PROJECT_SOURCE_DIR}/test/simple_test.py")
