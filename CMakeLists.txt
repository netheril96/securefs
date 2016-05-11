cmake_minimum_required(VERSION 2.8.5 FATAL_ERROR)
project (securefs)

set (CMAKE_CXX_FLAGS "-std=c++11 -Wall -Wextra -pedantic -D_FILE_OFFSET_BITS=64")
set (CMAKE_BUILD_TYPE Release)

option(GENERAL_ARCH "Build for the general architecture instead of this cpu" OFF)
option(SANITIZE "Turn on sanitization" OFF)

if (SANITIZE)
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
endif()

if (GENERAL_ARCH)
else()
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native -mtune=native")
endif()

if (APPLE)
	set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-dead_strip")
else()
	set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ffunction-sections -fdata-sections -pthread")
	set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections -pthread")
endif()

set (CRYPTOPP_DIR ${PROJECT_SOURCE_DIR}/cryptopp)
include_directories(${PROJECT_SOURCE_DIR}/sources)
include_directories(${PROJECT_SOURCE_DIR})

file (GLOB SOURCES ${PROJECT_SOURCE_DIR}/sources/*.cpp ${PROJECT_SOURCE_DIR}/sources/*.h)
file (GLOB TEST_SOURCES ${PROJECT_SOURCE_DIR}/test/*.cpp)
add_executable(securefs ${SOURCES} main.cpp)
add_executable(securefs_test ${SOURCES} ${TEST_SOURCES})

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
find_package(FUSE REQUIRED)
include_directories(${FUSE_INCLUDE_DIR})
target_link_libraries(securefs ${FUSE_LIBRARIES})
target_link_libraries(securefs_test ${FUSE_LIBRARIES})

add_subdirectory(${PROJECT_SOURCE_DIR}/cryptopp)
target_link_libraries(securefs cryptopp-static)
target_link_libraries(securefs_test cryptopp-static)

enable_testing()
add_test(NAME sec_test COMMAND securefs_test)
add_test(NAME simple_test COMMAND ${PROJECT_SOURCE_DIR}/test/simple_test.py)

install(TARGETS securefs DESTINATION bin)
