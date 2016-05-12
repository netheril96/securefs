cmake_minimum_required(VERSION 2.8.5 FATAL_ERROR)
project (securefs)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
if (UNIX)
find_package(FUSE REQUIRED)
include_directories(${FUSE_INCLUDE_DIR})
link_libraries(${FUSE_LIBRARIES})
set (CMAKE_CXX_FLAGS "-std=c++11 -Wall -Wextra -pedantic -D_FILE_OFFSET_BITS=64")

option(GENERAL_ARCH "Build for the general architecture instead of this cpu" OFF)
option(SANITIZE "Turn on sanitization" OFF)

if (${SANITIZE})
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
endif()

if (NOT ${GENERAL_ARCH})
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native -mtune=native")
endif()

if (APPLE)
	set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-dead_strip")
else()
	set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ffunction-sections -fdata-sections -pthread")
	set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections -pthread")
endif()

endif()

set (CMAKE_BUILD_TYPE Release)

include(FeatureDetection)

include_directories(${PROJECT_SOURCE_DIR}/sources)
set (EXTERNAL_DIR ${PROJECT_SOURCE_DIR}/external)
include_directories(${EXTERNAL_DIR})

set (CRYPTOPP_DIR ${EXTERNAL_DIR}/cryptopp)
add_subdirectory(${CRYPTOPP_DIR})
link_libraries(cryptopp-static)

file (GLOB SOURCES ${PROJECT_SOURCE_DIR}/sources/*.cpp ${PROJECT_SOURCE_DIR}/sources/*.h ${EXTERNAL_DIR}/*.h ${EXTERNAL_DIR}/*.hpp ${EXTERNAL_DIR}/*.cpp)
file (GLOB TEST_SOURCES ${PROJECT_SOURCE_DIR}/test/*.cpp)
add_library(securefs-static STATIC ${SOURCES})
link_libraries(securefs-static)

add_executable(securefs ${PROJECT_SOURCE_DIR}/main.cpp)
add_executable(securefs_test ${TEST_SOURCES})

enable_testing()
add_test(NAME sec_test COMMAND securefs_test)
add_test(NAME simple_test COMMAND ${PROJECT_SOURCE_DIR}/test/simple_test.py)

install(TARGETS securefs DESTINATION bin)
