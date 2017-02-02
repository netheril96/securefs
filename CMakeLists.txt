cmake_minimum_required(VERSION 2.8.12 FATAL_ERROR)

option(PORTABLE_BUILD "Build for the general architecture instead of this cpu" OFF)
if (PORTABLE_BUILD)
    set(DISABLE_ASM ON)
    add_definitions(-DCRYPTOPP_DISABLE_ASM=1)
endif ()

project(securefs)
list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

if (UNIX)
    find_package(FUSE REQUIRED)
    include_directories(${FUSE_INCLUDE_DIR})
    link_libraries(${FUSE_LIBRARIES})
    add_compile_options(-Wall -Wextra -pedantic -std=gnu++11)

    if (NOT ${PORTABLE_BUILD})
        add_compile_options(-march=native -mtune=native)
    endif ()

    if (APPLE)
        link_libraries(-Wl,-dead_strip)
    endif ()
    link_libraries(${CMAKE_DL_LIBS})
else ()
    add_definitions(-DNOMINMAX=1)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS=1)
    add_definitions(-D__STDC__=1)
    if (NOT WINFSP_PREFIX)
        set(WINFSP_PREFIX "C:/Program Files (x86)/WinFsp")
    endif ()
    if (NOT WINFSP_PREFIX)
        message(FATAL_ERROR "WinFsp prefix not set or found")
    endif ()
    include_directories(${WINFSP_PREFIX}/inc/fuse)
    link_libraries(${WINFSP_PREFIX}/lib/winfsp-x64.lib)
    if (MSVC)
        add_compile_options(/MP)
    endif()
endif ()

add_definitions(-D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -DFUSE_USE_VERSION=28)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif ()

include(FeatureDetection)

include_directories(${PROJECT_SOURCE_DIR}/sources)
set(EXTERNAL_DIR ${PROJECT_SOURCE_DIR}/external)
include_directories(${EXTERNAL_DIR})

set(CRYPTOPP_DIR ${EXTERNAL_DIR}/cryptopp)
add_subdirectory(${CRYPTOPP_DIR})
link_libraries(cryptopp-static)

file(GLOB SOURCES ${PROJECT_SOURCE_DIR}/sources/*.cpp ${PROJECT_SOURCE_DIR}/sources/*.h ${EXTERNAL_DIR}/*.h ${EXTERNAL_DIR}/*.hpp ${EXTERNAL_DIR}/*.cpp)
file(GLOB TEST_SOURCES ${PROJECT_SOURCE_DIR}/test/*.cpp)
add_library(securefs-static STATIC ${SOURCES})
link_libraries(securefs-static)

add_executable(securefs ${PROJECT_SOURCE_DIR}/main.cpp)
add_executable(securefs_test ${TEST_SOURCES})

enable_testing()
add_test(NAME sec_test COMMAND securefs_test)
add_test(NAME simple_test COMMAND ${PROJECT_SOURCE_DIR}/test/simple_test.py)

install(TARGETS securefs DESTINATION bin)
