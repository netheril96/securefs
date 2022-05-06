cmake_minimum_required(VERSION 3.0 FATAL_ERROR)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)

project(securefs)
enable_testing()
cmake_policy(SET CMP0048 NEW)
cmake_policy(SET CMP0069 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0069 NEW)

include(CheckIPOSupported)
check_ipo_supported(RESULT IPO_SUPPORTED OUTPUT error)

if(IPO_SUPPORTED)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO ON)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_MINSIZEREL ON)
endif()
set(CMAKE_FIND_FRAMEWORK NEVER)

execute_process(COMMAND bash -c "uname -m" OUTPUT_VARIABLE architecture)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake-modules/")
include(GetGitRevisionDescription)
git_describe(GIT_VERSION --tags)
configure_file(${CMAKE_SOURCE_DIR}/sources/git-version.cpp.in
               ${CMAKE_BINARY_DIR}/git-version.cpp)

file(COPY ${CMAKE_SOURCE_DIR}/external/cmake-cryptopp/CMakeLists.txt
     DESTINATION ${CMAKE_SOURCE_DIR}/external/cryptopp)

if(UNIX)
    find_path(FUSE_INCLUDE_DIR fuse.h PATHS /usr/local/include)
    find_library(FUSE_LIBRARIES fuse PATHS /usr/local/lib)
    include_directories(${FUSE_INCLUDE_DIR})
    link_libraries(${FUSE_LIBRARIES})
    add_compile_options(-Wall -Wextra -Wno-unknown-pragmas)

    if(APPLE)
        link_libraries(-Wl,-dead_strip)
    else()
        add_compile_options(-pthread)
        link_libraries(-pthread)
    endif()
    link_libraries(${CMAKE_DL_LIBS})
else()
    add_definitions(-DNOMINMAX=1)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS=1)
    add_definitions(-D__STDC__=1)
    if(NOT WINFSP_PREFIX)
        message("WINFSP_PREFIX not set, fallback to default value")
        set(WINFSP_PREFIX "C:/Program Files (x86)/WinFsp")
    endif()
    if(${CMAKE_SIZEOF_VOID_P} EQUAL 8)
        set(ARCH x64)
    else()
        set(ARCH x86)
    endif()
    set(FUSE_INCLUDE_DIR ${WINFSP_PREFIX}/inc/fuse)
    include_directories(${WINFSP_PREFIX}/inc)
    include_directories(${FUSE_INCLUDE_DIR})
    link_libraries(${WINFSP_PREFIX}/lib/winfsp-${ARCH}.lib)
    link_libraries(delayimp.lib)
    if(MSVC)
        link_libraries(-DELAYLOAD:winfsp-${ARCH}.dll)
        add_compile_options(/utf-8)
    elseif(MINGW)
        link_libraries(-delayload=winfsp-${ARCH}.dll)
    endif()
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(-Wthread-safety)
    if(MINGW)
        add_compile_options(-fansi-escape-codes -fcolor-diagnostics)
    endif()
endif()

add_definitions(-D_REENTRANT -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=28
                -DUTF8PROC_EXPORTS=1)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

include_directories(sources)
set(EXTERNAL_DIR external)
include_directories(${EXTERNAL_DIR})

set(CRYPTOPP_DIR ${EXTERNAL_DIR}/cryptopp)
add_subdirectory(${CRYPTOPP_DIR})
link_libraries(cryptopp-static)

add_subdirectory(${EXTERNAL_DIR}/argon2)
include_directories(${EXTERNAL_DIR}/argon2/include)
link_libraries(argon2_static)

file(
    GLOB
    SOURCES
    sources/*.cpp
    sources/*.h
    ${EXTERNAL_DIR}/*.h
    ${EXTERNAL_DIR}/*.hpp
    ${EXTERNAL_DIR}/*.cpp
    ${CMAKE_BINARY_DIR}/git-version.cpp
    ${EXTERNAL_DIR}/utf8proc/utf8proc.h
    ${EXTERNAL_DIR}/utf8proc/utf8proc.c)
file(GLOB TEST_SOURCES test/*.h test/*.cpp)
add_library(securefs-static STATIC ${SOURCES})
link_libraries(securefs-static)

if(MSVC)
    add_executable(securefs main.cpp securefs.manifest)
else()
    add_executable(securefs main.cpp)
endif()

add_executable(securefs_test ${TEST_SOURCES})

add_test(NAME sec_test COMMAND securefs_test)
find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
    add_test(
        NAME simple_test
        COMMAND ${CMAKE_COMMAND} -E env SECUREFS_BINARY=$<TARGET_FILE:securefs>
                ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/test/simple_test.py)
endif()

install(TARGETS securefs DESTINATION bin)

if(MINGW)
    target_link_libraries(securefs PRIVATE -municode)
endif()
