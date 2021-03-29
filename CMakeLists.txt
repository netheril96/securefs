cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

project(securefs)
if (POLICY CMP0048)
  cmake_policy(SET CMP0048 NEW)
endif()

set (CMAKE_FIND_FRAMEWORK NEVER)

execute_process (
    COMMAND bash -c "uname -m"
    OUTPUT_VARIABLE architecture
)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake-modules/")
include(GetGitRevisionDescription)
git_describe(GIT_VERSION --tags)
configure_file(${CMAKE_SOURCE_DIR}/sources/git-version.cpp.in ${CMAKE_BINARY_DIR}/git-version.cpp)

if (UNIX)
    find_path(FUSE_INCLUDE_DIR fuse.h PATHS /usr/local/include)
    find_library(FUSE_LIBRARIES fuse PATHS /usr/local/lib)
    include_directories(${FUSE_INCLUDE_DIR})
    link_libraries(${FUSE_LIBRARIES})
    add_compile_options(-Wall -Wextra -Wno-unknown-pragmas)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --std=gnu++11")

    if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        add_compile_options(-Wthread-safety -Wthread-safety-negative)
    endif()

    if (APPLE)
        link_libraries(-Wl,-dead_strip)
    else ()
        add_compile_options(-pthread)
        link_libraries(-pthread)
    endif ()
    link_libraries(${CMAKE_DL_LIBS})
else ()
    add_definitions(-DNOMINMAX=1)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS=1)
    add_definitions(-D__STDC__=1)
    if (NOT WINFSP_PREFIX)
        message("WINFSP_PREFIX not set, fallback to default value")
        set(WINFSP_PREFIX "C:/Program Files (x86)/WinFsp")
    endif ()
    if (${CMAKE_SIZEOF_VOID_P} EQUAL 8)
        set(ARCH x64)
    else ()
        set(ARCH x86)
    endif ()
    set(FUSE_INCLUDE_DIR ${WINFSP_PREFIX}/inc/fuse)
    include_directories(${WINFSP_PREFIX}/inc)
    include_directories(${FUSE_INCLUDE_DIR})
    link_libraries(${WINFSP_PREFIX}/lib/winfsp-${ARCH}.lib)
    link_libraries(-DELAYLOAD:winfsp-${ARCH}.dll)
    link_libraries(delayimp.lib)
    add_compile_options(/MP)
endif ()

add_definitions(-D_REENTRANT -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=28 -DUTF8PROC_EXPORTS=1)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif ()

include_directories(sources)
set(EXTERNAL_DIR external)
include_directories(${EXTERNAL_DIR})

set(CRYPTOPP_DIR ${EXTERNAL_DIR}/cryptopp)
add_subdirectory(${CRYPTOPP_DIR})
link_libraries(cryptopp-static)

file(GLOB SOURCES sources/*.cpp sources/*.h ${EXTERNAL_DIR}/*.h ${EXTERNAL_DIR}/*.hpp ${EXTERNAL_DIR}/*.cpp ${CMAKE_BINARY_DIR}/git-version.cpp ${EXTERNAL_DIR}/utf8proc/utf8proc.h ${EXTERNAL_DIR}/utf8proc/utf8proc.c)
file(GLOB TEST_SOURCES test/*.cpp)
add_library(securefs-static STATIC ${SOURCES})
link_libraries(securefs-static)

add_executable(securefs main.cpp)
add_executable(securefs_test ${TEST_SOURCES})

include(CheckCXXSourceRuns)
CHECK_CXX_SOURCE_RUNS("int main() { thread_local int i = 0; return i; }" HAS_THREAD_LOCAL)

CHECK_CXX_SOURCE_RUNS("
#include <time.h>

int main() {
    timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return 0;
}
" HAS_CLOCK_GETTIME)

CHECK_CXX_SOURCE_RUNS("
#include <unistd.h>
#include <sys/stat.h>

int main() {
    futimens(-1, nullptr);
    return 0;
}
" HAS_FUTIMENS)

CHECK_CXX_SOURCE_RUNS("
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

int main() {
    utimensat(-1, nullptr, nullptr, 0);
    return 0;
}
" HAS_UTIMENSAT)

configure_file(sources/securefs_config.in securefs_config.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

enable_testing()
add_test(NAME sec_test COMMAND securefs_test)
find_package(Python3 COMPONENTS Interpreter)
if (Python3_FOUND)
    add_test(NAME simple_test COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/test/simple_test.py)
else()
add_test(NAME simple_test COMMAND python3 ${PROJECT_SOURCE_DIR}/test/simple_test.py)
endif()

install(TARGETS securefs DESTINATION bin)
