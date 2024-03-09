cmake_minimum_required(VERSION 3.6 FATAL_ERROR)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 17)
endif()

option(
    SECUREFS_USE_VCPKG
    "Whether to use vcpkg for the dependencies. When off, pkg-config is used instead."
    ON)
option(SECUREFS_ENABLE_UNIT_TEST
       "Whether to build dedicated test binary and test it" ON)
option(SECUREFS_ENABLE_INTEGRATION_TEST
       "Whether to run integration test over real FUSE mounts" ON)
option(SECUREFS_USE_FUSET
       "Use FUSE-T instead of MacFUSE (only makes sense on macOS)" OFF)

project(securefs)
enable_testing()

set(CMAKE_FIND_FRAMEWORK NEVER)

if(APPLE)
    add_link_options(-Wl,-dead_strip)
endif()

execute_process(COMMAND bash -c "uname -m" OUTPUT_VARIABLE architecture)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake-modules/")
include(GetGitRevisionDescription)
git_describe(GIT_VERSION --tags)
configure_file(${CMAKE_SOURCE_DIR}/sources/git-version.cpp.in
               ${CMAKE_BINARY_DIR}/git-version.cpp)

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

include_directories(BEFORE sources)

file(GLOB SOURCES sources/*.cpp sources/*.h ${CMAKE_BINARY_DIR}/git-version.cpp)
file(GLOB TEST_SOURCES test/*.h test/*.cpp)
add_library(securefs-static STATIC ${SOURCES})
link_libraries(securefs-static)

if(WIN32)
    add_executable(securefs main.cpp securefs.manifest)
else()
    add_executable(securefs main.cpp)
endif()

find_package(Threads REQUIRED)
target_link_libraries(securefs-static PUBLIC Threads::Threads)
find_path(TCLAP_INCLUDE_DIRS "tclap/Arg.h")
target_include_directories(securefs-static PUBLIC ${TCLAP_INCLUDE_DIRS})
find_package(absl CONFIG REQUIRED)
target_link_libraries(
    securefs-static PUBLIC absl::base absl::inlined_vector absl::flat_hash_map
                           absl::strings absl::str_format absl::span)

if(SECUREFS_USE_VCPKG)
    find_package(cryptopp CONFIG REQUIRED)
    target_link_libraries(securefs-static PUBLIC cryptopp::cryptopp)
    find_package(unofficial-utf8proc CONFIG REQUIRED)
    target_link_libraries(securefs-static PUBLIC utf8proc)
    find_package(unofficial-argon2 CONFIG REQUIRED)
    target_link_libraries(securefs-static PUBLIC unofficial::argon2::libargon2)
    find_package(jsoncpp CONFIG REQUIRED)
    target_link_libraries(securefs-static PUBLIC JsonCpp::JsonCpp)
    find_package(unofficial-sqlite3 CONFIG REQUIRED)
    target_link_libraries(securefs-static PUBLIC unofficial::sqlite3::sqlite3)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(UTF8PROC REQUIRED libutf8proc)
    pkg_check_modules(ARGON2 REQUIRED libargon2)
    pkg_check_modules(JSONCPP REQUIRED jsoncpp)
    pkg_check_modules(SQLITE sqlite3 REQUIRED)
    target_include_directories(
        securefs-static SYSTEM
        PUBLIC ${UTF8PROC_INCLUDE_DIRS} ${ARGON2_INCLUDE_DIRS}
               ${JSONCPP_INCLUDE_DIRS} ${SQLITE_INCLUDE_DIRS})
    target_link_libraries(
        securefs-static
        PUBLIC ${CRYPTOPP_LDFLAGS} ${UTF8PROC_LDFLAGS} ${ARGON2_LDFLAGS}
               ${JSONCPP_LDFLAGS} ${SQLITE_LDFLAGS})
    find_library(CRYPTOPP_FLAGS NAMES cryptopp crypto++)
    target_link_libraries(securefs-static PUBLIC ${CRYPTOPP_FLAGS})
endif()

find_library(
    FRUIT_LIBRARY
    NAMES fruit
    HINTS (/usr /usr/local)
    PATH_SUFFIXES lib lib64)
target_link_libraries(securefs-static PUBLIC ${FRUIT_LIBRARY})

if(CMAKE_DL_LIBS)
    target_link_libraries(securefs-static PUBLIC ${CMAKE_DL_LIBS})
endif()

if(UNIX)
    find_path(FUSE_INCLUDE_DIR fuse.h PATHS /usr/local/include/fuse
                                            /usr/local/include)
    if(SECUREFS_USE_FUSET)
        find_library(FUSE_LIBRARIES fuse-t PATHS /usr/local/lib)
    else()
        find_library(FUSE_LIBRARIES fuse PATHS /usr/local/lib)
    endif()

    target_include_directories(securefs-static SYSTEM AFTER
                               PUBLIC ${FUSE_INCLUDE_DIR})
    target_link_libraries(securefs-static PUBLIC ${FUSE_LIBRARIES})
else()
    target_compile_options(
        securefs-static PUBLIC -DNOMINMAX=1 -D_CRT_SECURE_NO_WARNINGS=1
                               -D__STDC__=1 -DSTRSAFE_NO_DEPRECATE=1)
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
    target_include_directories(securefs-static SYSTEM AFTER
                               PUBLIC ${WINFSP_PREFIX}/inc ${FUSE_INCLUDE_DIR})
    target_link_libraries(securefs-static
                          PUBLIC ${WINFSP_PREFIX}/lib/winfsp-${ARCH}.lib)
    target_link_libraries(securefs-static PUBLIC delayimp.lib)
    if(MSVC)
        target_link_libraries(securefs-static
                              PUBLIC -DELAYLOAD:winfsp-${ARCH}.dll)
        target_compile_options(securefs-static PUBLIC /utf-8)
    else()
        target_link_libraries(securefs-static
                              PUBLIC -delayload=winfsp-${ARCH}.dll)
    endif()
endif()

if(SECUREFS_ENABLE_UNIT_TEST)
    add_executable(securefs_test ${TEST_SOURCES})
    find_package(doctest CONFIG REQUIRED)
    target_link_libraries(securefs_test PRIVATE doctest::doctest)
    add_test(NAME sec_test COMMAND securefs_test)
    target_compile_definitions(securefs_test
                               PRIVATE DOCTEST_CONFIG_SUPER_FAST_ASSERTS=1)
endif()

find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND AND SECUREFS_ENABLE_INTEGRATION_TEST)
    add_test(
        NAME simple_test
        COMMAND ${CMAKE_COMMAND} -E env SECUREFS_BINARY=$<TARGET_FILE:securefs>
                ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/test/simple_test.py)
endif()

install(TARGETS securefs DESTINATION bin)

if(MINGW)
    target_link_libraries(securefs PRIVATE -municode)
endif()
