cmake_minimum_required(VERSION 3.10 FATAL_ERROR)
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
option(SECUREFS_LINK_PROFILER "Enable linking with gperftools profiler" OFF)
option(SECUREFS_ENABLE_MIMALLOC "Enable linking with mimalloc." OFF)
option(SECUREFS_ENABLE_JEMALLOC "Enable linking with jemalloc." OFF)
option(SECUREFS_ADDRESS_SANITIZE "Enable address sanitizer" OFF)
project(securefs)
enable_testing()

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(SECUREFS_ADDRESS_SANITIZE)
    add_compile_options($<$<CONFIG:Debug>:-fsanitize=address>)
    add_link_options($<$<CONFIG:Debug>:-fsanitize=address>)
endif()

if(${SECUREFS_LINK_PROFILER})
    add_compile_options(-g)
endif()

set(CMAKE_FIND_FRAMEWORK NEVER)

if(APPLE)
    add_link_options(-Wl,-dead_strip)
    add_compile_options(-fvisibility=hidden -fvisibility-inlines-hidden)
endif()

# Generate is_fuse_t.h based on SECUREFS_USE_FUSET option
set(SECUREFS_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/securefs_generated)
file(MAKE_DIRECTORY ${SECUREFS_GENERATED_DIR})

if(SECUREFS_USE_FUSET)
    set(SECUREFS_IS_FUSE_T_VALUE_FOR_HEADER "true")
else()
    set(SECUREFS_IS_FUSE_T_VALUE_FOR_HEADER "false")
endif()

configure_file("${CMAKE_SOURCE_DIR}/sources/is_fuse_t.h.in"
               "${SECUREFS_GENERATED_DIR}/is_fuse_t.h" @ONLY)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake-modules/")
include(GetGitRevisionDescription)
git_describe(GIT_VERSION --tags)
configure_file(${CMAKE_SOURCE_DIR}/sources/git-version.cpp.in
               ${SECUREFS_GENERATED_DIR}/git-version.cpp @ONLY)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(-Wthread-safety)
    if(MINGW)
        add_compile_options(-fansi-escape-codes -fcolor-diagnostics)
    elseif(MSVC) # This implies clang-cl
        # Disable -Winvalid-offsetof for clang-cl as it can be noisy when
        # compiling protobuf files.
        add_compile_options(-Wno-invalid-offsetof)
    endif()
endif()

include_directories(BEFORE sources)

file(GLOB SOURCES sources/*.cpp sources/*.h
     ${SECUREFS_GENERATED_DIR}/git-version.cpp)
file(GLOB TEST_SOURCES test/*.h test/*.cpp)
add_library(securefs-static STATIC ${SOURCES})

# Add generated headers directory for is_fuse_t.h to securefs-static's include
# directories
target_include_directories(securefs-static
                           PUBLIC $<BUILD_INTERFACE:${SECUREFS_GENERATED_DIR}>)

if(WIN32)
    add_executable(securefs main.cpp securefs.manifest)
else()
    add_executable(securefs main.cpp)
endif()
target_link_libraries(securefs PRIVATE securefs-static)

find_package(Threads REQUIRED)
target_link_libraries(securefs-static PUBLIC Threads::Threads)
find_path(TCLAP_INCLUDE_DIRS "tclap/Arg.h")
target_include_directories(securefs-static PUBLIC SYSTEM ${TCLAP_INCLUDE_DIRS})
find_package(absl CONFIG REQUIRED)
find_package(uni-algo CONFIG REQUIRED)
find_package(Protobuf CONFIG REQUIRED)
target_link_libraries(
    securefs-static
    PUBLIC uni-algo::uni-algo
           absl::base
           absl::time
           absl::synchronization
           absl::inlined_vector
           absl::flat_hash_map
           absl::strings
           absl::str_format
           absl::span
           absl::failure_signal_handler)
add_library(securefs-proto OBJECT protos/params.proto)
target_link_libraries(securefs-proto PUBLIC protobuf::libprotobuf)
set(PROTO_BINARY_DIR "${SECUREFS_GENERATED_DIR}")
target_include_directories(securefs-proto
                           PUBLIC "$<BUILD_INTERFACE:${PROTO_BINARY_DIR}>")
protobuf_generate(TARGET securefs-proto IMPORT_DIRS "protos" PROTOC_OUT_DIR
                  "${PROTO_BINARY_DIR}")
target_link_libraries(securefs-static PUBLIC securefs-proto)
if(SECUREFS_USE_VCPKG)
    find_package(cryptopp CONFIG REQUIRED)
    target_link_libraries(securefs-static PUBLIC cryptopp::cryptopp)
    find_package(unofficial-argon2 CONFIG REQUIRED)
    target_link_libraries(securefs-static PUBLIC unofficial::argon2::libargon2)
    find_package(unofficial-sqlite3 CONFIG REQUIRED)
    target_link_libraries(securefs-static PUBLIC unofficial::sqlite3::sqlite3)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(ARGON2 libargon2 REQUIRED)
    pkg_check_modules(SQLITE sqlite3 REQUIRED)
    pkg_check_modules(CRYPTOPP libcryptopp REQUIRED)

    target_include_directories(
        securefs-static SYSTEM
        PUBLIC ${ARGON2_INCLUDE_DIRS} ${SQLITE_INCLUDE_DIRS}
               ${CRYPTOPP_INCLUDE_DIRS})
    target_link_libraries(
        securefs-static PUBLIC ${CRYPTOPP_LDFLAGS} ${ARGON2_LDFLAGS}
                               ${SQLITE_LDFLAGS})
    target_compile_options(
        securefs-static PUBLIC ${CRYPTOPP_CFLAGS} ${ARGON2_CFLAGS}
                               ${SQLITE_CFLAGS})

endif()

if(SECUREFS_ENABLE_MIMALLOC)
    find_package(mimalloc CONFIG REQUIRED)
    target_link_libraries(
        securefs-static
        PUBLIC $<IF:$<TARGET_EXISTS:mimalloc-static>,mimalloc-static,mimalloc>)
endif()

if(SECUREFS_ENABLE_JEMALLOC)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(JEMALLOC jemalloc REQUIRED)
    target_include_directories(securefs-static SYSTEM
                               PUBLIC ${JEMALLOC_INCLUDE_DIRS})
    target_link_libraries(securefs-static PUBLIC ${JEMALLOC_LDFLAGS})
endif()

if(UNIX)
    find_package(PkgConfig REQUIRED)

    if(SECUREFS_USE_FUSET)
        pkg_check_modules(FUSE fuse-t REQUIRED)
    else()
        pkg_check_modules(FUSE fuse REQUIRED)
    endif()

    target_include_directories(securefs-static SYSTEM AFTER
                               PUBLIC ${FUSE_INCLUDE_DIRS})
    target_link_libraries(securefs-static PUBLIC ${FUSE_LDFLAGS})
    target_compile_options(securefs-static PUBLIC ${FUSE_CFLAGS})
    target_compile_definitions(securefs-static PUBLIC -D_FILE_OFFSET_BITS=64
                                                      -DFUSE_USE_VERSION=29)
else()
    target_compile_definitions(
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
    target_link_libraries(securefs_test PRIVATE doctest::doctest
                                                securefs-static)
    add_test(
        NAME sec_test
        COMMAND
            ${CMAKE_COMMAND} -E env
            SECUREFS_TEST_REFERENCE=${PROJECT_SOURCE_DIR}/test/reference
            $<TARGET_FILE:securefs_test>)
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

if(SECUREFS_LINK_PROFILER)
    target_link_libraries(securefs PRIVATE -Wl,--no-as-needed -lprofiler)
endif()
