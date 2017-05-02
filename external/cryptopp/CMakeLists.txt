# Please ensure your changes or patch meets minimum requirements.
#   The minimum requirements are 2.8.5. They roughly equate to Ubuntu 12.04 LTS
#   Please do not check in something for 2.8.12 or 3.5.0. To test your changes,
#   please set up a Ubuntu 12.04 LTS system. Then, manually install Cmake 2.8.5
#   from http://cmake.org/Wiki/CMake_Released_Versions.

# This file has been tweaked for cryptopp to be embedded in `securefs`.
# Please download the original sources if you need to build cryptopp for
# another project or as a general library.

cmake_minimum_required(VERSION 2.8.5 FATAL_ERROR)

project(cryptopp)

# Make RelWithDebInfo the default (it does e.g. add '-O2 -g -DNDEBUG' for GNU)
#   If not in multi-configuration environments, no explicit build type or CXX
#   flags are set by the user and if we are the root CMakeLists.txt file.
if (NOT CMAKE_CONFIGURATION_TYPES AND
    NOT CMAKE_NO_BUILD_TYPE AND
    NOT CMAKE_BUILD_TYPE AND
    NOT CMAKE_CXX_FLAGS AND
    CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
	set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

set(cryptopp_VERSION_MAJOR 5)
set(cryptopp_VERSION_MINOR 6)
set(cryptopp_VERSION_PATCH 5)

include(GNUInstallDirs)
include(TestBigEndian)
include(CheckCXXCompilerFlag)

#============================================================================
# Settable options
#============================================================================

option(BUILD_STATIC "Build static library" ON)

option(DISABLE_ASM "Disable ASM" OFF)
option(DISABLE_SSSE3 "Disable SSSE3" OFF)
option(DISABLE_AESNI "Disable AES-NI" OFF)
set(CRYPTOPP_DATA_DIR "" CACHE PATH "Crypto++ test data directory")

#============================================================================
# Internal compiler options
#============================================================================

# Stop hiding the damn output...
# set(CMAKE_VERBOSE_MAKEFILE on)

# Always 1 ahead in Master. Also see http://groups.google.com/forum/#!topic/cryptopp-users/SFhqLDTQPG4
set(LIB_VER ${cryptopp_VERSION_MAJOR}${cryptopp_VERSION_MINOR}${cryptopp_VERSION_PATCH})

# Only set when cross-compiling, http://www.vtk.org/Wiki/CMake_Cross_Compiling
if (NOT (CMAKE_SYSTEM_VERSION AND CMAKE_SYSTEM_PROCESSOR))
	set(CRYPTOPP_CROSS_COMPILE 1)
else()
	set(CRYPTOPP_CROSS_COMPILE 0)
endif()

# Don't use RPATH's. The resulting binary could fail a security audit.
if (NOT CMAKE_VERSION VERSION_LESS 2.8.12)
  set(CMAKE_MACOSX_RPATH 0)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "Intel")
	add_definitions(-wd68 -wd186 -wd279 -wd327 -wd161 -wd3180)
endif()

# Endianess
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
if(IS_BIG_ENDIAN)
	add_definitions(-DIS_BIG_ENDIAN)
endif()

if(DISABLE_ASM)
	add_definitions(-DCRYPTOPP_DISABLE_ASM)
endif()
if(DISABLE_SSSE3)
	add_definitions(-DCRYPTOPP_DISABLE_SSSE3)
endif()
if(DISABLE_AESNI)
	add_definitions(-DCRYPTOPP_DISABLE_AESNI)
endif()
if(NOT CRYPTOPP_DATA_DIR STREQUAL "")
	add_definitions(-DCRYPTOPP_DATA_DIR="${CRYPTOPP_DATA_DIR}")
endif()

# We need the output 'uname -s' for Unix and Linux system detection
if (NOT CRYPTOPP_CROSS_COMPILE)
	set (UNAME_CMD "uname")
	set (UNAME_ARG "-s")
	execute_process(COMMAND ${UNAME_CMD} ${UNAME_ARG}
		WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
		RESULT_VARIABLE UNAME_RESULT
		OUTPUT_VARIABLE UNAME_SYSTEM)
		string(REGEX REPLACE "\n$" "" UNAME_SYSTEM "${UNAME_SYSTEM}")
endif()

# We need the output 'uname -m' for Unix and Linux platform detection
if (NOT CRYPTOPP_CROSS_COMPILE)
	set (UNAME_CMD "uname")
	set (UNAME_ARG "-m")
	execute_process(COMMAND ${UNAME_CMD} ${UNAME_ARG}
		WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
		RESULT_VARIABLE UNAME_RESULT
		OUTPUT_VARIABLE UNAME_MACHINE)
	string(REGEX REPLACE "\n$" "" UNAME_MACHINE "${UNAME_MACHINE}")
endif()

if(WINDOWS_STORE OR WINDOWS_PHONE)
	if("${CMAKE_SYSTEM_VERSION}" MATCHES "10\\.0.*")
		SET( CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} /D\"_WIN32_WINNT=0x0A00\"" )
	endif()
	SET( CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} /FI\"winapifamily.h\"" )
endif()

# Link is driven through the compiler, but CXXFLAGS are not used. Also see
#   http://public.kitware.com/pipermail/cmake/2003-June/003967.html
if (NOT (WINDOWS OR WINDOWS_STORE OR WINDOWS_PHONE))
	SET(CMAKE_CXX_LINK_FLAGS "${CMAKE_CXX_FLAGS}")
endif()

#============================================================================
# Sources & headers
#============================================================================

# Library headers
file(GLOB cryptopp_HEADERS *.h)

# Library sources. You can use the GNUmakefile to generate the list: `make sources`.
file(GLOB cryptopp_SOURCES *.cpp)
list(REMOVE_ITEM cryptopp_SOURCES
		${CMAKE_CURRENT_SOURCE_DIR}/cryptlib.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/cpu.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/integer.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/pch.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/simple.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/winpipes.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/cryptlib_bds.cpp
		${cryptopp_SOURCES_TEST}
		)
set(cryptopp_SOURCES
		${CMAKE_CURRENT_SOURCE_DIR}/cryptlib.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/cpu.cpp
		${CMAKE_CURRENT_SOURCE_DIR}/integer.cpp
		${cryptopp_SOURCES}
		)

if(MINGW OR WIN32)
	list(APPEND cryptopp_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/winpipes.cpp)
endif()

if(MSVC AND NOT DISABLE_ASM)
	if(${CMAKE_GENERATOR} MATCHES ".*ARM")
		message(STATUS "Disabling ASM because ARM is specified as target platform.")
	else()
		if(CMAKE_SIZEOF_VOID_P EQUAL 8)
			list(APPEND cryptopp_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/x64dll.asm)
			list(APPEND cryptopp_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/x64masm.asm)
			set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/x64dll.asm PROPERTIES COMPILE_FLAGS "/D_M_X64")
			set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/x64masm.asm PROPERTIES COMPILE_FLAGS "/D_M_X64")
			set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/rdrand.asm PROPERTIES COMPILE_FLAGS "/D_M_X64")
		else()
			set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/x64dll.asm PROPERTIES COMPILE_FLAGS "/D_M_X86 /safeseh")
			set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/x64masm.asm PROPERTIES COMPILE_FLAGS "/D_M_X86 /safeseh")
			set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/rdrand.asm PROPERTIES COMPILE_FLAGS "/D_M_X86 /safeseh")
		endif()
		list(APPEND cryptopp_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/rdrand.asm)
		enable_language(ASM_MASM)
	endif()
endif()

#============================================================================
# Compile targets
#============================================================================

# Set global includes BEFORE adding any targets for legacy CMake versions
if(CMAKE_VERSION VERSION_LESS 2.8.12)
	include_directories("${CMAKE_CURRENT_SOURCE_DIR}")
endif()


if (BUILD_STATIC)
	add_library(cryptopp-static STATIC ${cryptopp_SOURCES})
endif()

# Set filenames for targets to be "cryptopp"
if(NOT MSVC)
	set(COMPAT_VERSION ${cryptopp_VERSION_MAJOR}.${cryptopp_VERSION_MINOR})

	if (BUILD_STATIC)
		set_target_properties(cryptopp-static
				PROPERTIES
				OUTPUT_NAME cryptopp)
	endif()
	if (BUILD_SHARED)
		set_target_properties(cryptopp-shared
				PROPERTIES
				SOVERSION ${COMPAT_VERSION}
				OUTPUT_NAME cryptopp)
	endif()
endif()

# Targets, compatible with Crypto++ GNUMakefile
if (BUILD_STATIC)
	add_custom_target(static)
	add_dependencies(static cryptopp-static)
endif()
if (BUILD_SHARED)
	add_custom_target(dynamic)
	add_dependencies(dynamic cryptopp-shared)
endif()

#============================================================================
# Third-party libraries
#============================================================================

if(WIN32)
	if (BUILD_STATIC)
		target_link_libraries(cryptopp-static ws2_32)
	endif()
	if (BUILD_SHARED)
		target_link_libraries(cryptopp-shared ws2_32)
	endif()
endif()

# This may need to be expanded to "Solaris"
if ("${UNAME_SYSTEM}" STREQUAL "SunOS")
	if (BUILD_STATIC)
		target_link_libraries(cryptopp-static nsl socket)
	endif()
	if (BUILD_SHARED)
		target_link_libraries(cryptopp-shared nsl socket)
	endif()
endif()

find_package(Threads)
if (BUILD_STATIC)
	target_link_libraries(cryptopp-static ${CMAKE_THREAD_LIBS_INIT})
endif()
if (BUILD_SHARED)
	target_link_libraries(cryptopp-shared ${CMAKE_THREAD_LIBS_INIT})
endif()
