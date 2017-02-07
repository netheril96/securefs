include(CheckCXXSourceCompiles)
include(CheckFunctionExists)
include(CheckIncludeFileCXX)

CHECK_FUNCTION_EXISTS(openat HAS_OPENAT)
CHECK_FUNCTION_EXISTS(unlinkat HAS_UNLINKAT)
CHECK_FUNCTION_EXISTS(mkdirat HAS_MKDIRAT)
CHECK_FUNCTION_EXISTS(renameat HAS_RENAMEAT)
CHECK_FUNCTION_EXISTS(fstatat HAS_FSTATAT)
CHECK_FUNCTION_EXISTS(fchmodat HAS_FCHMODAT)
CHECK_FUNCTION_EXISTS(futimens HAS_FUTIMENS)
CHECK_FUNCTION_EXISTS(readlinkat HAS_READLINKAT)
CHECK_FUNCTION_EXISTS(symlinkat HAS_SYMLINKAT)
CHECK_FUNCTION_EXISTS(linkat HAS_LINKAT)
CHECK_FUNCTION_EXISTS(clock_gettime HAS_CLOCK_GETTIME)

if (HAS_OPENAT AND HAS_UNLINKAT AND HAS_MKDIRAT AND HAS_RENAMEAT AND HAS_FSTATAT AND HAS_FCHMODAT AND HAS_RENAMEAT AND HAS_SYMLINKAT AND HAS_LINKAT)
    add_definitions(-DHAS_AT_FUNCTIONS)
endif ()

if (HAS_FUTIMENS)
    add_definitions(-DHAS_FUTIMENS)
endif ()

if (HAS_CLOCK_GETTIME)
    add_definitions(-DHAS_CLOCK_GETTIME)
endif ()

set(CMAKE_REQUIRED_INCLUDES ${FUSE_INCLUDE_DIR})

CHECK_CXX_SOURCE_COMPILES("
#define _FILE_OFFSET_BITS 64
#define FUSE_USE_VERSION 28
#include <fuse.h>
int main()
{
    struct fuse_conn_info* fsinfo = 0;
    fsinfo->want |= FUSE_CAP_BIG_WRITES;
    fsinfo->max_readahead = static_cast<unsigned>(-1);
    fsinfo->max_write = static_cast<unsigned>(-1);
    return 0;
}
" CAN_SET_FUSE_CONN_INFO)

if (CAN_SET_FUSE_CONN_INFO)
    add_definitions(-DCAN_SET_FUSE_CONN_INFO)
endif ()
