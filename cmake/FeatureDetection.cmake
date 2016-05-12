include(CheckCXXSourceCompiles)
if (UNIX)
    set (CMAKE_REQUIRED_FLAGS "-std=c++11")
endif()

CHECK_CXX_SOURCE_COMPILES("int main() { thread_local int a = 0; return a; }" HAS_THREAD_LOCAL)
if (${HAS_THREAD_LOCAL})
    add_definitions(-DHAS_THREAD_LOCAL)
endif()

CHECK_CXX_SOURCE_COMPILES(
"#include <sys/xattr.h>
int main() {return 0;}" 
HAS_XATTR)

if (${HAS_XATTR})
    add_definitions(-DHAS_XATTR)
endif()

