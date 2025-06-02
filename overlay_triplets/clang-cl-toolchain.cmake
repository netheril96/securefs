# Chainload the default vcpkg toolchain first to inherit common settings
include("${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")

# Explicitly set the C and C++ compilers to clang-cl
# Find clang-cl.exe dynamically. This searches standard system paths and locations.
# Ensure clang-cl.exe is in your system's PATH or installed in a standard location.
find_program(CLANG_CL_EXECUTABLE
    NAMES clang-cl
    REQUIRED # Make the build fail if clang-cl is not found
)

# Set the C and C++ compilers to the found clang-cl executable
set(CMAKE_C_COMPILER "${CLANG_CL_EXECUTABLE}" CACHE FILEPATH "C compiler")
set(CMAKE_CXX_COMPILER "${CLANG_CL_EXECUTABLE}" CACHE FILEPATH "C++ compiler")

# Important: Set the Visual Studio platform toolset to LLVM (clang-cl)
# This is often needed when integrating with MSBuild-based projects or when vcpkg tries to deduce the toolset.
set(CMAKE_GENERATOR_TOOLSET "LLVM (clang-cl)" CACHE STRING "Platform Toolset")
