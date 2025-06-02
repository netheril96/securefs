# Explicitly set the C and C++ compilers to clang-cl
# Find clang-cl.exe dynamically. This searches standard system paths and locations.
# If clang-cl.exe is not found in these common locations, ensure its directory
# is added to your system's PATH environment variable.
find_program(CLANG_CL_EXECUTABLE
    NAMES clang-cl # find_program automatically handles .exe on Windows
    HINTS
        ENV LLVM_DIR         # Standard environment variable for LLVM installation root
        ENV LLVM_ROOT        # Another common environment variable for LLVM root
        ENV LLVM_INSTALL_DIR # Yet another common variable for LLVM root
    PATHS
        # Common paths for clang-cl within Visual Studio 2022 installations
        # (often found on CI systems like GitHub Actions or standard developer setups)
        "C:/Program Files/Microsoft Visual Studio/2022/Enterprise/VC/Tools/Llvm/x64/bin"
        "C:/Program Files/Microsoft Visual Studio/2022/Enterprise/VC/Tools/Llvm/bin"
        "C:/Program Files/Microsoft Visual Studio/2022/Professional/VC/Tools/Llvm/x64/bin"
        "C:/Program Files/Microsoft Visual Studio/2022/Professional/VC/Tools/Llvm/bin"
        "C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/Llvm/x64/bin"
        "C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/Llvm/bin"
        "C:/Program Files/Microsoft Visual Studio/2022/BuildTools/VC/Tools/Llvm/x64/bin"
        "C:/Program Files/Microsoft Visual Studio/2022/BuildTools/VC/Tools/Llvm/bin"

        # Common paths for clang-cl within Visual Studio 2019 installations
        "C:/Program Files (x86)/Microsoft Visual Studio/2019/Enterprise/VC/Tools/Llvm/x64/bin"
        "C:/Program Files (x86)/Microsoft Visual Studio/2019/Enterprise/VC/Tools/Llvm/bin"
        "C:/Program Files (x86)/Microsoft Visual Studio/2019/Professional/VC/Tools/Llvm/x64/bin"
        "C:/Program Files (x86)/Microsoft Visual Studio/2019/Professional/VC/Tools/Llvm/bin"
        "C:/Program Files (x86)/Microsoft Visual Studio/2019/Community/VC/Tools/Llvm/x64/bin"
        "C:/Program Files (x86)/Microsoft Visual Studio/2019/Community/VC/Tools/Llvm/bin"
        "C:/Program Files (x86)/Microsoft Visual Studio/2019/BuildTools/VC/Tools/Llvm/x64/bin"
        "C:/Program Files (x86)/Microsoft Visual Studio/2019/BuildTools/VC/Tools/Llvm/bin"

        # Standard standalone LLVM installations
        "C:/Program Files/LLVM/bin"
        "C:/LLVM/bin"
    PATH_SUFFIXES bin # If HINTS (like ENV LLVM_DIR) point to a root directory, look in its 'bin' subdirectory
    REQUIRED # Make the build fail if clang-cl is not found
)

# For diagnostic purposes, show where clang-cl was found
message(STATUS "Found clang-cl: ${CLANG_CL_EXECUTABLE}")

# Set the C and C++ compilers to the found clang-cl executable
set(CMAKE_C_COMPILER "${CLANG_CL_EXECUTABLE}" CACHE FILEPATH "C compiler")
set(CMAKE_CXX_COMPILER "${CLANG_CL_EXECUTABLE}" CACHE FILEPATH "C++ compiler")

# Important: Set the Visual Studio platform toolset to LLVM (clang-cl)
# This is often needed when integrating with MSBuild-based projects or when vcpkg tries to deduce the toolset.
set(CMAKE_GENERATOR_TOOLSET "LLVM (clang-cl)" CACHE STRING "Platform Toolset")
