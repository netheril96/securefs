set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)

set(VCPKG_CMAKE_SYSTEM_NAME Linux)

set(VCPKG_C_FLAGS_DEBUG "-fsanitize=address")
set(VCPKG_CXX_FLAGS_DEBUG "-fsanitize=address")
set(VCPKG_LINKER_FLAGS_DEBUG "-fsanitize=address")
