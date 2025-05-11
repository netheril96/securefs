vcpkg_from_github(
    OUT_SOURCE_PATH
    SOURCE_PATH
    REPO
    google/fruit
    REF
    "19f5c05466565ef507a196b33de08f1c96dd0e58"
    SHA512
    835097d209a3e7c73b14b751c49d01f6ccfaaf5189125e2646dbbeeb90b99c52addc06a93acaf2e6f5c96ce087bf2b78dbb968e5b7671e726afa2d34c7c1196a
    HEAD_REF
    master)

# TODO: Make boost an optional dependency?
vcpkg_cmake_configure(
    SOURCE_PATH ${SOURCE_PATH} OPTIONS -DFRUIT_USES_BOOST=False
    -DFRUIT_TESTS_USE_PRECOMPILED_HEADERS=OFF)

vcpkg_cmake_install()
file(REMOVE_RECURSE ${CURRENT_PACKAGES_DIR}/debug/include)

# Handle copyright
file(
    INSTALL ${SOURCE_PATH}/COPYING
    DESTINATION ${CURRENT_PACKAGES_DIR}/share/${PORT}
    RENAME copyright)
