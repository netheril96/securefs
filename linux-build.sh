#!/bin/bash
set -x;
SOURCE_DIR=$(dirname $(realpath "$0"));
cd "${SOURCE_DIR}" && git submodule update --init;
OUR_TMP_DIR=$(mktemp -d -t securefs-build-XXXXX)
cd "${OUR_TMP_DIR}";
cmake "${SOURCE_DIR}";
make -j4;
SECUREFS_BINARY_PATH=$(realpath ./securefs);
echo "Please copy ${SECUREFS_BINARY_PATH} to anywhere in your \$PATH to use it";
