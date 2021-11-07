#!/bin/bash
set -x;
SOURCE_DIR=$(dirname $(realpath "$0"));
cd "${SOURCE_DIR}" && git submodule update --init;
export TMPDIR=/dev/shm;
cd $(mktemp -d -t securefs-build-XXXXX);
cmake "${SOURCE_DIR}";
make -j4;
ctest;
SECUREFS_BINARY_PATH=$(realpath ./securefs);
echo "Please copy ${SECUREFS_BINARY_PATH} to anywhere in your \$PATH to use it";
