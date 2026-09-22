#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Detect container engine: honor CONTAINER_TOOL if set, otherwise prefer podman then docker
detect_container_tool() {
    if [ -n "${CONTAINER_TOOL:-}" ]; then
        CONTAINER_TOOL_NAME="$(basename "$CONTAINER_TOOL")"
        return
    fi
    if command -v podman >/dev/null 2>&1; then
        CONTAINER_TOOL="podman"
        CONTAINER_TOOL_NAME="podman"
    elif command -v docker >/dev/null 2>&1; then
        CONTAINER_TOOL="docker"
        CONTAINER_TOOL_NAME="docker"
    else
        echo "Error: Neither podman nor docker was found in PATH." >&2
        echo "Please install Podman or Docker, or set CONTAINER_TOOL." >&2
        exit 1
    fi
}

detect_container_tool

# Define cache volume
CACHE_VOLUME="${SECUREFS_VCPKG_CACHE_VOLUME:-securefs_vcpkg_archive_cache}"

ensure_cache_volume() {
    if ! "$CONTAINER_TOOL" volume inspect "$CACHE_VOLUME" >/dev/null 2>&1; then
        echo "Creating cache volume '$CACHE_VOLUME'..."
        "$CONTAINER_TOOL" volume create "$CACHE_VOLUME" >/dev/null
    fi
}

# Volume mount arguments for build commands.
# Note: 'podman build -v' only accepts absolute host directory paths; named volumes
# are not supported at build time by container engines and are used during 'run'.
BUILD_VOLUME_ARGS=()
case "$CACHE_VOLUME" in
    /*)
        BUILD_VOLUME_ARGS=(-v "${CACHE_VOLUME}:/root/.cache/vcpkg:Z")
        ;;
esac

build_builder() {
    echo "==> Building target 'builder' (securefs:builder)..."
    "$CONTAINER_TOOL" build \
        --target builder \
        -t securefs:builder \
        "${BUILD_VOLUME_ARGS[@]}" \
        "$REPO_ROOT"
}

build_runtime() {
    echo "==> Building target 'runtime' (securefs:latest)..."
    "$CONTAINER_TOOL" build \
        --target runtime \
        -t securefs:latest \
        "${BUILD_VOLUME_ARGS[@]}" \
        "$REPO_ROOT"
}

ensure_builder_image() {
    if ! "$CONTAINER_TOOL" image inspect securefs:builder >/dev/null 2>&1; then
        echo "Image 'securefs:builder' not found locally. Building it first..."
        build_builder
    fi
}

show_help() {
    cat <<EOF
Usage: $(basename "$0") <subcommand> [args...]

Convenience script for containerized building, testing, and extraction of securefs.
Detected container engine: $CONTAINER_TOOL_NAME

Subcommands:
  build                 Build securefs:builder and securefs:latest (runtime image)
  extract [DEST]        Build static binary and export to DEST (default: ./build/securefs)
  test [ARGS...]        Run unit tests in securefs:builder using ctest (e.g. ctest -V -C Release)
  test-integration [ARGS...]
                        Run integration tests with /dev/fuse and SYS_ADMIN capability
  shell, dev [CMD...]   Open interactive bash shell (or execute CMD) in securefs:builder
                        with repository mounted at /src and cache volume mounted
  help, --help, -h      Show this help message

Environment variables:
  CONTAINER_TOOL        Container runtime to use (podman or docker)
  SECUREFS_VCPKG_CACHE_VOLUME
                        Named volume for caching vcpkg packages (default: securefs_vcpkg_archive_cache)
EOF
}

COMMAND="${1:-help}"
shift || true

case "$COMMAND" in
    build)
        ensure_cache_volume
        build_builder
        build_runtime
        echo "==> Successfully built securefs:builder and securefs:latest"
        ;;

    extract)
        DEST_DIR="${1:-${REPO_ROOT}/build}"
        case "$DEST_DIR" in
            /*) ;;
            *) DEST_DIR="$(pwd)/${DEST_DIR}" ;;
        esac
        mkdir -p "$DEST_DIR"
        ensure_cache_volume

        echo "==> Extracting static securefs binary to '${DEST_DIR}/securefs'..."
        # Try direct export with --output (BuildKit / modern container engines)
        if ! "$CONTAINER_TOOL" build --target binary --output "type=local,dest=${DEST_DIR}" "${BUILD_VOLUME_ARGS[@]}" "$REPO_ROOT" 2>/dev/null; then
            echo "Direct '--output' export not supported or failed. Falling back to container copy..."
            "$CONTAINER_TOOL" build --target binary -t securefs:binary "${BUILD_VOLUME_ARGS[@]}" "$REPO_ROOT"
            CID="$("$CONTAINER_TOOL" create securefs:binary)"
            "$CONTAINER_TOOL" cp "${CID}:/securefs" "${DEST_DIR}/securefs"
            "$CONTAINER_TOOL" rm -f "$CID" >/dev/null
        fi

        if [ -f "${DEST_DIR}/securefs" ]; then
            chmod +x "${DEST_DIR}/securefs"
            echo "==> Extracted static binary: ${DEST_DIR}/securefs"
        else
            echo "Error: Failed to find extracted binary at ${DEST_DIR}/securefs" >&2
            exit 1
        fi
        ;;

    test)
        ensure_cache_volume
        ensure_builder_image
        echo "==> Running unit tests in securefs:builder..."
        "$CONTAINER_TOOL" run --rm \
            -v "${CACHE_VOLUME}:/root/.cache/vcpkg:Z" \
            securefs:builder \
            ctest -V -C Release "$@"
        ;;

    test-integration)
        ensure_cache_volume
        ensure_builder_image
        if [ ! -e /dev/fuse ]; then
            echo "Warning: /dev/fuse device was not detected on the host." >&2
        fi
        echo "==> Running integration tests in securefs:builder with FUSE enabled..."
        "$CONTAINER_TOOL" run --rm \
            --device /dev/fuse \
            --cap-add SYS_ADMIN \
            -v "${CACHE_VOLUME}:/root/.cache/vcpkg:Z" \
            securefs:builder \
            env SECUREFS_BINARY=/usr/local/bin/securefs python3 /src/test/simple_test.py "$@"
        ;;

    shell|dev)
        ensure_cache_volume
        ensure_builder_image
        echo "==> Launching container environment (repo mounted at /src)..."
        if [ $# -gt 0 ]; then
            exec "$CONTAINER_TOOL" run -it --rm \
                -v "${CACHE_VOLUME}:/root/.cache/vcpkg:Z" \
                -v "${REPO_ROOT}:/src:Z" \
                -w /src \
                securefs:builder "$@"
        else
            exec "$CONTAINER_TOOL" run -it --rm \
                -v "${CACHE_VOLUME}:/root/.cache/vcpkg:Z" \
                -v "${REPO_ROOT}:/src:Z" \
                -w /src \
                securefs:builder bash
        fi
        ;;

    help|--help|-h)
        show_help
        ;;

    *)
        echo "Error: Unknown subcommand '$COMMAND'" >&2
        show_help >&2
        exit 1
        ;;
esac
