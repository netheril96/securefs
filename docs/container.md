# Containerized Builds and Deployments

This document describes how to build, test, extract, and run `securefs` using containers (Podman or Docker).

---

## Architecture Overview

The container configuration uses a multi-stage `Containerfile` (with symlinked `Dockerfile`) based on Alpine Linux 3.20. It builds a fully static `securefs` binary linked against musl libc, mimalloc, and static C/C++ runtimes.

The build comprises three stages:

1. **`builder` (`alpine:3.20`)**:
   - Contains the C++ toolchain (GCC, CMake, Ninja, autotools, Python 3).
   - Clones and bootstraps Microsoft `vcpkg` pinned to the repository baseline commit (`74e6536215718009aae747d86d84b78376bf9e09`).
   - Configures static compilation flags (`CFLAGS="-static"`, `CXXFLAGS="-static"`).
   - Pre-installs manifest dependencies (cryptopp, protobuf, doctest, abseil, sqlite3, argon2, mimalloc) into `/build/vcpkg_installed` to maximize layer caching.
   - Compiles `securefs` with Link Time Optimization (`--lto`) and runs unit tests.
   - Installs the static executable to `/usr/local/bin/securefs`.

2. **`runtime` (`alpine:3.20`)**:
   - A minimal image containing only the `fuse` userspace tools and the statically compiled `/usr/local/bin/securefs` binary.
   - Configured with `ENTRYPOINT ["/usr/local/bin/securefs"]`.

3. **`binary` (`scratch`)**:
   - An empty scratch image containing only the static `/securefs` binary.
   - Used for zero-overhead local export of the standalone binary via container build `--output`.

---

## Quick Start with `scripts/podman-build.sh`

The helper script [`scripts/podman-build.sh`](../scripts/podman-build.sh) automatically discovers either `podman` (preferred) or `docker` and manages cache volumes for you.

### Subcommands

- **Build runtime & builder images:**
  ```bash
  ./scripts/podman-build.sh build
  ```
  Produces `securefs:builder` and `securefs:latest`.

- **Extract static binary to host:**
  ```bash
  ./scripts/podman-build.sh extract [DEST]
  ```
  Exports the static executable to `${DEST:-./build}/securefs`. If no destination is specified, it extracts to `./build/securefs`.

- **Run unit tests:**
  ```bash
  ./scripts/podman-build.sh test
  ```
  Runs the doctest unit test suite inside `securefs:builder` using `ctest -V -C Release`.

- **Run integration tests (requires FUSE):**
  ```bash
  ./scripts/podman-build.sh test-integration
  ```
  Executes Python integration tests (`test/simple_test.py`) with `--device /dev/fuse --cap-add SYS_ADMIN`.

- **Open development shell:**
  ```bash
  ./scripts/podman-build.sh shell
  # or pass custom commands:
  ./scripts/podman-build.sh dev ninja -C /build
  ```
  Spawns an interactive bash shell in `securefs:builder` with the repository mounted at `/src` and vcpkg cache volume mounted.

---

## Direct Podman and Docker Commands

If you prefer using container commands directly:

### 1. Build the Runtime Image

With Podman (using the cache volume):
```bash
podman volume create securefs_vcpkg_archive_cache
podman build --target runtime -t securefs:latest -v securefs_vcpkg_archive_cache:/root/.cache/vcpkg:Z .
```

With Docker:
```bash
docker build --target runtime -t securefs:latest .
```

### 2. Extract Static Binary Directly

Using BuildKit / Podman direct output export:
```bash
podman build --target binary --output type=local,dest=./build .
```

Using container copy fallback:
```bash
podman build --target binary -t securefs:binary .
CONTAINER_ID=$(podman create securefs:binary)
podman cp "${CONTAINER_ID}:/securefs" ./build/securefs
podman rm "$CONTAINER_ID"
chmod +x ./build/securefs
```

### 3. Run Unit Tests

```bash
podman run --rm -v securefs_vcpkg_archive_cache:/root/.cache/vcpkg:Z securefs:builder ctest -V -C Release
```

---

## Named Volume Caching (`securefs_vcpkg_archive_cache`)

`vcpkg` caches built package archives inside `VCPKG_DEFAULT_BINARY_CACHE` (`/root/.cache/vcpkg`). By persisting this directory across container builds in a named volume (`securefs_vcpkg_archive_cache`), recompilation of third-party C++ libraries (cryptopp, protobuf, abseil, etc.) is skipped when building updated source code or switching branches.

### Managing the Cache

- **Inspect volume:**
  ```bash
  podman volume inspect securefs_vcpkg_archive_cache
  ```

- **Clear / Reset cache:**
  ```bash
  podman volume rm -f securefs_vcpkg_archive_cache
  ```

- **Use a custom volume name:**
  Set the `SECUREFS_VCPKG_CACHE_VOLUME` environment variable:
  ```bash
  SECUREFS_VCPKG_CACHE_VOLUME=my_custom_cache ./scripts/podman-build.sh build
  ```

---

## Running FUSE Mounts Inside Containers

FUSE filesystems require access to the host's `/dev/fuse` character device and elevated capabilities.

### Requirements

1. **Host kernel module**: Ensure the `fuse` kernel module is loaded:
   ```bash
   ls -l /dev/fuse
   # If missing:
   sudo modprobe fuse
   ```

2. **Container privileges**: Pass `--device /dev/fuse` and `--cap-add SYS_ADMIN`:
   ```bash
   podman run --rm -it \
       --device /dev/fuse \
       --cap-add SYS_ADMIN \
       -v /path/to/cipher:/data/cipher:Z \
       -v /path/to/mount:/data/mount:Z \
       securefs:latest mount /data/cipher /data/mount
   ```

### Rootless Containers vs. Host Mount Access

Mounting a filesystem inside a container and accessing it involves important Linux kernel namespace considerations:

1. **Mounting for Host Access (Recommended: Static Binary)**:
   - Linux kernel security restrictions **prevent unprivileged (rootless) user namespaces from propagating mounts back to the host mount namespace**.
   - Rootless users also cannot run `mount --make-shared` on the host as it requires host `CAP_SYS_ADMIN` (root/sudo).
   - **Recommended Approach**: If you want to mount a securefs filesystem to access plaintext files directly on the host, extract and run the static standalone binary:
     ```bash
     ./scripts/podman-build.sh extract ./build
     ./build/securefs mount /path/to/cipher /path/to/mount
     ```
     Because the extracted binary is statically linked with musl, it runs natively on any Linux host without installing compilers, vcpkg, or development libraries.

2. **Mounting Inside Rootless Containers (Container-Internal Use)**:
   - Rootless Podman can mount securefs inside a container for containerized applications (e.g., a backup job, database, or processing service running inside Podman that reads/writes encrypted data):
     ```bash
     podman run --rm -it \
         --device /dev/fuse \
         --cap-add SYS_ADMIN \
         -v /path/to/cipher:/data/cipher:Z \
         securefs:latest mount /data/cipher /data/mount
     ```
   - In this mode, `/data/mount` is accessible inside that container (and to other containers sharing volumes), but is not propagated back to the host filesystem.

3. **Exposing Container Mounts to the Host (Requires Root / Sudo)**:
   - If you specifically need a container to perform the mount and propagate it back to the host, this requires running with root privileges (`sudo podman` or `sudo docker`):
     ```bash
     # 1. On the host, mark the mountpoint directory as shared (requires root):
     sudo mount --bind /host/mount /host/mount
     sudo mount --make-shared /host/mount

     # 2. Run container with shared volume propagation as root:
     sudo podman run -d \
         --device /dev/fuse \
         --cap-add SYS_ADMIN \
         -v /host/cipher:/container/cipher:Z \
         -v /host/mount:/container/mount:rshared \
         securefs:latest mount /container/cipher /container/mount
     ```
