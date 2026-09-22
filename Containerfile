# Stage 1: builder
FROM alpine:3.20 AS builder

RUN apk add --no-cache \
    curl \
    git \
    cmake \
    ninja-build \
    fuse-dev \
    fuse-static \
    python3 \
    py3-pip \
    build-base \
    zip \
    linux-headers \
    autoconf \
    automake \
    autoconf-archive \
    sudo \
    pkgconf \
    bash

# musl / mimalloc compatibility workaround
RUN echo | tee /usr/include/linux/prctl.h

# Ensure ninja is available in PATH
ENV PATH="/usr/lib/ninja-build/bin:$PATH"
ENV VCPKG_FORCE_SYSTEM_BINARIES=1
ENV VCPKG_DEFAULT_BINARY_CACHE=/root/.cache/vcpkg

RUN ln -sf /usr/lib/ninja-build/bin/ninja /usr/bin/ninja && \
    mkdir -p /root/.cache/vcpkg

# Install Python xattr for integration test support
RUN pip install --break-system-packages xattr

# Fetch vcpkg at pinned baseline commit and bootstrap
RUN git clone https://github.com/microsoft/vcpkg.git /opt/vcpkg && \
    cd /opt/vcpkg && \
    git checkout 74e6536215718009aae747d86d84b78376bf9e09 && \
    ./bootstrap-vcpkg.sh -disableMetrics

# Pre-cache dependencies using vcpkg manifest
WORKDIR /src
COPY vcpkg.json /src/
COPY overlay_triplets /src/overlay_triplets
RUN /opt/vcpkg/vcpkg install \
    --x-manifest-root=/src \
    --x-install-root=/build/vcpkg_installed \
    --overlay-triplets=/src/overlay_triplets \
    --x-feature=mimalloc

# Copy source tree and compile securefs
COPY . /src
WORKDIR /build
RUN python3 /src/build.py \
    --lto \
    --enable_unit_test \
    --vcpkg_root=/opt/vcpkg \
    --build_root=/build \
    --cmake_defines VCPKG_MANIFEST_FEATURES=mimalloc SECUREFS_ENABLE_MIMALLOC=ON CMAKE_INSTALL_PREFIX=/usr/local CMAKE_EXE_LINKER_FLAGS=-static && \
    cmake --install /build

# Stage 2: runtime
FROM alpine:3.20 AS runtime

RUN apk add --no-cache fuse

COPY --from=builder /usr/local/bin/securefs /usr/local/bin/securefs

ENTRYPOINT ["/usr/local/bin/securefs"]

# Stage 3: binary
FROM scratch AS binary

COPY --from=builder /usr/local/bin/securefs /securefs
