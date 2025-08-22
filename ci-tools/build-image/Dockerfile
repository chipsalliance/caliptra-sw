# Licensed under the Apache-2.0 license

# This docker image shares a rootfs with the Caliptra FPGAs.
# This image is used in various GitHub actions to cross-compile binaries targeting the FPGAs.

# Move dev images to debian.
FROM debian:bookworm-slim
RUN apt update && apt install gcc git curl make gcc-aarch64-linux-gnu libssl-dev pkg-config  -y
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --profile=minimal -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup install nightly-2025-02-15 --profile=minimal --no-self-update \
  && rustup +nightly-2025-02-15 target add riscv32imc-unknown-none-elf \
  && rustup +nightly-2025-02-15 target add aarch64-unknown-linux-gnu
RUN rustup install 1.85 --profile=minimal --no-self-update \
  && rustup +1.85 target add riscv32imc-unknown-none-elf \
  && rustup +1.85 target add aarch64-unknown-linux-gnu
RUN cargo +nightly-2025-02-15 install cargo-nextest
RUN cargo +1.85 install sccache --version 0.10.0 --no-default-features --features=gha --locked
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="aarch64-linux-gnu-gcc"
ENV OPENSSL_SHA256="c53a47e5e441c930c3928cf7bf6fb00e5d129b630e0aa873b08258656e7345ec"
RUN curl -L "https://github.com/openssl/openssl/releases/download/openssl-3.5.2/openssl-3.5.2.tar.gz" -o openssl.tar.gz \
  && tar -xvf openssl.tar.gz \
  # For some reason make clean is not fully cleaning up the previous build
  # so create a duplicate folder
  && cp -r openssl-3.5.2 openssl-3.5.2-arm \
  && cd openssl-3.5.2 && ./config no-shared no-apps no-quic && make -j8 build_sw && cd .. \
  && cd openssl-3.5.2-arm && ./config linux-aarch64 no-shared no-apps no-quic --cross-compile-prefix=aarch64-linux-gnu- \
  && make -j8 build_sw && cd .. \
  && mkdir -p /tmp/openssl/native/lib && mv openssl-3.5.2/include /tmp/openssl/native/include && mv openssl-3.5.2/libcrypto.a /tmp/openssl/native/lib && mv openssl-3.5.2/libssl.a /tmp/openssl/native/lib \
  && mkdir -p /tmp/openssl/arm/lib && mv openssl-3.5.2-arm/include /tmp/openssl/arm/include && mv openssl-3.5.2-arm/libcrypto.a /tmp/openssl/arm/lib && mv openssl-3.5.2-arm/libssl.a /tmp/openssl/arm/lib \
  && rm -r openssl-3.5.2 && rm -r openssl-3.5.2-arm && rm openssl.tar.gz

