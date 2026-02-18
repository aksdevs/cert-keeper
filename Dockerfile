# syntax=docker/dockerfile:1
FROM rust:1.83-slim-bookworm AS builder

RUN apt-get update && apt-get install -y musl-tools && rm -rf /var/lib/apt/lists/*

ARG TARGETARCH

RUN case "${TARGETARCH}" in \
      amd64) echo "x86_64-unknown-linux-musl" > /tmp/rust-target ;; \
      arm64) echo "aarch64-unknown-linux-musl" > /tmp/rust-target ;; \
      *) echo "unsupported arch: ${TARGETARCH}" && exit 1 ;; \
    esac && \
    rustup target add "$(cat /tmp/rust-target)"

WORKDIR /build

# Cache dependencies by building a dummy project first.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --target "$(cat /tmp/rust-target)" || true
RUN rm -rf src

# Build the real binary.
COPY src/ src/
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    RUST_TARGET="$(cat /tmp/rust-target)" && \
    cargo build --release --target "${RUST_TARGET}" && \
    cp "/build/target/${RUST_TARGET}/release/cert-keeper" /cert-keeper

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /cert-keeper /cert-keeper

EXPOSE 8443

ENTRYPOINT ["/cert-keeper"]
