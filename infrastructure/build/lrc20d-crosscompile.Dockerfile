FROM --platform=$BUILDPLATFORM rust:1.85-slim-bookworm AS builder

ARG TARGETOS TARGETARCH
RUN echo "$TARGETARCH" | sed 's,arm,aarch,;s,amd,x86_,' > /tmp/arch

# Install cross compliation toolchain
RUN apt-get update && apt-get install -y \
    "gcc-$(tr _ - < /tmp/arch)-linux-gnu" \
    "g++-$(tr _ - < /tmp/arch)-linux-gnu" \
    pkg-config \
    libssl-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add "$(cat /tmp/arch)-unknown-${TARGETOS}-gnu"

WORKDIR /opt

COPY Cargo.lock .
COPY Cargo.toml .
COPY crates crates/
COPY apps apps/

RUN sed -i '/"benches"/,/"tests"/d' Cargo.toml

RUN cargo build --target "$(cat /tmp/arch)-unknown-${TARGETOS}-gnu" --config target.$(cat /tmp/arch)-unknown-${TARGETOS}-gnu.linker=\"$(cat /tmp/arch)-${TARGETOS}-gnu-gcc\" -p lrc20d
RUN cargo build --target "$(cat /tmp/arch)-unknown-${TARGETOS}-gnu" --config target.$(cat /tmp/arch)-unknown-${TARGETOS}-gnu.linker=\"$(cat /tmp/arch)-${TARGETOS}-gnu-gcc\" -p migration

FROM debian:bookworm-slim

# FIXME: Done only for backward compatibility. Remove it after migration to the new version of chart.
ENTRYPOINT ["yuvd"]

# FIXME: Done only for backward compatibility. Remove it after migration to the new version of chart.
COPY --from=builder /opt/target/*/debug/lrc20d /usr/local/bin/yuvd
COPY --from=builder /opt/crates/storage/src/migration /migration
COPY --from=builder /opt/target/*/debug/migration /usr/local/bin/migration

RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    && apt-get -y upgrade \
    && apt-get clean && rm -rf /var/lib/apt/lists/*