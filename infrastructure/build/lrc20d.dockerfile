FROM rust:1.85-alpine3.20 as builder
# This is important, see https://github.com/rust-lang/docker-rust/issues/85
ENV RUSTFLAGS="-C target-feature=-crt-static"

RUN apk add --no-cache musl-dev openssl-dev build-base

WORKDIR /opt

COPY Cargo.lock .
COPY Cargo.toml .

RUN sed -i '/"benches"/,/"tests"/d' Cargo.toml

COPY crates crates/
COPY apps apps/

# Build main application
RUN cargo build --release -p lrc20d \
	&& mkdir out \
	&& cp target/release/lrc20d out/ \
	&& strip out/lrc20d

# Build migration tool
RUN cargo build --release -p migration \
	&& mkdir -p out/migration \
	&& cp target/release/migration out/migration/ \
	&& strip out/migration/migration

FROM alpine:3.20

RUN apk add --no-cache libgcc openssl postgresql-client

COPY --from=builder /opt/out/lrc20d /bin/lrc20d
COPY --from=builder /opt/out/migration/migration /bin/migration

CMD ["/bin/lrc20d", "run", "--config", "/config.toml"]