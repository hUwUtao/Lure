FROM rust:1-slim-trixie AS builder
WORKDIR /app

ARG RUSTFLAGS
ENV RUSTFLAGS=${RUSTFLAGS}

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl libssl-dev pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY . .
RUN cargo install --path .

# Stage 2: Create the final image
FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /usr/local/cargo/bin/lure /app/lure

# Command to run the application
CMD ["/app/lure"]
