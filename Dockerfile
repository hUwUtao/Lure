FROM rust:1-slim AS builder
WORKDIR /app

RUN apt-get update && apt-get upgrade && apt-get install -y openssl libssl-dev pkg-config

COPY . .
RUN cargo install --path .

# Stage 2: Create the final image
FROM debian:bookworm-slim

WORKDIR /app
COPY --from=builder /usr/local/cargo/bin/lure /app/lure

# Command to run the application
CMD ["/app/lure"]