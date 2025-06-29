FROM rust:1-slim AS builder
WORKDIR /app

COPY . .
RUN cargo install --path .

# Stage 2: Create the final image
FROM debian:bookworm-slim

WORKDIR /app
COPY --from=builder /usr/local/cargo/bin/lure /app/lure

# Command to run the application
CMD ["/app/lure"]