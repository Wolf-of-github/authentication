FROM rust:1-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY .sqlx ./.sqlx
COPY migrations ./migrations
COPY src ./src

ENV SQLX_OFFLINE=true
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates sqlite3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/authentication ./authentication
COPY migrations ./migrations

ENV DATABASE_URL=sqlite:///app/data/auth.db?mode=rwc
ENV BIND_ADDR=0.0.0.0:3000

RUN mkdir -p /app/data
VOLUME ["/app/data"]

EXPOSE 3000

CMD ["./authentication"]
