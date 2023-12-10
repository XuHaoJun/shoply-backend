###
# Base
# for all external lib or tool prepare
###
FROM rust:1.74.1-alpine3.18 AS base
RUN apk add --no-cache musl-dev libressl-dev protoc
WORKDIR /app

###
# chef
# compile chef and install
###
FROM base AS chef
# We only pay the installation cost once,
# it will be cached from the second build onwards
RUN cargo install cargo-chef

###
# planner
# for generate recipe.json
###
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

###
# dependencies
# cook by recipe.json
###
FROM chef AS dependencies
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json

###
# builder
# build app
###
FROM dependencies AS builder
# Build application
COPY . .
RUN cargo install --path .

###
# runtime
# we do not need the Rust toolchain to run the binary!
# not use alpine:3.18.4 because less security problem (scan vulnerability by grype)
###
FROM gcr.io/distroless/cc-debian12 AS runtime
COPY --from=builder /usr/local/cargo/bin/shoply-backend /usr/local/bin/

ENV TZ Asia/Taipei

WORKDIR /app
COPY .env .

EXPOSE 5000
CMD ["shoply-backend"]
