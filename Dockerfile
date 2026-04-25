FROM rust:1.93-bookworm AS chef
WORKDIR /app
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true

RUN cargo install cargo-chef --locked

FROM chef AS planner

COPY Cargo.toml Cargo.lock ./

# Replace local path dependencies with repository sources so Docker builds do
# not depend on sibling directories from the host machine.
RUN sed -i \
    -e 's|wattetheria-gateway-contract = { path = "../wattetheria/crates/gateway-contract" }|wattetheria-gateway-contract = { git = "https://github.com/wattetheria/wattetheria.git", package = "wattetheria-gateway-contract" }|' \
    -e 's|watt-did = { path = "../watt-did" }|watt-did = { git = "https://github.com/wattetheria/watt-did.git" }|' \
    -e 's|wattswarm-artifact-store = { path = "../wattswarm/crates/artifact-store" }|wattswarm-artifact-store = { git = "https://github.com/wattetheria/wattswarm.git", package = "wattswarm-artifact-store" }|' \
    -e 's|wattswarm-network-substrate = { path = "../wattswarm/crates/network-substrate" }|wattswarm-network-substrate = { git = "https://github.com/wattetheria/wattswarm.git", package = "wattswarm-network-substrate" }|' \
    -e 's|wattswarm-network-transport-core = { path = "../wattswarm/crates/network-transport-core" }|wattswarm-network-transport-core = { git = "https://github.com/wattetheria/wattswarm.git", package = "wattswarm-network-transport-core" }|' \
    -e 's|wattswarm-network-transport-iroh = { path = "../wattswarm/crates/network-transport-iroh" }|wattswarm-network-transport-iroh = { git = "https://github.com/wattetheria/wattswarm.git", package = "wattswarm-network-transport-iroh" }|' \
    Cargo.toml

RUN mkdir -p src \
    && printf "pub fn _planner_stub() {}\n" > src/lib.rs \
    && printf "fn main() {}\n" > src/main.rs

RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS cacher

COPY --from=planner /app/recipe.json /app/recipe.json
RUN --mount=type=secret,id=github_token \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    if [ -f /run/secrets/github_token ]; then \
      git config --global url."https://$(cat /run/secrets/github_token)@github.com/".insteadOf "https://github.com/"; \
    fi \
    && cargo chef cook --release --recipe-path recipe.json

FROM chef AS builder

COPY . .
COPY --from=cacher /app/target /app/target

# COPY . . restores local path dependencies, so apply the Docker-only git
# dependency rewrite again before the final build.
RUN sed -i \
    -e 's|wattetheria-gateway-contract = { path = "../wattetheria/crates/gateway-contract" }|wattetheria-gateway-contract = { git = "https://github.com/wattetheria/wattetheria.git", package = "wattetheria-gateway-contract" }|' \
    -e 's|watt-did = { path = "../watt-did" }|watt-did = { git = "https://github.com/wattetheria/watt-did.git" }|' \
    -e 's|wattswarm-artifact-store = { path = "../wattswarm/crates/artifact-store" }|wattswarm-artifact-store = { git = "https://github.com/wattetheria/wattswarm.git", package = "wattswarm-artifact-store" }|' \
    -e 's|wattswarm-network-substrate = { path = "../wattswarm/crates/network-substrate" }|wattswarm-network-substrate = { git = "https://github.com/wattetheria/wattswarm.git", package = "wattswarm-network-substrate" }|' \
    -e 's|wattswarm-network-transport-core = { path = "../wattswarm/crates/network-transport-core" }|wattswarm-network-transport-core = { git = "https://github.com/wattetheria/wattswarm.git", package = "wattswarm-network-transport-core" }|' \
    -e 's|wattswarm-network-transport-iroh = { path = "../wattswarm/crates/network-transport-iroh" }|wattswarm-network-transport-iroh = { git = "https://github.com/wattetheria/wattswarm.git", package = "wattswarm-network-transport-iroh" }|' \
    Cargo.toml

RUN --mount=type=secret,id=github_token \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    if [ -f /run/secrets/github_token ]; then \
      git config --global url."https://$(cat /run/secrets/github_token)@github.com/".insteadOf "https://github.com/"; \
    fi \
    && cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/wattetheria-gateway /usr/local/bin/wattetheria-gateway

EXPOSE 8080
CMD ["wattetheria-gateway"]
