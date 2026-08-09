#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WATT_ROOT="$(cd "$ROOT/.." && pwd)"
REPO_DIR="$(basename "$ROOT")"
COMPOSE_PROJECT="wattswarm-message-gateway-contract"
TLS_DIR="$ROOT/.tmp/rabbitmq-tls"
mkdir -p "$TLS_DIR"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj "/CN=Wattswarm Contract CA" \
  -keyout "$TLS_DIR/ca.key" -out "$TLS_DIR/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" \
  -keyout "$TLS_DIR/server.key" -out "$TLS_DIR/server.csr" >/dev/null 2>&1
printf 'subjectAltName=DNS:localhost,DNS:rabbitmq,DNS:rabbitmq-contract,IP:127.0.0.1\n' > "$TLS_DIR/server.ext"
openssl x509 -req -days 1 -in "$TLS_DIR/server.csr" \
  -CA "$TLS_DIR/ca.crt" -CAkey "$TLS_DIR/ca.key" -CAcreateserial \
  -extfile "$TLS_DIR/server.ext" -out "$TLS_DIR/server.crt" >/dev/null 2>&1
chmod 644 "$TLS_DIR"/*

cat > "$ROOT/.tmp/rabbitmq.conf" <<'EOF'
listeners.tcp = none
listeners.ssl.1 = 0.0.0.0:5671
ssl_options.cacertfile = /certs/ca.crt
ssl_options.certfile = /certs/server.crt
ssl_options.keyfile = /certs/server.key
ssl_options.verify = verify_none
ssl_options.fail_if_no_peer_cert = false
management.tcp.port = 15672
EOF

cleanup() {
  docker compose --project-name "$COMPOSE_PROJECT" \
    -f "$ROOT/docker-compose.message-gateway-contract.yml" down -v >/dev/null
}
trap cleanup EXIT
docker compose --project-name "$COMPOSE_PROJECT" \
  -f "$ROOT/docker-compose.message-gateway-contract.yml" up -d --wait

host_ready=false
for attempt in $(seq 1 5); do
  if python3 -c 'import socket, ssl, sys; c=ssl.create_default_context(cafile=sys.argv[1]); s=c.wrap_socket(socket.create_connection(("localhost", 35671), timeout=2), server_hostname="localhost"); s.close()' \
    "$TLS_DIR/ca.crt" >/dev/null 2>&1; then
    host_ready=true
    break
  fi
  sleep 1
done

if [ "$host_ready" = true ]; then
  export WATTSWARM_RABBITMQ_TEST_ENDPOINT="amqps://localhost:35671/%2fwattswarm?cacertfile=$TLS_DIR/ca.crt"
  export WATTSWARM_RABBITMQ_TEST_USERNAME=wattswarm
  export WATTSWARM_RABBITMQ_TEST_PASSWORD=contract-password
  export WATTSWARM_MESSAGE_GATEWAY_TEST_DATABASE_URL="postgres://wattswarm:contract-password@localhost:55439/message_gateway_contract"
  cargo test -p wattetheria-message-gateway --tests -- --ignored --nocapture --test-threads=1
else
  echo "Host Docker port forwarding is unavailable; running contracts inside the Compose network." >&2
  docker run --rm \
    --network "${COMPOSE_PROJECT}_default" \
    -v "$WATT_ROOT:/workspace" \
    -v wattswarm-message-gateway-target:/target \
    -w "/workspace/$REPO_DIR" \
    -e CARGO_TARGET_DIR=/target \
    -e WATTSWARM_RABBITMQ_TEST_ENDPOINT="amqps://rabbitmq:5671/%2fwattswarm?cacertfile=/workspace/$REPO_DIR/.tmp/rabbitmq-tls/ca.crt" \
    -e WATTSWARM_RABBITMQ_TEST_USERNAME=wattswarm \
    -e WATTSWARM_RABBITMQ_TEST_PASSWORD=contract-password \
    -e WATTSWARM_MESSAGE_GATEWAY_TEST_DATABASE_URL="postgres://wattswarm:contract-password@postgres-contract:5432/message_gateway_contract" \
    rust:1.90-bookworm \
    cargo test -p wattetheria-message-gateway --tests -- --ignored --nocapture --test-threads=1
fi
