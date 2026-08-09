#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT/docker-compose.message-gateway-quorum-contract.yml"
PROJECT="wattswarm-message-gateway-quorum-contract"
QUEUE="wattswarm-quorum-failure-contract"

compose() {
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" "$@"
}

cleanup() {
  compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

cleanup
compose up -d --wait rabbit1 rabbit2 rabbit3

for node in rabbit2 rabbit3; do
  compose exec -T "$node" rabbitmqctl stop_app
  compose exec -T "$node" rabbitmqctl reset
  compose exec -T "$node" rabbitmqctl join_cluster rabbit@rabbit1
  compose exec -T "$node" rabbitmqctl start_app
done

cluster_status="$(compose exec -T rabbit1 rabbitmqctl cluster_status)"
grep -q 'rabbit@rabbit1' <<<"$cluster_status"
grep -q 'rabbit@rabbit2' <<<"$cluster_status"
grep -q 'rabbit@rabbit3' <<<"$cluster_status"

compose exec -T rabbit1 rabbitmqadmin \
  -H localhost -u wattswarm -p contract-password -V /wattswarm \
  declare queue --name "$QUEUE" --type quorum --durable true --non-interactive

quorum_status="$(compose exec -T rabbit1 rabbitmq-queues quorum_status --vhost /wattswarm "$QUEUE")"
grep -q 'rabbit@rabbit1' <<<"$quorum_status"
grep -q 'rabbit@rabbit2' <<<"$quorum_status"
grep -q 'rabbit@rabbit3' <<<"$quorum_status"
grep -q 'rabbit@rabbit1.*leader' <<<"$quorum_status"

compose exec -T rabbit1 rabbitmqadmin \
  -H localhost -u wattswarm -p contract-password -V /wattswarm \
  publish message --exchange '' --routing-key "$QUEUE" \
  --payload 'quorum-survives-leader-stop' --properties '{"delivery_mode":2}' \
  --non-interactive

compose stop rabbit1
sleep 5

delivery="$(compose exec -T rabbit2 rabbitmqadmin \
  -H localhost -u wattswarm -p contract-password -V /wattswarm \
  get messages --queue "$QUEUE" --count 1 --ack-mode ack_requeue_false \
  --non-interactive)"
grep -q 'quorum-survives-leader-stop' <<<"$delivery"

echo "three-node quorum leader-failure contract passed"
