# wattetheria-gateway

Self-hostable gateway services for Wattetheria and Wattswarm.

This workspace contains two independently deployable services:

- `wattetheria-gateway` is a non-authoritative public query and indexing layer.
  It verifies signed public snapshots and events from `wattetheria` nodes,
  stores client-facing read models in PostgreSQL, and exposes aggregated APIs
  for `wattetheria-client` and other gateways. It also includes a registry
  slice for signed gateway manifests, bootstrap registry lists,
  self-registration, and reviewed public discovery.
- `wattetheria-message-gateway` is the private ClientServer transport boundary
  for Wattswarm nodes. It authenticates node identities, validates signed
  records and scope routes, publishes messages to bounded RabbitMQ mailboxes,
  and manages delivery and commit state.

The services have separate binaries, runtime configuration, and deployment
boundaries. Neither service creates, re-signs, or becomes authoritative over
Wattetheria or Wattswarm business facts.

## Workspace Layout

The repository is a Cargo workspace:

- `crates/gateway`: HTTP API, DB, registry, read models, and runtime entrypoint
- `crates/gateway-p2p`: shared Iroh P2P adapter used by the gateway runtime
- `crates/message-gateway`: independent private Wattswarm ClientServer mailbox
  service with its own binary, PostgreSQL control schema, and RabbitMQ access

## Stack

- Rust
- NATS
- Postgres
- RabbitMQ (ClientServer mode only)

ClickHouse and Typesense are intentionally deferred roadmap items.

## Wattswarm Message Gateway

`wattetheria-message-gateway` is operationally separate from the public
Wattetheria indexer. It authenticates one logical Wattswarm principal per V1
session, validates existing signed records and scope routes, and expands direct
or versioned scope delivery into two quorum mailboxes per Tenant: Interactive
and Bulk. It does not create Authority facts, re-sign records, store permanent
message history, or expose RabbitMQ to nodes.

The service requires PostgreSQL and AMQPS. Its configuration uses
`WATTSWARM_CS_*` and `WATTSWARM_RABBITMQ_*` variables; startup validates queue
cardinality, active-Tenant/fanout capacity, Global delivery-rate admission,
TLS, commit HMAC, membership mutation, object size, and horizontal
owner-forwarding settings. The optional Object Store is read-only and
content-addressed. Objects are isolated below a SHA-256 network directory, so
the same content digest in two networks never resolves through a shared path.

Operators can read a network-scoped snapshot from
`GET /internal/v1/observability?network_id=<network-id>` on the internal mTLS
listener. It reports active sessions, admission and backpressure, mailbox and
dead-letter depth, delivery and confirm latency, membership binding drift,
commit ownership, gaps, and receipt state. The endpoint is not mounted on the
public listener and never returns session proofs, tokens, passwords, commit
tokens, or message payloads.

Trusted network authorities are supplied as a JSON object mapping `network_id`
to genesis node id through `WATTSWARM_CS_TRUSTED_NETWORK_GENESIS_FILE`. Startup
seeds that mapping into the membership projection and rejects any active Tenant
whose current membership cannot be validated. Membership changes must be signed
by the current Finalizer quorum; the trusted genesis identity is only the
bootstrap authority for the first membership event.

The trusted Genesis map is a public-key trust root, not a user token or a
Wattetheria real-world Credential. In the Docker deployment, copy the map to
the host path configured by `WATTSWARM_CS_TRUSTED_NETWORK_GENESIS_HOST_FILE`;
the compose file mounts it as
`/run/wattswarm/trusted-network-genesis.json`.

New ClientServer nodes auto-register with the Genesis Wattswarm node, not with
this Message Gateway. The node sends a request signed by its own Ed25519
identity to `POST /api/network/registration/auto`. The Genesis node verifies
that request and automatically signs a `NetworkMembershipGrant`. The node then
sends that Grant to this Gateway at `POST /v1/admission/grant`. The Gateway
verifies the Genesis signature, checks that the configured Genesis authority is
active, and idempotently projects the node into the active global membership.
Only after this admission does the normal session challenge run.

The Grant has no expiry by default. Set
`WATTSWARM_NETWORK_GRANT_TTL_SECONDS` on the Genesis registration server to a
positive value to issue Grants with an expiry; the Gateway validates that
expiry. `WATTSWARM_CS_AUTO_REGISTER=false` disables the node's automatic
request; the manual application workflow will use the same Grant format later.

Public APIs listen on `WATTSWARM_CS_BIND_ADDR`. Cross-instance delivery commits
use the separate `WATTSWARM_CS_INTERNAL_BIND_ADDR` listener and require all of
`WATTSWARM_CS_INTERNAL_ROUTE`, `WATTSWARM_CS_INTERNAL_MTLS_IDENTITY_FILE`, and
`WATTSWARM_CS_INTERNAL_MTLS_CA_FILE`; partial internal-listener configuration is
rejected. The internal commit endpoint is not mounted on the public router.

Dead letters have their own byte bound,
`WATTSWARM_RABBITMQ_DEAD_LETTER_MAX_LENGTH_BYTES`, and use quorum-queue
at-least-once dead-lettering. Expired challenges, sessions, receipts, owner
leases, and retained acknowledged gaps are cleaned at
`WATTSWARM_CS_METADATA_CLEANUP_INTERVAL`; acknowledged gap retention is set by
`WATTSWARM_CS_ACKNOWLEDGED_GAP_RETENTION`.

Mailbox pages use manual ACK and stable delivery identities. The owning Gateway
instance retains the original AMQP channel; a commit received by another
instance is forwarded over the configured HTTPS/mTLS internal route. If the
owner lease disappears, the channel closes and RabbitMQ requeues the page. TTL,
capacity, and delivery-limit dead letters are compressed into payload-free,
network- and class-bound `MailboxGap` records. Direct and versioned-scope
routing keys also include the network identity, preventing cross-network queue
delivery even when principals or scope addresses match.

Session proofs bind an optional signed Tenant state-instance id. A changed id
durably returns `history_unavailable`, because the Gateway cannot restore
already ACKed local history. Group and Region authors must be active members of
that exact scope; a globally admitted principal receives a narrow exception
only for its signed self-join event. PostgreSQL also holds the shared Global and
non-Global cell token buckets, coalesces identical membership retries, and
records payload-free accepted-session and confirmed-publish audit metadata.

Run the real TLS RabbitMQ/PostgreSQL contracts with:

```bash
./scripts/run-message-gateway-contract.sh
```

The script uses host-published ports when available and automatically runs the
Rust contract runner inside the Compose network when Docker Desktop port
forwarding is unavailable.

Run the independent three-node quorum leader-failure contract with:

```bash
./scripts/run-message-gateway-quorum-failure-contract.sh
```

It forms a three-node RabbitMQ cluster, publishes a persistent quorum message,
stops the queue leader, verifies delivery from a surviving node, and removes
the isolated contract cluster on exit.

## Data Flow: Wattswarm, Wattetheria, Gateway

The gateway sits above two data planes:

- `wattswarm`: foundation/P2P layer and node-local public read models
- `wattetheria`: application/rules layer that signs public snapshots and events
- `wattetheria-gateway`: verification, storage, registry, and public API layer

Current sync paths:

1. `Wattswarm -> Wattetheria`: Wattetheria runs as a client of the Wattswarm
   sync service and folds network projections into local application state.
2. `Wattetheria -> Gateway`: Wattetheria can push signed public snapshots to
   `POST /api/ingest/snapshot` and events to `POST /api/ingest/event`.
3. `Gateway -> Wattetheria / Wattswarm`: Gateway pull mode is exposed through
   `POST /api/nodes/sync` and can fetch a registered Wattetheria export plus
   selected public Wattswarm read models.

Pull sync is trigger-based. Operators, schedulers, or external automation call
`POST /api/nodes/sync`; the gateway does not run an internal periodic sync loop.

```mermaid
flowchart LR
    subgraph WS["Wattswarm node"]
        WS_P2P["P2P transport, gossip, tasks"]
        WS_HTTP["HTTP read models\n/api/wattetheria/network/snapshot\n/api/wattetheria/topic/activity\n/api/wattetheria/topic/subscriptions"]
        WS_GRPC["gRPC projection streams\nnetwork/task/topic/social"]
        WS_P2P --> WS_HTTP
        WS_P2P --> WS_GRPC
    end

    subgraph WT["Wattetheria node"]
        WT_SYNC["Wattswarm sync bridge\ngRPC client"]
        WT_STATE["Application state\nidentity, governance, orgs, topics"]
        WT_EXPORT["Signed public export\nGET /v1/wattetheria/client/export"]
        WT_PUSH["Gateway dispatch\nsnapshot interval + event stream"]
        WT_SYNC --> WT_STATE
        WT_STATE --> WT_EXPORT
        WT_STATE --> WT_PUSH
    end

    subgraph GW["wattetheria-gateway"]
        GW_REGISTER["Node source registry\n/api/nodes/register"]
        GW_SYNC["Triggered pull\nPOST /api/nodes/sync"]
        GW_INGEST["Push ingest\n/api/ingest/snapshot\n/api/ingest/event"]
        GW_VERIFY["Signature verification"]
        GW_DB["Postgres\nnode_snapshots + projection rows"]
        GW_API["Public APIs\n/api/network/status\n/api/network/nodes\n/api/missions\n/api/hives"]
        GW_REGISTER --> GW_SYNC
        GW_SYNC --> GW_VERIFY
        GW_INGEST --> GW_VERIFY
        GW_VERIFY --> GW_DB
        GW_DB --> GW_API
    end

    WT_SYNC -- "subscribes/pulls gRPC" --> WS_GRPC
    WT_PUSH -- "pushes signed snapshots/events" --> GW_INGEST
    GW_SYNC -- "pulls signed export" --> WT_EXPORT
    GW_SYNC -- "optionally pulls selected Wattswarm HTTP read models\nwhen wattswarm_ui_base_url is configured" --> WS_HTTP
```

## Configuration

Common environment variables:

- `WATTETHERIA_GATEWAY_BIND`
- `WATTETHERIA_GATEWAY_DATABASE_URL`
- `WATTETHERIA_GATEWAY_NATS_URL`
- `WATTETHERIA_GATEWAY_REQUEST_TIMEOUT_SECS`
- `WATTETHERIA_GATEWAY_REGISTRY_ADMIN_TOKEN`
- `WATTETHERIA_GATEWAY_BOOTSTRAP_REGISTRY_URLS`
- `WATTETHERIA_GATEWAY_FEDERATION_MODE`
- `WATTETHERIA_GATEWAY_FEDERATION_TRUSTED_PEERS`
- `WATTETHERIA_GATEWAY_P2P_ENABLED`
- `WATTETHERIA_GATEWAY_P2P_STATE_DIR`
- `WATTETHERIA_GATEWAY_P2P_LISTEN_ADDRS`
- `WATTETHERIA_GATEWAY_P2P_BOOTSTRAP_PEERS`
- `WATTETHERIA_GATEWAY_IDENTITY_ID`
- `WATTETHERIA_GATEWAY_IDENTITY_DISPLAY_NAME`
- `WATTETHERIA_GATEWAY_IDENTITY_BASE_URL`
- `WATTETHERIA_GATEWAY_IDENTITY_SIGNING_KEY`
- `WATTETHERIA_GATEWAY_IDENTITY_REGION`
- `WATTETHERIA_GATEWAY_IDENTITY_OPERATOR_DID`
- `WATTETHERIA_GATEWAY_IDENTITY_ROLES`
- `WATTETHERIA_GATEWAY_IDENTITY_SUPPORTED_ENDPOINTS`
- `WATTETHERIA_GATEWAY_IDENTITY_FEDERATION_PEERS` legacy alias for trusted peers
- `WATTETHERIA_GATEWAY_IDENTITY_ALLOWS_PUBLIC_INGEST`

## Gateway P2P Synchronization

When `WATTETHERIA_GATEWAY_P2P_ENABLED` is enabled, the gateway starts a shared
P2P runtime and joins the global summary gossip scope. Successful signed
snapshot ingests are announced over gossip with the gateway's Iroh contact
material. Peer gateways that receive an announcement compare the advertised
snapshot version with their local store, fetch missing or newer signed snapshots
over Iroh direct transport, then run the normal signature verification and
read-model ingest path. Successful signed node events are propagated as signed
gossip payloads and are also re-ingested through the normal event verification
and projection path.

Gossip carries only small synchronization announcements and signed event
payloads. Snapshot payloads and artifacts are fetched over direct transport so
large public data is not broadcast through the gossip mesh. HTTP federation
remains available for query-time aggregation and registry discovery.

`WATTETHERIA_GATEWAY_BOOTSTRAP_REGISTRY_URLS` accepts gateway base URLs, registry
list URLs, or registry registration URLs; the gateway normalizes them for list
and register operations.

Federation can run in `open` mode or `trusted` mode. Curated entry gateways
should prefer trusted mode:

```bash
WATTETHERIA_GATEWAY_FEDERATION_MODE=trusted
WATTETHERIA_GATEWAY_FEDERATION_TRUSTED_PEERS=https://gw-ap.example.com,https://gw-eu.example.com
```

Public UI query endpoints aggregate trusted peers directly and add
`federation=local` to remote requests to prevent recursive gateway fan-out.

Public chat support is intentionally limited in this phase:

- supported: public topics and public topic messages in signed snapshots
- supported: public Board plaza messages in signed Wattetheria snapshots and
  events, exposed through `/api/board`
- supported: Hive `member_count` from active Wattswarm topic subscription
  projections when a source exposes `wattswarm_ui_base_url`
- not supported: private groups, encrypted rooms, or sensitive coordination channels

Default Postgres DSN:

```text
postgres://postgres:postgres@127.0.0.1:5432/wattetheria_gateway
```

`docker-compose.yml` publishes Postgres on `127.0.0.1:55434`:

```text
postgres://postgres:postgres@127.0.0.1:55434/wattetheria_gateway
```

## Local Development

The default Compose file runs the P2P gateway stack only:

```bash
cp .env.example .env
docker compose up --build
```

ClientServer mode uses a separate overlay that adds the Message Gateway and
RabbitMQ while retaining the public Gateway, PostgreSQL, and NATS services:

```bash
cp .env.example .env
docker compose \
  -f docker-compose.yml \
  -f docker-compose.client-server.yml \
  up --build
```

Set non-default values for `WATTSWARM_RABBITMQ_PASSWORD` and
`WATTSWARM_CS_COMMIT_HMAC_SECRET` before exposing this deployment. The overlay
creates the separate `wattswarm_message_gateway` PostgreSQL database, generates
a local RabbitMQ TLS certificate, and exposes the Message Gateway on port
`8090`. RabbitMQ's management UI is exposed on port `15672`; Wattswarm nodes
never connect to RabbitMQ directly.

If you prefer running the Rust process directly outside Docker:

```bash
cp .env.example .env
docker compose up -d postgres nats
cargo run
```

## Testing

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

Integration tests start the local `postgres` service from `docker-compose.yml`
and create isolated test databases per test case.

## Direction

This project is intended to evolve into a federated gateway network:

- anyone can deploy a gateway
- not every deployed gateway is automatically discoverable
- gateways can index the same public node data independently
- future versions can mirror or federate between gateways
- registry trust tiers can remain local to each registry operator or later federate between registries
- the gateway remains non-authoritative; signed node data stays the root fact source
