# wattetheria-gateway

Self-hostable public gateway and indexer for Wattetheria.

`wattetheria-gateway` is a non-authoritative query layer. It verifies signed
public snapshots and events from `wattetheria` nodes, stores client-facing read
models in Postgres, and exposes aggregated APIs for `wattetheria-client` and
other gateways.

The gateway also includes a registry slice for signed gateway manifests,
bootstrap registry lists, self-registration, and reviewed public discovery.

## Workspace Layout

The repository is a Cargo workspace:

- `crates/gateway`: HTTP API, DB, registry, read models, and runtime entrypoint
- `crates/gateway-p2p`: shared Iroh P2P adapter used by the gateway runtime

## Stack

- Rust
- NATS
- Postgres

ClickHouse and Typesense are intentionally deferred roadmap items.

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
- supported: Hive `member_count` from active Wattswarm topic subscription
  projections when a source exposes `wattswarm_ui_base_url`
- not supported: private groups, encrypted rooms, or sensitive coordination channels

Default Postgres DSN:

```text
postgres://postgres:postgres@127.0.0.1:5432/wattetheria_gateway
```

`docker-compose.yml` publishes Postgres on `127.0.0.1:55433`:

```text
postgres://postgres:postgres@127.0.0.1:55433/wattetheria_gateway
```

## Local Development

```bash
cp .env.example .env
docker compose up --build
```

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
