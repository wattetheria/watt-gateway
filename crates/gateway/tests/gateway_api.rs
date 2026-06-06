use axum::body::{Body, to_bytes};
use axum::extract::OriginalUri;
use axum::http::{Request, StatusCode};
use axum::{Json, Router, routing::get};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use sqlx::ConnectOptions;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use tower::util::ServiceExt;
use wattetheria_gateway::contracts::{
    DataKind, EventScope, NodeEventPayload, ProvisionalExportPolicy, SignedNodeEvent, Visibility,
};
use wattetheria_gateway::db::{self, UpsertProjectionRecord, UpsertSnapshotRecord};
use wattetheria_gateway::gateway_identity::{GatewayIdentity, GatewayIdentityConfig};
use wattetheria_gateway::gateway_network::{
    self, GatewayNetworkHandle, GatewayNetworkNode, GatewayNetworkRuntime,
};
use wattetheria_gateway::http;
use wattetheria_gateway::models::{
    GatewayManifest, PublicClientSnapshot, SignedGatewayManifest, SignedPublicClientSnapshot,
};
use wattetheria_gateway::node_client::NodeClient;
use wattetheria_gateway::registry_client::RegistryClient;
use wattetheria_gateway::state::AppState;
use wattetheria_gateway::verify::{canonical_bytes, verify_signed_gateway_manifest};
use wattswarm_artifact_store::ArtifactStore;
use wattswarm_network_transport_core::PeerTransportCapabilities;

static POSTGRES_READY: OnceLock<()> = OnceLock::new();

#[tokio::test]
async fn register_and_sync_ingests_snapshot_and_aggregates() {
    let db = TestDatabase::new().await;
    let export_server = MockExportServer::spawn(signed_snapshot(
        "node-alpha",
        SnapshotContents {
            network_name: Some("Watt Etheria"),
            network_org_name: Some("Aether Prime"),
            peers: &[json!({"id":"peer-1"}), json!({"id":"peer-2"})],
            public_blocks: &[json!({
                "counterpart_public_id":"did:key:blocked-1",
                "relationship_state":"blocked"
            })],
            public_topics: &[json!({
                "topic_id":"topic-public-1",
                "organization_id":"org-1",
                "title":"Aurora Ops",
                "last_message_at":"2026-03-18T01:00:00Z"
            })],
            public_topic_messages: &[json!({
                "message_id":"msg-1",
                "topic_id":"topic-public-1",
                "organization_id":"org-1",
                "author_id":"agent-1",
                "body":"Relay stable",
                "created_at":"2026-03-18T01:00:00Z"
            })],
            swarm_task_activity: json!({
                "generated_at": 1_710_000_000,
                "tasks": [{"task_id":"task-1","terminal_state":"finalized"}],
                "runs": [{
                    "run_id":"run-1",
                    "task_id":"task-1",
                    "status":"QUEUED",
                    "updated_at":"2026-03-18T01:03:00Z"
                }]
            }),
            tasks: &[json!({"id":"task-1","title":"Relay Repair"})],
            organizations: &[json!({"id":"org-1","name":"Aurora Guild"})],
            leaderboard: &[json!({"agent_did":"did:key:agent-1","score":9})],
        },
    ))
    .await;
    let app = test_app(&db.database_url).await;

    let register = request_json(
        &app,
        "POST",
        "/api/nodes/register",
        json!({
            "name": "alpha",
            "export_url": export_server.export_url(),
            "region": "ap-southeast"
        }),
    )
    .await;
    assert_eq!(register.0, StatusCode::CREATED);

    let sync = request_json(&app, "POST", "/api/nodes/sync", json!({})).await;
    assert_eq!(sync.0, StatusCode::OK);
    assert_eq!(sync.1.as_array().unwrap().len(), 1);
    assert_eq!(sync.1[0]["node_id"].as_str(), Some("node-alpha"));

    let nodes = request(&app, "GET", "/api/nodes").await;
    assert_eq!(nodes.0, StatusCode::OK);
    assert_eq!(nodes.1.as_array().unwrap().len(), 1);
    assert_eq!(nodes.1[0]["last_sync_status"].as_str(), Some("ok"));
    assert_eq!(
        nodes.1[0]["snapshot"]["node_id"].as_str(),
        Some("node-alpha")
    );
    assert_eq!(
        nodes.1[0]["snapshot"]["network_name"].as_str(),
        Some("Watt Etheria")
    );
    assert_eq!(
        nodes.1[0]["snapshot"]["network_org_name"].as_str(),
        Some("Aether Prime")
    );

    let network_status = request(&app, "GET", "/api/network/status").await;
    assert_eq!(network_status.0, StatusCode::OK);
    assert_eq!(network_status.1["nodes"].as_u64(), Some(1));
    assert_eq!(network_status.1["peers"].as_u64(), Some(2));
    assert_eq!(network_status.1["tasks"].as_u64(), Some(1));
    assert_eq!(network_status.1["organizations"].as_u64(), Some(1));
    assert_eq!(network_status.1["topics"].as_u64(), Some(1));
    assert_eq!(network_status.1["topic_messages"].as_u64(), Some(1));
    assert_eq!(network_status.1["public_blocks"].as_u64(), Some(1));
    assert_eq!(
        network_status.1["network_name"].as_str(),
        Some("Watt Etheria")
    );
    assert_eq!(
        network_status.1["network_org_name"].as_str(),
        Some("Aether Prime")
    );

    let peers = request(&app, "GET", "/api/peers?limit=10").await;
    assert_eq!(peers.0, StatusCode::OK);
    assert_eq!(peers.1.as_array().unwrap().len(), 2);
    assert_eq!(peers.1[0]["source_node_id"].as_str(), Some("node-alpha"));

    let topics = request(&app, "GET", "/api/hives?limit=10").await;
    assert_eq!(topics.0, StatusCode::OK);
    assert_eq!(topics.1.as_array().unwrap().len(), 1);
    assert_eq!(topics.1[0]["source_node_id"].as_str(), Some("node-alpha"));

    let topic_messages = request(
        &app,
        "GET",
        "/api/hive-messages?topic_id=topic-public-1&limit=10",
    )
    .await;
    assert_eq!(topic_messages.0, StatusCode::OK);
    assert_eq!(topic_messages.1.as_array().unwrap().len(), 1);
    assert_eq!(
        topic_messages.1[0]["topic_id"].as_str(),
        Some("topic-public-1")
    );

    let friends = request_status(&app, "GET", "/api/friends?limit=10").await;
    assert_eq!(friends, StatusCode::NOT_FOUND);

    let pending_requests = request_status(&app, "GET", "/api/friend-requests?limit=10").await;
    assert_eq!(pending_requests, StatusCode::NOT_FOUND);

    let blocks = request(&app, "GET", "/api/blocks?limit=10").await;
    assert_eq!(blocks.0, StatusCode::OK);
    assert_eq!(blocks.1.as_array().unwrap().len(), 1);
    assert_eq!(
        blocks.1[0]["counterpart_public_id"].as_str(),
        Some("did:key:blocked-1")
    );

    let dm_threads = request_status(&app, "GET", "/api/dm/threads?limit=10").await;
    assert_eq!(dm_threads, StatusCode::NOT_FOUND);

    let dm_messages = request_status(&app, "GET", "/api/dm/messages?limit=10").await;
    assert_eq!(dm_messages, StatusCode::NOT_FOUND);

    let tasks = request(&app, "GET", "/api/missions?limit=10").await;
    assert_eq!(tasks.0, StatusCode::OK);
    assert_eq!(tasks.1.as_array().unwrap().len(), 1);
    assert_eq!(tasks.1[0]["source_node_id"].as_str(), Some("node-alpha"));

    assert_eq!(
        request_status(&app, "GET", "/v1/wattetheria/hives?limit=10").await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request_status(
            &app,
            "GET",
            "/v1/wattetheria/hives/topic-public-1/messages?limit=10"
        )
        .await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request_status(&app, "GET", "/v1/wattetheria/missions?limit=10").await,
        StatusCode::NOT_FOUND
    );

    let task_activity = request(&app, "GET", "/api/mission-activity?limit=10").await;
    assert_eq!(task_activity.0, StatusCode::OK);
    assert_eq!(task_activity.1["tasks"].as_array().unwrap().len(), 1);
    assert_eq!(task_activity.1["runs"].as_array().unwrap().len(), 1);
    assert_eq!(
        task_activity.1["tasks"][0]["task_id"].as_str(),
        Some("task-1")
    );
    assert_eq!(task_activity.1["runs"][0]["run_id"].as_str(), Some("run-1"));

    let organizations = request(&app, "GET", "/api/organizations?limit=10").await;
    assert_eq!(organizations.0, StatusCode::OK);
    assert_eq!(organizations.1.as_array().unwrap().len(), 1);

    let leaderboard = request(&app, "GET", "/api/leaderboard?limit=10").await;
    assert_eq!(leaderboard.0, StatusCode::OK);
    assert_eq!(leaderboard.1.as_array().unwrap().len(), 1);

    drop(app);
    export_server.abort();
    db.cleanup().await;
}

#[tokio::test]
async fn sync_rejects_invalid_signature_and_marks_source_invalid() {
    let db = TestDatabase::new().await;
    let mut invalid = signed_snapshot(
        "node-invalid",
        SnapshotContents {
            network_name: None,
            network_org_name: None,
            peers: &[],
            public_blocks: &[],
            public_topics: &[],
            public_topic_messages: &[],
            swarm_task_activity: json!({}),
            tasks: &[json!({"id":"task-bad"})],
            organizations: &[],
            leaderboard: &[],
        },
    );
    invalid.signature = "corrupted-signature".to_string();
    let export_server = MockExportServer::spawn(invalid).await;
    let app = test_app(&db.database_url).await;

    let register = request_json(
        &app,
        "POST",
        "/api/nodes/register",
        json!({
            "name": "invalid",
            "export_url": export_server.export_url()
        }),
    )
    .await;
    assert_eq!(register.0, StatusCode::CREATED);

    let sync = request_json(&app, "POST", "/api/nodes/sync", json!({})).await;
    assert_eq!(sync.0, StatusCode::BAD_REQUEST);

    let nodes = request(&app, "GET", "/api/nodes").await;
    assert_eq!(nodes.0, StatusCode::OK);
    assert_eq!(nodes.1[0]["last_sync_status"].as_str(), Some("invalid"));
    assert!(nodes.1[0]["last_error"].as_str().is_some());

    drop(app);
    export_server.abort();
    db.cleanup().await;
}

#[tokio::test]
async fn upsert_snapshot_replaces_existing_snapshot_for_same_source() {
    let db = TestDatabase::new().await;
    let pool = db.pool().await;
    db::init_schema(&pool).await.unwrap();
    let source_id = uuid::Uuid::new_v4();
    db::insert_node_source(
        &pool,
        db::InsertNodeSourceRecord {
            id: source_id,
            name: "source-a",
            export_url: "http://127.0.0.1:7777/v1/wattetheria/client/export",
            wattetheria_snapshot_export_url: Some(
                "http://127.0.0.1:7777/v1/wattetheria/client/export",
            ),
            wattetheria_events_export_url: None,
            wattswarm_ui_base_url: None,
            wattswarm_sync_grpc_endpoint: None,
            region: Some("test"),
            expected_signer_agent_did: None,
            expected_wattswarm_node_id: None,
            source_status: "active",
            transport_capabilities: None,
            transport_contact_material: None,
        },
    )
    .await
    .unwrap();

    let first = json!({
        "generated_at": 1,
        "node_id": "node-a",
        "public_key": "pub-a",
        "network_name": null,
        "network_org_name": null,
        "network_status": {},
        "peers": [],
        "operator": {},
        "rpc_logs": [],
        "tasks": [{"id":"task-1"}],
        "organizations": [],
        "leaderboard": [],
    });
    db::upsert_snapshot(
        &pool,
        UpsertSnapshotRecord {
            source_id: Some(source_id),
            node_id: "node-a",
            signer_agent_did: "pub-a",
            public_key: "pub-a",
            generated_at: 1,
            payload: &first,
            signature: "sig-1",
        },
    )
    .await
    .unwrap();

    let second = json!({
        "generated_at": 2,
        "node_id": "node-a",
        "public_key": "pub-a",
        "network_name": null,
        "network_org_name": null,
        "network_status": {},
        "peers": [],
        "operator": {},
        "rpc_logs": [],
        "tasks": [{"id":"task-2"}],
        "organizations": [],
        "leaderboard": [],
    });
    db::upsert_snapshot(
        &pool,
        UpsertSnapshotRecord {
            source_id: Some(source_id),
            node_id: "node-a",
            signer_agent_did: "pub-a",
            public_key: "pub-a",
            generated_at: 2,
            payload: &second,
            signature: "sig-2",
        },
    )
    .await
    .unwrap();

    let snapshots = db::list_snapshots(&pool).await.unwrap();
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].generated_at.timestamp(), 2);
    assert_eq!(snapshots[0].signature, "sig-2");
    assert_eq!(
        snapshots[0].payload.0["tasks"][0]["id"].as_str(),
        Some("task-2")
    );

    db.cleanup().await;
}

#[tokio::test]
async fn upsert_projection_row_does_not_write_ingest_audit() {
    let db = TestDatabase::new().await;
    let pool = db.pool().await;
    db::init_schema(&pool).await.unwrap();

    let payload = json!({"node_id": "node-a", "network_status": {"total_nodes": 1}});
    let provenance = json!({"ingest_path": "snapshot_push"});
    db::upsert_projection_row(
        &pool,
        UpsertProjectionRecord {
            data_kind: "network_projection",
            identity_key: "node-a",
            source_node_id: "node-a",
            source_id: None,
            generated_at: 1_710_000_000,
            visibility: "public",
            payload: &payload,
            provenance: &provenance,
        },
    )
    .await
    .unwrap();

    let count: i64 =
        sqlx::query_scalar("select count(*) from gateway_ingest_audit where record_kind = $1")
            .bind("projection_upsert")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 0);

    let stored_generated_at: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("select generated_at from gateway_projection_rows where data_kind = $1")
            .bind("network_projection")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored_generated_at.timestamp(), 1_710_000_000);

    db.cleanup().await;
}

#[tokio::test]
async fn generated_at_columns_use_timestamptz() {
    let db = TestDatabase::new().await;
    let pool = db.pool().await;
    db::init_schema(&pool).await.unwrap();

    let rows: Vec<(String, String)> = sqlx::query_as(
        r#"
        select table_name, data_type
        from information_schema.columns
        where table_schema = current_schema()
          and table_name in (
              'gateway_ingest_audit',
              'gateway_projection_rows',
              'gateway_ui_events',
              'node_snapshots'
          )
          and column_name = 'generated_at'
        order by table_name
        "#,
    )
    .fetch_all(&pool)
    .await
    .unwrap();

    assert_eq!(
        rows,
        vec![
            (
                "gateway_ingest_audit".to_string(),
                "timestamp with time zone".to_string()
            ),
            (
                "gateway_projection_rows".to_string(),
                "timestamp with time zone".to_string()
            ),
            (
                "gateway_ui_events".to_string(),
                "timestamp with time zone".to_string()
            ),
            (
                "node_snapshots".to_string(),
                "timestamp with time zone".to_string()
            ),
        ]
    );

    db.cleanup().await;
}

#[tokio::test]
async fn ingest_snapshot_accepts_push_without_registered_source() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;
    let snapshot = signed_snapshot(
        "node-push",
        SnapshotContents {
            network_name: None,
            network_org_name: None,
            peers: &[json!({"id":"peer-9"})],
            public_blocks: &[],
            public_topics: &[json!({"topic_id":"topic-9","title":"Public Topic 9"})],
            public_topic_messages: &[
                json!({"message_id":"msg-9","topic_id":"topic-9","body":"hello"}),
            ],
            swarm_task_activity: json!({}),
            tasks: &[json!({"id":"task-9"})],
            organizations: &[json!({"id":"org-9"})],
            leaderboard: &[json!({"agent_did":"did:key:agent-9","score":99})],
        },
    );

    let ingest = request_json(
        &app,
        "POST",
        "/api/ingest/snapshot",
        serde_json::to_value(&snapshot).unwrap(),
    )
    .await;
    assert_eq!(ingest.0, StatusCode::OK);
    assert_eq!(ingest.1["node_id"].as_str(), Some("node-push"));

    let nodes = request(&app, "GET", "/api/nodes").await;
    assert_eq!(nodes.0, StatusCode::OK);
    assert_eq!(nodes.1.as_array().unwrap().len(), 1);
    assert_eq!(nodes.1[0]["last_sync_status"].as_str(), Some("push"));
    assert_eq!(
        nodes.1[0]["snapshot"]["node_id"].as_str(),
        Some("node-push")
    );

    let network_status = request(&app, "GET", "/api/network/status").await;
    assert_eq!(network_status.1["nodes"].as_u64(), Some(1));

    db.cleanup().await;
}

#[tokio::test]
async fn public_hives_and_messages_are_deduped_sorted_and_filterable() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;
    let first = signed_snapshot(
        "node-alpha",
        SnapshotContents {
            network_name: None,
            network_org_name: None,
            peers: &[],
            public_blocks: &[],
            public_topics: &[json!({
                "topic_id":"topic-a",
                "organization_id":"org-1",
                "title":"Ops",
                "last_message_at":"2026-03-18T02:00:00Z"
            })],
            public_topic_messages: &[json!({
                "message_id":"msg-a",
                "topic_id":"topic-a",
                "organization_id":"org-1",
                "author_id":"agent-1",
                "body":"first",
                "created_at":"2026-03-18T02:00:00Z"
            })],
            swarm_task_activity: json!({}),
            tasks: &[],
            organizations: &[],
            leaderboard: &[],
        },
    );
    let second = signed_snapshot(
        "node-beta",
        SnapshotContents {
            network_name: None,
            network_org_name: None,
            peers: &[],
            public_blocks: &[],
            public_topics: &[
                json!({
                    "topic_id":"topic-a",
                    "organization_id":"org-1",
                    "title":"Ops duplicate",
                    "last_message_at":"2026-03-18T01:00:00Z"
                }),
                json!({
                    "topic_id":"topic-b",
                    "organization_id":"org-2",
                    "title":"Travel",
                    "last_message_at":"2026-03-18T03:00:00Z"
                }),
            ],
            public_topic_messages: &[
                json!({
                    "message_id":"msg-a",
                    "topic_id":"topic-a",
                    "organization_id":"org-1",
                    "author_id":"agent-1",
                    "body":"first",
                    "created_at":"2026-03-18T02:00:00Z"
                }),
                json!({
                    "message_id":"msg-b",
                    "topic_id":"topic-b",
                    "organization_id":"org-2",
                    "author_id":"agent-2",
                    "body":"second",
                    "created_at":"2026-03-18T03:00:00Z"
                }),
            ],
            swarm_task_activity: json!({}),
            tasks: &[],
            organizations: &[],
            leaderboard: &[],
        },
    );

    let ingest_first = request_json(
        &app,
        "POST",
        "/api/ingest/snapshot",
        serde_json::to_value(&first).unwrap(),
    )
    .await;
    assert_eq!(ingest_first.0, StatusCode::OK);

    let ingest_second = request_json(
        &app,
        "POST",
        "/api/ingest/snapshot",
        serde_json::to_value(&second).unwrap(),
    )
    .await;
    assert_eq!(ingest_second.0, StatusCode::OK);

    let topics = request(&app, "GET", "/api/hives?limit=10").await;
    assert_eq!(topics.0, StatusCode::OK);
    assert_eq!(topics.1.as_array().unwrap().len(), 2);
    assert_eq!(topics.1[0]["topic_id"].as_str(), Some("topic-b"));
    assert_eq!(topics.1[1]["topic_id"].as_str(), Some("topic-a"));

    let filtered_topics = request(&app, "GET", "/api/hives?organization_id=org-1").await;
    assert_eq!(filtered_topics.0, StatusCode::OK);
    assert_eq!(filtered_topics.1.as_array().unwrap().len(), 1);
    assert_eq!(filtered_topics.1[0]["topic_id"].as_str(), Some("topic-a"));

    let messages = request(&app, "GET", "/api/hive-messages?topic_id=topic-b&limit=10").await;
    assert_eq!(messages.0, StatusCode::OK);
    assert_eq!(messages.1.as_array().unwrap().len(), 1);
    assert_eq!(messages.1[0]["message_id"].as_str(), Some("msg-b"));

    let filtered_messages = request(&app, "GET", "/api/hive-messages?topic_id=topic-a").await;
    assert_eq!(filtered_messages.0, StatusCode::OK);
    assert_eq!(filtered_messages.1.as_array().unwrap().len(), 1);
    assert_eq!(filtered_messages.1[0]["message_id"].as_str(), Some("msg-a"));

    db.cleanup().await;
}

#[tokio::test]
async fn older_snapshot_does_not_replace_newer_snapshot() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;
    let newer = signed_snapshot_at(
        "node-stable",
        1_710_000_100,
        SnapshotContents {
            network_name: None,
            network_org_name: None,
            peers: &[],
            public_blocks: &[],
            public_topics: &[],
            public_topic_messages: &[],
            swarm_task_activity: json!({}),
            tasks: &[json!({"id":"task-new"})],
            organizations: &[],
            leaderboard: &[],
        },
    );
    let older = signed_snapshot_at(
        "node-stable",
        1_710_000_090,
        SnapshotContents {
            network_name: None,
            network_org_name: None,
            peers: &[],
            public_blocks: &[],
            public_topics: &[],
            public_topic_messages: &[],
            swarm_task_activity: json!({}),
            tasks: &[json!({"id":"task-old"})],
            organizations: &[],
            leaderboard: &[],
        },
    );

    let ingest_newer = request_json(
        &app,
        "POST",
        "/api/ingest/snapshot",
        serde_json::to_value(&newer).unwrap(),
    )
    .await;
    assert_eq!(ingest_newer.0, StatusCode::OK);

    let stale = request_json(
        &app,
        "POST",
        "/api/ingest/snapshot",
        serde_json::to_value(&older).unwrap(),
    )
    .await;
    assert_eq!(stale.0, StatusCode::OK);

    let tasks = request(&app, "GET", "/api/missions?limit=10").await;
    assert_eq!(tasks.0, StatusCode::OK);
    assert_eq!(tasks.1[0]["id"].as_str(), Some("task-new"));

    db.cleanup().await;
}

#[tokio::test]
async fn suspended_registered_source_is_hidden_from_public_reads_and_rejects_push_ingest() {
    let db = TestDatabase::new().await;
    let pool = db.pool().await;
    let snapshot = signed_snapshot(
        "node-suspend",
        SnapshotContents {
            network_name: Some("Watt Etheria"),
            network_org_name: Some("Aether Prime"),
            peers: &[json!({"id":"peer-hidden"})],
            public_blocks: &[],
            public_topics: &[],
            public_topic_messages: &[],
            swarm_task_activity: json!({}),
            tasks: &[json!({"id":"task-hidden"})],
            organizations: &[],
            leaderboard: &[],
        },
    );
    let export_server = MockExportServer::spawn(snapshot.clone()).await;
    let app = test_app(&db.database_url).await;

    let register = request_json(
        &app,
        "POST",
        "/api/nodes/register",
        json!({
            "name": "suspended-node",
            "export_url": export_server.export_url(),
            "expected_signer_agent_did": snapshot.signer_agent_did,
        }),
    )
    .await;
    assert_eq!(register.0, StatusCode::CREATED);

    let sync = request_json(&app, "POST", "/api/nodes/sync", json!({})).await;
    assert_eq!(sync.0, StatusCode::OK);

    let source_id = uuid::Uuid::parse_str(register.1["source_id"].as_str().unwrap()).unwrap();
    sqlx::query("update node_sources set source_status = 'suspended' where id = $1")
        .bind(source_id)
        .execute(&pool)
        .await
        .unwrap();

    let network_status = request(&app, "GET", "/api/network/status").await;
    assert_eq!(network_status.0, StatusCode::OK);
    assert_eq!(network_status.1["nodes"].as_u64(), Some(0));

    let tasks = request(&app, "GET", "/api/missions?limit=10").await;
    assert_eq!(tasks.0, StatusCode::OK);
    assert_eq!(tasks.1.as_array().unwrap().len(), 0);

    let push_snapshot = request_json(
        &app,
        "POST",
        "/api/ingest/snapshot",
        serde_json::to_value(&snapshot).unwrap(),
    )
    .await;
    assert_eq!(push_snapshot.0, StatusCode::CONFLICT);

    let event = signed_node_event(
        "node-suspend",
        DataKind::TaskRoundUpdate,
        "task.round.updated",
        json!({"task_id":"task-hidden","round_id":"round-1"}),
    );
    let push_event = request_json(
        &app,
        "POST",
        "/api/ingest/event",
        serde_json::to_value(&event).unwrap(),
    )
    .await;
    assert_eq!(push_event.0, StatusCode::BAD_REQUEST);

    drop(app);
    export_server.abort();
    db.cleanup().await;
}

#[tokio::test]
async fn find_node_source_returns_first_match_when_multiple_sources_match_identity() {
    let db = TestDatabase::new().await;
    let pool = db.pool().await;
    db::init_schema(&pool).await.unwrap();

    db::insert_node_source(
        &pool,
        db::InsertNodeSourceRecord {
            id: uuid::Uuid::new_v4(),
            name: "first-match",
            export_url: "https://first.example/export",
            wattetheria_snapshot_export_url: None,
            wattetheria_events_export_url: None,
            wattswarm_ui_base_url: None,
            wattswarm_sync_grpc_endpoint: None,
            region: None,
            expected_signer_agent_did: Some("did:key:shared"),
            expected_wattswarm_node_id: Some("node-shared"),
            source_status: "active",
            transport_capabilities: None,
            transport_contact_material: None,
        },
    )
    .await
    .unwrap();
    db::insert_node_source(
        &pool,
        db::InsertNodeSourceRecord {
            id: uuid::Uuid::new_v4(),
            name: "second-match",
            export_url: "https://second.example/export",
            wattetheria_snapshot_export_url: None,
            wattetheria_events_export_url: None,
            wattswarm_ui_base_url: None,
            wattswarm_sync_grpc_endpoint: None,
            region: None,
            expected_signer_agent_did: Some("did:key:shared"),
            expected_wattswarm_node_id: Some("node-shared"),
            source_status: "active",
            transport_capabilities: None,
            transport_contact_material: None,
        },
    )
    .await
    .unwrap();

    let source = db::find_node_source_for_identity(&pool, "node-shared", "did:key:shared")
        .await
        .unwrap()
        .expect("source should resolve");
    assert_eq!(source.name, "first-match");

    drop(pool);
    db.cleanup().await;
}

#[tokio::test]
async fn ephemeral_only_events_are_streamed_without_persisting_ui_rows() {
    let db = TestDatabase::new().await;
    let pool = db.pool().await;
    db::init_schema(&pool).await.unwrap();
    let (ui_stream_tx, mut ui_stream_rx) = tokio::sync::broadcast::channel(64);
    let state = AppState {
        pool: pool.clone(),
        node_client: NodeClient::new(5).unwrap(),
        registry_client: RegistryClient::new(5).unwrap(),
        nats: None,
        registry_admin_token: Some("registry-secret".to_string()),
        bootstrap_registry_urls: Vec::new(),
        gateway_identity: None,
        gateway_network: None,
        ui_stream_tx,
    };

    let mut event = signed_node_event(
        "node-ephemeral",
        DataKind::HiveMessagePosted,
        "topic.message.posted",
        json!({"topic_id":"topic-ephemeral","body":"transient"}),
    );
    event.payload.provisional_policy = ProvisionalExportPolicy::EphemeralOnly;
    let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
    event.signature = base64::engine::general_purpose::STANDARD.encode(
        signing_key
            .sign(&canonical_bytes(&event.payload).unwrap())
            .to_bytes(),
    );

    let cursor =
        wattetheria_gateway::streaming::persist_signed_node_event(&state, &event, None, None)
            .await
            .unwrap();
    assert_eq!(cursor, None);

    let streamed = ui_stream_rx.recv().await.unwrap();
    assert_eq!(streamed.event_id, event.payload.event_id);
    assert_eq!(streamed.cursor, 0);

    let persisted_count: i64 = sqlx::query_scalar("select count(*) from gateway_ui_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(persisted_count, 0);

    drop(pool);
    db.cleanup().await;
}

#[tokio::test]
async fn mission_lifecycle_event_materializes_task_projection() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;
    let mut event = signed_node_event(
        "node-mission",
        DataKind::MissionLifecycle,
        "mission.published",
        json!({
            "mission_id": "mission-event-1",
            "title": "Gateway Event Mission",
            "description": "Published through event push",
            "domain": "culture",
            "status": "open",
            "publisher": "agent-publisher",
            "publisher_kind": "player",
            "reward": {
                "agent_watt": 0,
                "capacity": 0,
                "reputation": 0,
                "treasury_share_watt": 0
            }
        }),
    );
    event.payload.provisional_policy = ProvisionalExportPolicy::NeverBeforeConfirmation;
    event.payload.scope.task_id = Some("mission-event-1".to_string());
    event.payload.identity_key = Some("mission-event-1".to_string());
    let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
    event.signature = base64::engine::general_purpose::STANDARD.encode(
        signing_key
            .sign(&canonical_bytes(&event.payload).unwrap())
            .to_bytes(),
    );

    let ingest = request_json(
        &app,
        "POST",
        "/api/ingest/event",
        serde_json::to_value(&event).unwrap(),
    )
    .await;
    assert_eq!(ingest.0, StatusCode::OK);

    let persisted_events: i64 = sqlx::query_scalar("select count(*) from gateway_ui_events")
        .fetch_one(&db.pool().await)
        .await
        .unwrap();
    assert_eq!(persisted_events, 1);

    let tasks = request(&app, "GET", "/api/missions?limit=10").await;
    assert_eq!(tasks.0, StatusCode::OK);
    assert_eq!(tasks.1.as_array().unwrap().len(), 1);
    assert_eq!(tasks.1[0]["mission_id"].as_str(), Some("mission-event-1"));
    assert_eq!(tasks.1[0]["task_id"].as_str(), Some("mission-event-1"));
    assert_eq!(
        tasks.1[0]["task_type"].as_str(),
        Some("wattetheria.mission")
    );
    assert_eq!(tasks.1[0]["status"].as_str(), Some("published"));
    assert_eq!(tasks.1[0]["source_node_id"].as_str(), Some("node-mission"));

    sqlx::query("delete from gateway_projection_rows")
        .execute(&db.pool().await)
        .await
        .unwrap();
    let duplicate = request_json(
        &app,
        "POST",
        "/api/ingest/event",
        serde_json::to_value(&event).unwrap(),
    )
    .await;
    assert_eq!(duplicate.0, StatusCode::OK);
    assert_eq!(duplicate.1["status"].as_str(), Some("duplicate"));
    let restored_tasks = request(&app, "GET", "/api/missions?limit=10").await;
    assert_eq!(restored_tasks.0, StatusCode::OK);
    assert_eq!(restored_tasks.1.as_array().unwrap().len(), 1);

    db.cleanup().await;
}

#[tokio::test]
async fn ranking_event_materializes_leaderboard_projection() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;
    let mut event = signed_node_event(
        "node-ranking",
        DataKind::RankingProjection,
        "ranking.updated",
        json!({
            "public_id": "agent-public-1",
            "agent_identity": "Agent One",
            "display_name": "Agent One",
            "watt_balance": 7,
            "score": 11,
            "score_tenths": 107,
            "compute_score": 1,
            "prestige": 0,
            "reputation": 0,
            "tasks_completed": 0
        }),
    );
    event.payload.provisional_policy = ProvisionalExportPolicy::NeverBeforeConfirmation;
    event.payload.scope.task_id = None;
    event.payload.identity_key = Some("agent-public-1".to_string());
    resign_node_event(&mut event);

    let ingest = request_json(
        &app,
        "POST",
        "/api/ingest/event",
        serde_json::to_value(&event).unwrap(),
    )
    .await;
    assert_eq!(ingest.0, StatusCode::OK);

    let leaderboard = request(&app, "GET", "/api/leaderboard?limit=10").await;
    assert_eq!(leaderboard.0, StatusCode::OK);
    assert_eq!(leaderboard.1.as_array().unwrap().len(), 1);
    assert_eq!(
        leaderboard.1[0]["public_id"].as_str(),
        Some("agent-public-1")
    );
    assert_eq!(leaderboard.1[0]["watt_balance"].as_i64(), Some(7));
    assert_eq!(
        leaderboard.1[0]["agent_identity"].as_str(),
        Some("Agent One")
    );
    assert_eq!(leaderboard.1[0]["score"].as_i64(), Some(11));
    assert_eq!(leaderboard.1[0]["score_tenths"].as_i64(), Some(107));
    assert_eq!(leaderboard.1[0]["compute_score"].as_i64(), Some(1));
    assert_eq!(leaderboard.1[0]["prestige"].as_i64(), Some(0));
    assert_eq!(
        leaderboard.1[0]["source_node_id"].as_str(),
        Some("node-ranking")
    );

    db.cleanup().await;
}

#[tokio::test]
async fn hive_metadata_event_materializes_topic_projection() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;
    let topic_id = "mainnet:watt-etheria@london-2026-economy@group:london-2026-economy";
    let mut event = signed_node_event(
        "node-hive",
        DataKind::HiveMetadata,
        "topic.created",
        json!({
            "hive": {
                "hive_id": topic_id,
                "topic_id": topic_id,
                "network_id": "mainnet:watt-etheria",
                "scope_hint": "group:london-2026-economy",
                "feed_key": "london-2026-economy",
                "display_name": "讨论伦敦2026年的经济情况",
                "summary": "讨论伦敦2026年的经济趋势、就业、通胀、房地产、金融服务和政策环境。",
                "active": true,
                "created_at": 1_780_114_390,
                "updated_at": 1_780_114_390,
                "created_by_public_id": "agent-mCPkNMDtN2X8.aa02a834d64b68b8",
                "participant_public_ids": []
            },
            "public_id": "agent-mCPkNMDtN2X8.aa02a834d64b68b8",
            "network_id": "mainnet:watt-etheria"
        }),
    );
    event.payload.provisional_policy = ProvisionalExportPolicy::NeverBeforeConfirmation;
    event.payload.scope.topic_id = Some(topic_id.to_string());
    event.payload.scope.task_id = None;
    event.payload.identity_key = Some(topic_id.to_string());
    resign_node_event(&mut event);

    let ingest = request_json(
        &app,
        "POST",
        "/api/ingest/event",
        serde_json::to_value(&event).unwrap(),
    )
    .await;
    assert_eq!(ingest.0, StatusCode::OK);

    let topics = request(&app, "GET", "/api/hives?limit=10").await;
    assert_eq!(topics.0, StatusCode::OK);
    assert_eq!(topics.1.as_array().unwrap().len(), 1);
    assert_eq!(topics.1[0]["topic_id"].as_str(), Some(topic_id));
    assert_eq!(
        topics.1[0]["display_name"].as_str(),
        Some("讨论伦敦2026年的经济情况")
    );
    assert_eq!(topics.1[0]["source_node_id"].as_str(), Some("node-hive"));

    db.cleanup().await;
}

#[tokio::test]
async fn hive_message_event_materializes_topic_message_projection() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;
    let topic_id = "mainnet:watt-etheria@london-2026-economy@group:london-2026-economy";
    let mut event = signed_node_event(
        "node-hive",
        DataKind::HiveActivity,
        "topic.message.posted",
        json!({
            "message_id": "msg-london-1",
            "topic_id": topic_id,
            "hive_id": topic_id,
            "network_id": "mainnet:watt-etheria",
            "feed_key": "london-2026-economy",
            "scope_hint": "group:london-2026-economy",
            "author_public_id": "agent-mCPkNMDtN2X8.aa02a834d64b68b8",
            "content": "伦敦2026测试消息",
            "created_at": 1_780_114_500
        }),
    );
    event.payload.provisional_policy = ProvisionalExportPolicy::NeverBeforeConfirmation;
    event.payload.scope.topic_id = Some(topic_id.to_string());
    event.payload.scope.task_id = None;
    event.payload.identity_key = Some("msg-london-1".to_string());
    resign_node_event(&mut event);

    let ingest = request_json(
        &app,
        "POST",
        "/api/ingest/event",
        serde_json::to_value(&event).unwrap(),
    )
    .await;
    assert_eq!(ingest.0, StatusCode::OK);

    let messages = request(
        &app,
        "GET",
        &format!("/api/hive-messages?topic_id={topic_id}&limit=10"),
    )
    .await;
    assert_eq!(messages.0, StatusCode::OK);
    assert_eq!(messages.1.as_array().unwrap().len(), 1);
    assert_eq!(messages.1[0]["message_id"].as_str(), Some("msg-london-1"));
    assert_eq!(messages.1[0]["topic_id"].as_str(), Some(topic_id));
    assert_eq!(messages.1[0]["content"].as_str(), Some("伦敦2026测试消息"));

    db.cleanup().await;
}

#[tokio::test]
async fn sync_nodes_reports_partial_when_wattswarm_collection_fails() {
    let db = TestDatabase::new().await;
    let snapshot = signed_snapshot(
        "node-partial",
        SnapshotContents {
            network_name: Some("Watt Etheria"),
            network_org_name: Some("Aether Prime"),
            peers: &[],
            public_blocks: &[],
            public_topics: &[],
            public_topic_messages: &[],
            swarm_task_activity: json!({}),
            tasks: &[json!({"id":"task-partial"})],
            organizations: &[],
            leaderboard: &[],
        },
    );
    let export_server = MockExportServer::spawn(snapshot.clone()).await;
    let app = test_app(&db.database_url).await;

    let register = request_json(
        &app,
        "POST",
        "/api/nodes/register",
        json!({
            "name": "partial-node",
            "export_url": export_server.export_url(),
            "expected_signer_agent_did": snapshot.signer_agent_did,
            "wattswarm_ui_base_url": "http://127.0.0.1:9"
        }),
    )
    .await;
    assert_eq!(register.0, StatusCode::CREATED);

    let sync = request_json(&app, "POST", "/api/nodes/sync", json!({})).await;
    assert_eq!(sync.0, StatusCode::OK);
    assert_eq!(sync.1.as_array().unwrap().len(), 1);
    assert_eq!(sync.1[0]["node_id"].as_str(), Some("node-partial"));
    assert_eq!(sync.1[0]["sync_status"].as_str(), Some("partial"));
    assert!(sync.1[0]["wattswarm_collect_error"].as_str().is_some());

    let nodes = request(&app, "GET", "/api/nodes").await;
    assert_eq!(nodes.0, StatusCode::OK);
    assert_eq!(nodes.1.as_array().unwrap().len(), 1);
    assert_eq!(nodes.1[0]["last_sync_status"].as_str(), Some("partial"));

    drop(app);
    export_server.abort();
    db.cleanup().await;
}

#[tokio::test]
async fn sync_nodes_does_not_require_or_import_wattswarm_task_run_snapshot() {
    let db = TestDatabase::new().await;
    let snapshot = signed_snapshot(
        "node-product-tasks",
        SnapshotContents {
            network_name: Some("Watt Etheria"),
            network_org_name: Some("Aether Prime"),
            peers: &[],
            public_blocks: &[],
            public_topics: &[],
            public_topic_messages: &[],
            swarm_task_activity: json!({}),
            tasks: &[json!({
                "id":"mission-product-1",
                "title":"Product mission",
                "status":"published"
            })],
            organizations: &[],
            leaderboard: &[],
        },
    );
    let export_server = MockExportServer::spawn(snapshot.clone()).await;
    let wattswarm_server = MockWattswarmReadModelServer::spawn().await;
    let app = test_app(&db.database_url).await;

    let register = request_json(
        &app,
        "POST",
        "/api/nodes/register",
        json!({
            "name": "product-task-node",
            "export_url": export_server.export_url(),
            "expected_signer_agent_did": snapshot.signer_agent_did,
            "wattswarm_ui_base_url": wattswarm_server.base_url()
        }),
    )
    .await;
    assert_eq!(register.0, StatusCode::CREATED);

    let sync = request_json(&app, "POST", "/api/nodes/sync", json!({})).await;
    assert_eq!(sync.0, StatusCode::OK);
    assert_eq!(sync.1[0]["sync_status"].as_str(), Some("ok"));
    assert!(sync.1[0]["wattswarm_collect_error"].is_null());

    let tasks = request(&app, "GET", "/api/missions?limit=10").await;
    assert_eq!(tasks.0, StatusCode::OK);
    assert_eq!(tasks.1.as_array().unwrap().len(), 1);
    assert_eq!(tasks.1[0]["id"].as_str(), Some("mission-product-1"));
    assert_eq!(tasks.1[0]["status"].as_str(), Some("published"));
    assert!(tasks.1[0].get("terminal_state").is_none());

    drop(app);
    wattswarm_server.abort();
    export_server.abort();
    db.cleanup().await;
}

#[tokio::test]
async fn gateway_registry_requires_review_before_public_discovery() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;
    let manifest = signed_gateway_manifest("gw-ap-1", "https://gw-ap.example", "ap-southeast");

    let register = request_json(
        &app,
        "POST",
        "/api/registry/gateways/register",
        json!({ "manifest": manifest }),
    )
    .await;
    assert_eq!(register.0, StatusCode::CREATED);
    assert_eq!(register.1["status"].as_str(), Some("pending"));

    let public_list = request(&app, "GET", "/api/registry/gateways").await;
    assert_eq!(public_list.0, StatusCode::OK);
    assert_eq!(public_list.1.as_array().unwrap().len(), 0);

    let review = request_json_with_auth(
        &app,
        "POST",
        "/api/admin/registry/gateways/gw-ap-1/review",
        json!({
            "status": "approved",
            "discovery_tier": "verified",
            "reason": "meets uptime and signature requirements",
            "reviewed_by": "registry-operator"
        }),
        Some("registry-secret"),
    )
    .await;
    assert_eq!(review.0, StatusCode::OK);
    assert_eq!(review.1["status"].as_str(), Some("approved"));
    assert_eq!(review.1["discovery_tier"].as_str(), Some("verified"));

    let public_list = request(&app, "GET", "/api/registry/gateways").await;
    assert_eq!(public_list.0, StatusCode::OK);
    assert_eq!(public_list.1.as_array().unwrap().len(), 1);
    assert_eq!(public_list.1[0]["gateway_id"].as_str(), Some("gw-ap-1"));

    let detail = request(&app, "GET", "/api/registry/gateways/gw-ap-1").await;
    assert_eq!(detail.0, StatusCode::OK);
    assert_eq!(detail.1["base_url"].as_str(), Some("https://gw-ap.example"));

    db.cleanup().await;
}

#[tokio::test]
async fn gateway_registry_review_requires_admin_token() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;
    let manifest = signed_gateway_manifest("gw-us-1", "https://gw-us.example", "us-east");

    let register = request_json(
        &app,
        "POST",
        "/api/registry/gateways/register",
        json!({ "manifest": manifest }),
    )
    .await;
    assert_eq!(register.0, StatusCode::CREATED);

    let unauthorized = request_json(
        &app,
        "POST",
        "/api/admin/registry/gateways/gw-us-1/review",
        json!({
            "status": "approved",
            "discovery_tier": "official"
        }),
    )
    .await;
    assert_eq!(unauthorized.0, StatusCode::UNAUTHORIZED);

    let forbidden = request_json_with_auth(
        &app,
        "POST",
        "/api/admin/registry/gateways/gw-us-1/review",
        json!({
            "status": "approved",
            "discovery_tier": "official"
        }),
        Some("wrong-secret"),
    )
    .await;
    assert_eq!(forbidden.0, StatusCode::FORBIDDEN);

    let pending = request_json_with_auth(
        &app,
        "GET",
        "/api/admin/registry/gateways",
        Value::Null,
        Some("registry-secret"),
    )
    .await;
    assert_eq!(pending.0, StatusCode::OK);
    assert_eq!(pending.1.as_array().unwrap().len(), 1);
    assert_eq!(pending.1[0]["status"].as_str(), Some("pending"));

    db.cleanup().await;
}

#[tokio::test]
async fn self_manifest_endpoint_returns_signed_manifest_when_identity_is_configured() {
    let db = TestDatabase::new().await;
    let app = test_app_with_identity(&db.database_url).await;

    let response = request(&app, "GET", "/api/registry/self-manifest").await;
    assert_eq!(response.0, StatusCode::OK);

    let manifest: SignedGatewayManifest = serde_json::from_value(response.1).unwrap();
    assert_eq!(manifest.payload.gateway_id, "gw-self-1");
    assert_eq!(manifest.payload.base_url, "https://gateway.self.example");
    verify_signed_gateway_manifest(&manifest).unwrap();

    db.cleanup().await;
}

#[tokio::test]
async fn self_register_posts_manifest_to_remote_registry() {
    let db = TestDatabase::new().await;
    let app = test_app_with_identity(&db.database_url).await;
    let received = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::<Value>::new()));
    let registry_app = Router::new().route(
        "/api/registry/gateways/register",
        axum::routing::post({
            let received = std::sync::Arc::clone(&received);
            move |Json(payload): Json<Value>| {
                let received = std::sync::Arc::clone(&received);
                async move {
                    received.lock().await.push(payload.clone());
                    Json(json!({
                        "gateway_id": "gw-self-1",
                        "status": "pending",
                        "discovery_tier": "community"
                    }))
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, registry_app).await.unwrap();
    });

    let response = request_json(
        &app,
        "POST",
        "/api/registry/self-register",
        json!({
            "registry_url": format!("http://{addr}")
        }),
    )
    .await;
    assert_eq!(response.0, StatusCode::OK);
    assert_eq!(response.1["results"].as_array().unwrap().len(), 1);
    assert_eq!(
        response.1["results"][0]["gateway_id"].as_str(),
        Some("gw-self-1")
    );
    assert_eq!(
        response.1["results"][0]["registry_url"].as_str(),
        Some(format!("http://{addr}/api/registry/gateways/register").as_str())
    );

    let received = received.lock().await;
    assert_eq!(received.len(), 1);
    let manifest: SignedGatewayManifest =
        serde_json::from_value(received[0]["manifest"].clone()).unwrap();
    assert_eq!(manifest.payload.gateway_id, "gw-self-1");
    verify_signed_gateway_manifest(&manifest).unwrap();

    server.abort();
    db.cleanup().await;
}

#[tokio::test]
async fn bootstrap_registry_list_and_discovery_aggregate_upstreams() {
    let db = TestDatabase::new().await;
    let received = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::<Value>::new()));
    let registry_app = Router::new()
        .route(
            "/api/registry/gateways",
            get(|| async move {
                Json(vec![json!({
                    "gateway_id": "gw-remote-1",
                    "display_name": "Remote Gateway",
                    "base_url": "https://gw-remote.example",
                    "public_key": "remote-pub",
                    "region": "eu-west",
                    "operator_did": "did:key:operator-remote",
                    "roles": ["query", "federation"],
                    "supported_endpoints": ["/api/network/status"],
                    "federation_peers": [],
                    "allows_public_ingest": true,
                    "manifest": {
                        "generated_at": 1710000000i64,
                        "gateway_id": "gw-remote-1",
                        "display_name": "Remote Gateway",
                        "base_url": "https://gw-remote.example",
                        "public_key": "remote-pub",
                        "region": "eu-west",
                        "operator_did": "did:key:operator-remote",
                        "roles": ["query", "federation"],
                        "supported_endpoints": ["/api/network/status"],
                        "federation_peers": [],
                        "allows_public_ingest": true
                    },
                    "manifest_signature": "remote-sig",
                    "status": "approved",
                    "discovery_tier": "verified",
                    "review_reason": null,
                    "reviewed_at": null,
                    "reviewed_by": null,
                    "created_at": "2026-03-19T00:00:00Z",
                    "updated_at": "2026-03-19T00:00:00Z"
                })])
            }),
        )
        .route(
            "/api/registry/gateways/register",
            axum::routing::post({
                let received = std::sync::Arc::clone(&received);
                move |Json(payload): Json<Value>| {
                    let received = std::sync::Arc::clone(&received);
                    async move {
                        received.lock().await.push(payload.clone());
                        Json(json!({
                            "gateway_id": "gw-self-1",
                            "status": "pending",
                            "discovery_tier": "community"
                        }))
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, registry_app).await.unwrap();
    });
    let app =
        test_app_with_identity_and_bootstrap(&db.database_url, vec![format!("http://{addr}")])
            .await;

    let bootstrap = request(&app, "GET", "/api/registry/bootstrap").await;
    assert_eq!(bootstrap.0, StatusCode::OK);
    assert_eq!(bootstrap.1.as_array().unwrap().len(), 1);

    let self_register = request_json(&app, "POST", "/api/registry/self-register", json!({})).await;
    assert_eq!(self_register.0, StatusCode::OK);
    assert_eq!(self_register.1["results"].as_array().unwrap().len(), 1);

    let discovery = request(&app, "GET", "/api/registry/discovery").await;
    assert_eq!(discovery.0, StatusCode::OK);
    assert_eq!(discovery.1.as_array().unwrap().len(), 1);
    assert_eq!(
        discovery.1[0]["source_registry_url"].as_str(),
        Some(format!("http://{addr}/api/registry/gateways").as_str())
    );
    assert_eq!(
        discovery.1[0]["gateway"]["gateway_id"].as_str(),
        Some("gw-remote-1")
    );

    server.abort();
    db.cleanup().await;
}

#[tokio::test]
async fn public_queries_federate_configured_peer_gateways() {
    let db = TestDatabase::new().await;
    let remote_requests = Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));
    let remote_app = Router::new()
        .route(
            "/api/network/status",
            get({
                let remote_requests = Arc::clone(&remote_requests);
                move |uri: OriginalUri| {
                    record_federated_request(
                        uri,
                        Arc::clone(&remote_requests),
                        json!({
                            "status": "ok",
                            "nodes": 3,
                            "peers": 4,
                            "tasks": 1,
                            "organizations": 0,
                            "topics": 1,
                            "topic_messages": 0,
                            "public_blocks": 0,
                            "network_name": "Watt Etheria",
                            "network_org_name": "Aether Prime"
                        }),
                    )
                }
            }),
        )
        .route(
            "/api/network/nodes",
            get({
                let remote_requests = Arc::clone(&remote_requests);
                move |uri: OriginalUri| {
                    record_federated_request(
                        uri,
                        Arc::clone(&remote_requests),
                        json!([{
                            "node_id": "remote-node",
                            "lat": 1.0,
                            "lng": 2.0,
                            "snapshot_generated_at": 1_710_000_100
                        }]),
                    )
                }
            }),
        )
        .route(
            "/api/peers",
            get({
                let remote_requests = Arc::clone(&remote_requests);
                move |uri: OriginalUri| {
                    record_federated_request(
                        uri,
                        Arc::clone(&remote_requests),
                        json!([{"id": "remote-peer"}]),
                    )
                }
            }),
        )
        .route(
            "/api/hives",
            get({
                let remote_requests = Arc::clone(&remote_requests);
                move |uri: OriginalUri| {
                    record_federated_request(
                        uri,
                        Arc::clone(&remote_requests),
                        json!([{
                            "topic_id": "remote-hive",
                            "title": "Remote Hive",
                            "last_message_at": "2026-03-18T02:00:00Z"
                        }]),
                    )
                }
            }),
        )
        .route(
            "/api/missions",
            get({
                let remote_requests = Arc::clone(&remote_requests);
                move |uri: OriginalUri| {
                    record_federated_request(
                        uri,
                        Arc::clone(&remote_requests),
                        json!([{
                            "id": "remote-mission",
                            "title": "Remote Mission",
                            "updated_at": "2026-03-18T02:00:00Z"
                        }]),
                    )
                }
            }),
        )
        .route(
            "/api/leaderboard",
            get({
                let remote_requests = Arc::clone(&remote_requests);
                move |uri: OriginalUri| {
                    record_federated_request(
                        uri,
                        Arc::clone(&remote_requests),
                        json!([{
                            "agent_did": "remote-agent",
                            "score": 7
                        }]),
                    )
                }
            }),
        );
    let remote_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote_addr = remote_listener.local_addr().unwrap();
    let remote_server = tokio::spawn(async move {
        axum::serve(remote_listener, remote_app).await.unwrap();
    });

    let app = test_app_with_identity_and_federation_peers(
        &db.database_url,
        vec![format!("http://{remote_addr}")],
    )
    .await;

    let snapshot = signed_snapshot(
        "node-local-fed",
        SnapshotContents {
            network_name: Some("Watt Etheria"),
            network_org_name: Some("Aether Prime"),
            peers: &[json!({"id":"local-peer","lat":-30.0,"lng":151.0})],
            public_blocks: &[],
            public_topics: &[json!({
                "topic_id":"local-hive",
                "title":"Local Hive",
                "last_message_at":"2026-03-18T01:00:00Z"
            })],
            public_topic_messages: &[],
            swarm_task_activity: json!({}),
            tasks: &[json!({
                "id":"local-mission",
                "title":"Local Mission",
                "updated_at":"2026-03-18T01:00:00Z"
            })],
            organizations: &[],
            leaderboard: &[json!({"agent_did":"local-agent","score":9})],
        },
    );
    let ingest = request_json(
        &app,
        "POST",
        "/api/ingest/snapshot",
        serde_json::to_value(&snapshot).unwrap(),
    )
    .await;
    assert_eq!(ingest.0, StatusCode::OK);

    let status = request(&app, "GET", "/api/network/status").await;
    assert_eq!(status.0, StatusCode::OK);
    assert_eq!(status.1["nodes"].as_u64(), Some(4));
    assert_eq!(status.1["peers"].as_u64(), Some(5));
    assert_eq!(status.1["tasks"].as_u64(), Some(2));
    assert_eq!(status.1["topics"].as_u64(), Some(2));
    assert_eq!(status.1["federated_gateways"].as_u64(), Some(1));

    let peers = request(&app, "GET", "/api/peers?limit=10").await;
    assert_eq!(peers.0, StatusCode::OK);
    assert_contains_id(&peers.1, "id", "local-peer");
    assert_contains_id(&peers.1, "id", "remote-peer");

    let nodes = request(&app, "GET", "/api/network/nodes?limit=10").await;
    assert_eq!(nodes.0, StatusCode::OK);
    assert_contains_id(&nodes.1, "node_id", "local-peer");
    assert_contains_id(&nodes.1, "node_id", "remote-node");

    let missions = request(&app, "GET", "/api/missions?limit=10").await;
    assert_eq!(missions.0, StatusCode::OK);
    assert_contains_id(&missions.1, "id", "local-mission");
    assert_contains_id(&missions.1, "id", "remote-mission");

    let hives = request(&app, "GET", "/api/hives?limit=10").await;
    assert_eq!(hives.0, StatusCode::OK);
    assert_contains_id(&hives.1, "topic_id", "local-hive");
    assert_contains_id(&hives.1, "topic_id", "remote-hive");

    let leaderboard = request(&app, "GET", "/api/leaderboard?limit=10").await;
    assert_eq!(leaderboard.0, StatusCode::OK);
    assert_contains_id(&leaderboard.1, "agent_did", "local-agent");
    assert_contains_id(&leaderboard.1, "agent_did", "remote-agent");

    let seen_requests = remote_requests.lock().await.clone();
    for endpoint in [
        "/api/network/status",
        "/api/network/nodes",
        "/api/peers",
        "/api/hives",
        "/api/missions",
        "/api/leaderboard",
    ] {
        assert!(
            seen_requests
                .iter()
                .any(|uri| uri.starts_with(endpoint) && uri.contains("federation=local")),
            "remote request for {endpoint} should include federation=local; seen {seen_requests:?}"
        );
    }

    remote_requests.lock().await.clear();
    let local_only = request(&app, "GET", "/api/missions?limit=10&federation=local").await;
    assert_eq!(local_only.0, StatusCode::OK);
    assert_eq!(local_only.1.as_array().unwrap().len(), 1);
    assert_contains_id(&local_only.1, "id", "local-mission");
    assert!(remote_requests.lock().await.is_empty());

    remote_server.abort();
    db.cleanup().await;
}

#[tokio::test]
async fn trusted_federation_ignores_registry_only_gateways() {
    let db = TestDatabase::new().await;
    let remote_requests = Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));
    let remote_app = Router::new().route(
        "/api/missions",
        get({
            let remote_requests = Arc::clone(&remote_requests);
            move |uri: OriginalUri| {
                record_federated_request(
                    uri,
                    Arc::clone(&remote_requests),
                    json!([{"id": "remote-mission"}]),
                )
            }
        }),
    );
    let remote_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote_addr = remote_listener.local_addr().unwrap();
    let remote_server = tokio::spawn(async move {
        axum::serve(remote_listener, remote_app).await.unwrap();
    });

    let app = test_app_with_identity_and_federation_peers(&db.database_url, Vec::new()).await;
    let manifest = signed_gateway_manifest(
        "gw-registry-only",
        &format!("http://{remote_addr}"),
        "global",
    );
    let register = request_json(
        &app,
        "POST",
        "/api/registry/gateways/register",
        json!({ "manifest": manifest }),
    )
    .await;
    assert_eq!(register.0, StatusCode::CREATED);
    let review = request_json_with_auth(
        &app,
        "POST",
        "/api/admin/registry/gateways/gw-registry-only/review",
        json!({
            "status": "approved",
            "discovery_tier": "verified"
        }),
        Some("registry-secret"),
    )
    .await;
    assert_eq!(review.0, StatusCode::OK);

    let missions = request(&app, "GET", "/api/missions?limit=10").await;
    assert_eq!(missions.0, StatusCode::OK);
    assert!(missions.1.as_array().unwrap().is_empty());
    assert!(remote_requests.lock().await.is_empty());

    remote_server.abort();
    db.cleanup().await;
}

#[tokio::test]
async fn register_node_persists_transport_material_and_routes() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;

    let register = request_json(
        &app,
        "POST",
        "/api/nodes/register",
        json!({
            "name": "alpha",
            "export_url": "https://alpha.example/v1/wattetheria/client/export",
            "transport_capabilities": PeerTransportCapabilities::iroh_direct_default(),
            "transport_contact_material": {
                "transport": "iroh_direct",
                "peer_id": "12D3KooWQdummy",
                "metadata": {
                    "route": "iroh_direct",
                    "generated_at": 1710000000u64,
                    "endpoint_id": "dummy-endpoint",
                    "alpn": "/wattswarm/iroh/1",
                    "listen_addrs": ["127.0.0.1:0"],
                    "capabilities": PeerTransportCapabilities::iroh_direct_default()
                },
                "extra": {
                    "endpoint_id": "dummy-endpoint",
                    "alpn": "/wattswarm/iroh/1",
                    "direct_addrs": ["127.0.0.1:0"],
                    "relay_urls": []
                }
            }
        }),
    )
    .await;
    assert_eq!(register.0, StatusCode::CREATED);

    let nodes = request(&app, "GET", "/api/nodes").await;
    assert_eq!(nodes.0, StatusCode::OK);
    assert_eq!(
        nodes.1[0]["transport_capabilities"]["supports_iroh_direct"].as_bool(),
        Some(true)
    );
    assert_eq!(
        nodes.1[0]["recommended_routes"]["backfill_chunk"].as_str(),
        Some("iroh_direct")
    );

    db.cleanup().await;
}

#[tokio::test]
async fn network_status_includes_gateway_runtime_when_shared_p2p_is_enabled() {
    let db = TestDatabase::new().await;
    let (app, _runtime, _handle) = test_app_with_network(&db.database_url).await;

    let response = request(&app, "GET", "/api/network/status").await;
    assert_eq!(response.0, StatusCode::OK);
    assert_eq!(
        response.1["gateway_runtime"]["transport_capabilities"]["supports_iroh_direct"].as_bool(),
        Some(true)
    );
    assert!(response.1["gateway_runtime"]["peer_id"].as_str().is_some());

    db.cleanup().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_nodes_prefers_iroh_when_contact_material_and_snapshot_binding_exist() {
    let db = TestDatabase::new().await;
    let remote_state_dir = unique_state_dir("gateway-remote");
    let remote_runtime = GatewayNetworkRuntime::new(
        GatewayNetworkNode::generate(wattetheria_gateway::config::GatewayP2pConfig {
            enabled: true,
            state_dir: remote_state_dir.clone(),
            listen_addrs: vec!["127.0.0.1:0".to_string()],
            ..Default::default()
        })
        .unwrap(),
    )
    .unwrap();
    let remote_snapshot = signed_snapshot(
        "node-iroh",
        SnapshotContents {
            network_name: Some("Watt Etheria"),
            network_org_name: Some("Iroh Mesh"),
            peers: &[json!({"id":"peer-iroh"})],
            public_blocks: &[],
            public_topics: &[],
            public_topic_messages: &[],
            swarm_task_activity: json!({}),
            tasks: &[json!({"id":"task-iroh"})],
            organizations: &[],
            leaderboard: &[],
        },
    );
    gateway_network::persist_snapshot_artifact(remote_runtime.state_dir(), &remote_snapshot)
        .unwrap();
    let remote_contact = remote_runtime
        .export_transport_contact_material(chrono::Utc::now().timestamp() as u64)
        .unwrap();
    let (app, _local_runtime, local_handle) = test_app_with_network(&db.database_url).await;

    let register = request_json(
        &app,
        "POST",
        "/api/nodes/register",
        json!({
            "name": "iroh-source",
            "export_url": "http://127.0.0.1:9/v1/wattetheria/client/export",
            "transport_capabilities": PeerTransportCapabilities::iroh_direct_default(),
            "transport_contact_material": remote_contact,
        }),
    )
    .await;
    assert_eq!(register.0, StatusCode::CREATED);
    let source_id = uuid::Uuid::parse_str(register.1["source_id"].as_str().unwrap()).unwrap();

    let pool = db.pool().await;
    db::upsert_snapshot(
        &pool,
        UpsertSnapshotRecord {
            source_id: Some(source_id),
            node_id: "node-iroh",
            signer_agent_did: &remote_snapshot.signer_agent_did,
            public_key: &remote_snapshot.payload.public_key,
            generated_at: remote_snapshot.payload.generated_at - 1,
            payload: &serde_json::to_value(&remote_snapshot.payload).unwrap(),
            signature: "seed-signature",
        },
    )
    .await
    .unwrap();

    let sync = request_json(&app, "POST", "/api/nodes/sync", json!({})).await;
    assert_eq!(sync.0, StatusCode::OK);
    assert_eq!(sync.1.as_array().unwrap().len(), 1);
    assert_eq!(sync.1[0]["node_id"].as_str(), Some("node-iroh"));

    let tasks = request(&app, "GET", "/api/missions?limit=10").await;
    assert_eq!(tasks.0, StatusCode::OK);
    assert_eq!(tasks.1.as_array().unwrap().len(), 1);
    assert_eq!(tasks.1[0]["id"].as_str(), Some("task-iroh"));

    let artifact_store = ArtifactStore::new(local_handle.state_dir.join("artifacts"));
    let snapshot_path = artifact_store
        .snapshot_path(
            gateway_network::PUBLIC_CLIENT_SNAPSHOT_SCOPE,
            &remote_snapshot.payload.node_id,
        )
        .unwrap();
    assert!(snapshot_path.exists());

    drop(pool);
    drop(app);
    drop(remote_runtime);
    db.cleanup().await;
}

async fn test_app(database_url: &str) -> Router {
    let pool = db::connect(database_url).await.unwrap();
    db::init_schema(&pool).await.unwrap();
    let (ui_stream_tx, _) = tokio::sync::broadcast::channel(64);
    http::router(AppState {
        pool,
        node_client: NodeClient::new(5).unwrap(),
        registry_client: RegistryClient::new(5).unwrap(),
        nats: None,
        registry_admin_token: Some("registry-secret".to_string()),
        bootstrap_registry_urls: Vec::new(),
        gateway_identity: None,
        gateway_network: None,
        ui_stream_tx,
    })
}

async fn record_federated_request(
    uri: OriginalUri,
    requests: Arc<tokio::sync::Mutex<Vec<String>>>,
    payload: Value,
) -> Json<Value> {
    requests.lock().await.push(uri.0.to_string());
    Json(payload)
}

fn assert_contains_id(values: &Value, key: &str, expected: &str) {
    assert!(
        values
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value[key].as_str() == Some(expected)),
        "expected {key}={expected} in {values}"
    );
}

async fn test_app_with_identity(database_url: &str) -> Router {
    let pool = db::connect(database_url).await.unwrap();
    db::init_schema(&pool).await.unwrap();
    let (ui_stream_tx, _) = tokio::sync::broadcast::channel(64);
    let gateway_identity = test_gateway_identity(vec!["https://gw-us.example".to_string()]);
    http::router(AppState {
        pool,
        node_client: NodeClient::new(5).unwrap(),
        registry_client: RegistryClient::new(5).unwrap(),
        nats: None,
        registry_admin_token: Some("registry-secret".to_string()),
        bootstrap_registry_urls: Vec::new(),
        gateway_identity,
        gateway_network: None,
        ui_stream_tx,
    })
}

async fn test_app_with_identity_and_federation_peers(
    database_url: &str,
    federation_peers: Vec<String>,
) -> Router {
    let pool = db::connect(database_url).await.unwrap();
    db::init_schema(&pool).await.unwrap();
    let (ui_stream_tx, _) = tokio::sync::broadcast::channel(64);
    let gateway_identity = test_gateway_identity(federation_peers);
    http::router(AppState {
        pool,
        node_client: NodeClient::new(5).unwrap(),
        registry_client: RegistryClient::new(5).unwrap(),
        nats: None,
        registry_admin_token: Some("registry-secret".to_string()),
        bootstrap_registry_urls: Vec::new(),
        gateway_identity,
        gateway_network: None,
        ui_stream_tx,
    })
}

fn test_gateway_identity(federation_peers: Vec<String>) -> Option<GatewayIdentity> {
    GatewayIdentity::from_config(GatewayIdentityConfig {
        gateway_id: Some("gw-self-1".to_string()),
        display_name: Some("Self Gateway".to_string()),
        base_url: Some("https://gateway.self.example".to_string()),
        region: Some("ap-southeast".to_string()),
        operator_did: Some("did:key:operator-self".to_string()),
        roles: vec!["ingest".to_string(), "query".to_string()],
        supported_endpoints: vec!["/api/network/status".to_string()],
        federation_mode: Some("trusted".to_string()),
        federation_peers,
        allows_public_ingest: true,
        signing_key_b64: Some(base64::engine::general_purpose::STANDARD.encode([21_u8; 32])),
    })
    .unwrap()
}

async fn test_app_with_identity_and_bootstrap(
    database_url: &str,
    bootstrap_registry_urls: Vec<String>,
) -> Router {
    let pool = db::connect(database_url).await.unwrap();
    db::init_schema(&pool).await.unwrap();
    let (ui_stream_tx, _) = tokio::sync::broadcast::channel(64);
    let gateway_identity = GatewayIdentity::from_config(GatewayIdentityConfig {
        gateway_id: Some("gw-self-1".to_string()),
        display_name: Some("Self Gateway".to_string()),
        base_url: Some("https://gateway.self.example".to_string()),
        region: Some("ap-southeast".to_string()),
        operator_did: Some("did:key:operator-self".to_string()),
        roles: vec!["ingest".to_string(), "query".to_string()],
        supported_endpoints: vec!["/api/network/status".to_string()],
        federation_mode: None,
        federation_peers: vec!["https://gw-us.example".to_string()],
        allows_public_ingest: true,
        signing_key_b64: Some(base64::engine::general_purpose::STANDARD.encode([21_u8; 32])),
    })
    .unwrap();
    http::router(AppState {
        pool,
        node_client: NodeClient::new(5).unwrap(),
        registry_client: RegistryClient::new(5).unwrap(),
        nats: None,
        registry_admin_token: Some("registry-secret".to_string()),
        bootstrap_registry_urls,
        gateway_identity,
        gateway_network: None,
        ui_stream_tx,
    })
}

async fn test_app_with_network(
    database_url: &str,
) -> (Router, GatewayNetworkRuntime, GatewayNetworkHandle) {
    let pool = db::connect(database_url).await.unwrap();
    db::init_schema(&pool).await.unwrap();
    let (ui_stream_tx, _) = tokio::sync::broadcast::channel(64);
    let runtime = GatewayNetworkRuntime::new(
        GatewayNetworkNode::generate(wattetheria_gateway::config::GatewayP2pConfig {
            enabled: true,
            state_dir: unique_state_dir("gateway-local"),
            listen_addrs: vec!["127.0.0.1:0".to_string()],
            ..Default::default()
        })
        .unwrap(),
    )
    .unwrap();
    let gateway_network = runtime
        .export_handle(chrono::Utc::now().timestamp() as u64)
        .unwrap();
    let app = http::router(AppState {
        pool,
        node_client: NodeClient::new(5).unwrap(),
        registry_client: RegistryClient::new(5).unwrap(),
        nats: None,
        registry_admin_token: Some("registry-secret".to_string()),
        bootstrap_registry_urls: Vec::new(),
        gateway_identity: None,
        gateway_network: Some(gateway_network.clone()),
        ui_stream_tx,
    });
    (app, runtime, gateway_network)
}

fn unique_state_dir(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4().simple()))
}

async fn request(app: &Router, method: &str, uri: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

async fn request_status(app: &Router, method: &str, uri: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

async fn request_json(app: &Router, method: &str, uri: &str, body: Value) -> (StatusCode, Value) {
    request_json_with_auth(app, method, uri, body, None).await
}

async fn request_json_with_auth(
    app: &Router,
    method: &str,
    uri: &str,
    body: Value,
    bearer_token: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(token) = bearer_token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

struct MockExportServer {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl MockExportServer {
    async fn spawn(snapshot: SignedPublicClientSnapshot) -> Self {
        let app = Router::new().route(
            "/v1/wattetheria/client/export",
            get({
                let snapshot = snapshot.clone();
                move || async move { Json(snapshot.clone()) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let export_url = format!("http://{addr}/v1/wattetheria/client/export");
        let client = reqwest::Client::new();
        for _ in 0..20 {
            if client.get(&export_url).send().await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        Self { addr, task }
    }

    fn export_url(&self) -> String {
        format!("http://{}/v1/wattetheria/client/export", self.addr)
    }

    fn abort(self) {
        self.task.abort();
    }
}

struct MockWattswarmReadModelServer {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl MockWattswarmReadModelServer {
    async fn spawn() -> Self {
        let app = Router::new().route(
            "/api/wattetheria/network/snapshot",
            get(|| async {
                Json(json!({
                    "generated_at": 1_778_000_000_u64,
                    "node_id": "wattswarm-node-1",
                    "display_name": "Wattswarm Node",
                    "org_id": "org-1",
                    "network_id": "net-1",
                    "running": true,
                    "mode": "network",
                    "peer_protocol_distribution": {},
                    "peers": []
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let network_url = format!("http://{addr}/api/wattetheria/network/snapshot");
        let client = reqwest::Client::new();
        for _ in 0..20 {
            if client.get(&network_url).send().await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        Self { addr, task }
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn abort(self) {
        self.task.abort();
    }
}

struct TestDatabase {
    database_url: String,
    admin_url: String,
    database_name: String,
}

impl TestDatabase {
    async fn new() -> Self {
        ensure_postgres().await;
        let base_url = test_database_url();
        let admin_url = admin_database_url(&base_url);
        let database_name = format!("wattetheria_gateway_test_{}", uuid::Uuid::new_v4().simple());
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&admin_url)
            .await
            .unwrap();
        sqlx::query(&format!(r#"create database "{}""#, database_name))
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        Self {
            database_url: database_url_for_name(&base_url, &database_name),
            admin_url,
            database_name,
        }
    }

    async fn pool(&self) -> sqlx::PgPool {
        db::connect(&self.database_url).await.unwrap()
    }

    async fn cleanup(self) {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&self.admin_url)
            .await
            .unwrap();
        sqlx::query(
            r#"
            select pg_terminate_backend(pid)
            from pg_stat_activity
            where datname = $1 and pid <> pg_backend_pid()
            "#,
        )
        .bind(&self.database_name)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(&format!(
            r#"drop database if exists "{}""#,
            self.database_name
        ))
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;
    }
}

async fn ensure_postgres() {
    POSTGRES_READY.get_or_init(|| {
        let status = Command::new("docker")
            .args(["compose", "up", "-d", "postgres"])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .status()
            .expect("run docker compose up -d postgres");
        assert!(status.success(), "postgres compose service failed to start");
    });

    let admin_url = admin_database_url(&test_database_url());
    for _ in 0..30 {
        if PgPoolOptions::new()
            .max_connections(1)
            .connect(&admin_url)
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    panic!("postgres test dependency did not become ready");
}

fn test_database_url() -> String {
    std::env::var("WATTETHERIA_GATEWAY_TEST_DATABASE_URL").unwrap_or_else(|_| {
        "postgres://postgres:postgres@127.0.0.1:55434/wattetheria_gateway".to_string()
    })
}

fn database_url_for_name(base_url: &str, database_name: &str) -> String {
    let mut options = PgConnectOptions::from_str(base_url).unwrap();
    options = options.database(database_name);
    options.to_url_lossy().to_string()
}

fn admin_database_url(base_url: &str) -> String {
    let mut options = PgConnectOptions::from_str(base_url).unwrap();
    options = options.database("postgres");
    options.to_url_lossy().to_string()
}

struct SnapshotContents<'a> {
    network_name: Option<&'a str>,
    network_org_name: Option<&'a str>,
    peers: &'a [Value],
    public_blocks: &'a [Value],
    public_topics: &'a [Value],
    public_topic_messages: &'a [Value],
    swarm_task_activity: Value,
    tasks: &'a [Value],
    organizations: &'a [Value],
    leaderboard: &'a [Value],
}

fn signed_snapshot(node_id: &str, contents: SnapshotContents<'_>) -> SignedPublicClientSnapshot {
    signed_snapshot_at(node_id, 1_710_000_000, contents)
}

fn signed_snapshot_at(
    node_id: &str,
    generated_at: i64,
    contents: SnapshotContents<'_>,
) -> SignedPublicClientSnapshot {
    let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
    let public_key =
        base64::engine::general_purpose::STANDARD.encode(signing_key.verifying_key().as_bytes());
    let payload = PublicClientSnapshot {
        generated_at,
        node_id: node_id.to_string(),
        public_key: public_key.clone(),
        network_name: contents.network_name.map(str::to_string),
        network_org_name: contents.network_org_name.map(str::to_string),
        network_status: json!({
            "total_nodes": contents.peers.len() + 1,
            "active_nodes": contents.peers.len() + 1,
            "health_percent": 100,
            "avg_latency_ms": 0
        }),
        peers: contents.peers.to_vec(),
        operator: json!({
            "id": "agent-root",
            "display_name": "Agent Root",
            "watt_balance": 42
        }),
        rpc_logs: vec![
            json!({"timestamp":"2026-03-18T00:00:00Z","message":"Agent connected","level":"success"}),
        ],
        public_blocks: contents.public_blocks.to_vec(),
        public_topics: contents.public_topics.to_vec(),
        public_topic_messages: contents.public_topic_messages.to_vec(),
        swarm_task_activity: contents.swarm_task_activity,
        tasks: contents.tasks.to_vec(),
        organizations: contents.organizations.to_vec(),
        leaderboard: contents.leaderboard.to_vec(),
    };
    let signature = base64::engine::general_purpose::STANDARD.encode(
        signing_key
            .sign(&canonical_bytes(&payload).unwrap())
            .to_bytes(),
    );
    SignedPublicClientSnapshot {
        payload,
        signature,
        signer_agent_did: did_key_from_public_key_b64(&public_key),
    }
}

fn signed_gateway_manifest(
    gateway_id: &str,
    base_url: &str,
    region: &str,
) -> SignedGatewayManifest {
    let signing_key = SigningKey::from_bytes(&[13_u8; 32]);
    let public_key =
        base64::engine::general_purpose::STANDARD.encode(signing_key.verifying_key().as_bytes());
    let payload = GatewayManifest {
        generated_at: 1_710_000_000,
        gateway_id: gateway_id.to_string(),
        display_name: format!("Gateway {gateway_id}"),
        base_url: base_url.to_string(),
        public_key,
        region: Some(region.to_string()),
        operator_did: Some("did:key:operator-root".to_string()),
        roles: vec![
            "ingest".to_string(),
            "query".to_string(),
            "federation".to_string(),
        ],
        supported_endpoints: vec![
            "/api/network/status".to_string(),
            "/api/network/nodes".to_string(),
            "/api/peers".to_string(),
            "/api/hives".to_string(),
            "/api/missions".to_string(),
            "/api/leaderboard".to_string(),
            "/api/registry/gateways".to_string(),
        ],
        federation_peers: vec![],
        allows_public_ingest: true,
    };
    let signature = base64::engine::general_purpose::STANDARD.encode(
        signing_key
            .sign(&canonical_bytes(&payload).unwrap())
            .to_bytes(),
    );
    SignedGatewayManifest { payload, signature }
}

fn signed_node_event(
    node_id: &str,
    data_kind: DataKind,
    event_kind: &str,
    payload: Value,
) -> SignedNodeEvent {
    let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
    let public_key =
        base64::engine::general_purpose::STANDARD.encode(signing_key.verifying_key().as_bytes());
    let payload = NodeEventPayload {
        event_id: format!("{node_id}:1"),
        node_id: node_id.to_string(),
        public_key: public_key.clone(),
        signer_agent_did: did_key_from_public_key_b64(&public_key),
        seq: 1,
        timestamp: 1_710_000_000,
        data_kind,
        event_kind: event_kind.to_string(),
        visibility: Visibility::Public,
        provisional_policy: ProvisionalExportPolicy::ProvisionalWithDowngrade,
        scope: EventScope {
            node_id: Some(node_id.to_string()),
            topic_id: None,
            organization_id: None,
            task_id: Some("task-hidden".to_string()),
        },
        identity_key: Some("task-hidden".to_string()),
        payload,
    };
    let signature = base64::engine::general_purpose::STANDARD.encode(
        signing_key
            .sign(&canonical_bytes(&payload).unwrap())
            .to_bytes(),
    );
    SignedNodeEvent { payload, signature }
}

fn resign_node_event(event: &mut SignedNodeEvent) {
    let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
    event.signature = base64::engine::general_purpose::STANDARD.encode(
        signing_key
            .sign(&canonical_bytes(&event.payload).unwrap())
            .to_bytes(),
    );
}

fn did_key_from_public_key_b64(public_key_b64: &str) -> String {
    const DID_KEY_PREFIX: &str = "did:key:";
    const DID_KEY_BASE58BTC_PREFIX: &str = "z";
    const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];

    let public_key = base64::engine::general_purpose::STANDARD
        .decode(public_key_b64)
        .unwrap();
    let mut multicodec = Vec::with_capacity(ED25519_MULTICODEC_PREFIX.len() + public_key.len());
    multicodec.extend_from_slice(&ED25519_MULTICODEC_PREFIX);
    multicodec.extend_from_slice(&public_key);
    format!(
        "{DID_KEY_PREFIX}{DID_KEY_BASE58BTC_PREFIX}{}",
        bs58::encode(multicodec).into_string()
    )
}
