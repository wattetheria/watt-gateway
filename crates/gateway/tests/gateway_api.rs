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
use std::path::Path;
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
use wattetheria_gateway::gateway_sync::GatewayP2pSyncCommand;
use wattetheria_gateway::http;
use wattetheria_gateway::models::{
    GatewayManifest, PublicClientSnapshot, SignedGatewayManifest, SignedPublicClientSnapshot,
};
use wattetheria_gateway::node_client::NodeClient;
use wattetheria_gateway::registry_client::RegistryClient;
use wattetheria_gateway::state::{AppState, UiStreamHub};
use wattetheria_gateway::verify::{canonical_bytes, verify_signed_gateway_manifest};
use wattswarm_artifact_store::ArtifactStore;
use wattswarm_network_transport_core::{PeerTransportCapabilities, TransportContactMaterial};

static POSTGRES_READY: OnceLock<()> = OnceLock::new();

#[tokio::test]
async fn space_presence_snapshot_requires_current_heartbeat_from_record_source() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;
    let presence = signed_space_presence(10, "signed resident");
    let did = &presence.record.agent_did;
    let list_path = "/api/spaces/presence?network_id=test-network&space_id=the-ville";
    let raw_path =
        format!("/api/spaces/presence/{did}/record?network_id=test-network&space_id=the-ville");
    let response = request_json(
        &app,
        "POST",
        "/api/ingest/event",
        json!(space_node_event("record-source", 1, &presence)),
    )
    .await;
    assert_eq!(response.0, StatusCode::OK, "{}", response.1);
    assert_eq!(
        request(&app, "GET", list_path).await.1["presences"],
        json!([])
    );
    assert_eq!(request(&app, "GET", &raw_path).await.1, json!(presence));

    let pool = db.pool().await;
    let persisted_before: (String, String, String) = sqlx::query_as(
        "select payload::text,seq::text,source_node_id from gateway_space_presence where network_id='test-network' and space_id='the-ville' and agent_did=$1",
    )
    .bind(did)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(persisted_before.1, "10");
    assert_eq!(persisted_before.2, "record-source");
    let now = chrono::Utc::now().timestamp_millis();
    ingest_space_heartbeat(
        &app,
        "record-source",
        &SigningKey::from_bytes(&[11_u8; 32]),
        now,
    )
    .await;
    ingest_space_heartbeat(
        &app,
        "other-source",
        &SigningKey::from_bytes(&[19_u8; 32]),
        now,
    )
    .await;
    assert_eq!(
        request(&app, "GET", list_path).await.1["presences"],
        json!([])
    );

    let expired = signed_space_heartbeat(
        "record-source",
        &SigningKey::from_bytes(&[19_u8; 32]),
        now - 61_000,
        20,
    );
    let response = request_json(&app, "POST", "/api/ingest/event", json!(expired)).await;
    assert_eq!(response.0, StatusCode::OK, "{}", response.1);
    assert_eq!(
        request(&app, "GET", list_path).await.1["presences"],
        json!([])
    );

    ingest_space_heartbeat(
        &app,
        "record-source",
        &SigningKey::from_bytes(&[19_u8; 32]),
        now,
    )
    .await;
    let visible = request(&app, "GET", list_path).await;
    assert_eq!(visible.0, StatusCode::OK);
    assert_eq!(visible.1["presences"], json!([presence]));
    assert_eq!(
        visible.1["identities"],
        json!([{"network_id":"test-network","agent_did":did,"node_id":"record-source","display_name":null}])
    );
    assert!(
        visible.1["node_presences"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| {
                item["node_id"] == "record-source" && item["agent_did"] == did.as_str()
            })
    );
    assert_eq!(visible.1["presences"][0]["signature"], presence.signature);
    assert_eq!(visible.1["presences"][0]["record"]["seq"], 10);
    let persisted_after: (String, String, String) = sqlx::query_as(
        "select payload::text,seq::text,source_node_id from gateway_space_presence where network_id='test-network' and space_id='the-ville' and agent_did=$1",
    )
    .bind(did)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        persisted_after, persisted_before,
        "heartbeat recovery must not rewrite the signed record or sequence"
    );
    assert_eq!(request(&app, "GET", &raw_path).await.1, json!(presence));

    let mut inactive = presence.clone();
    inactive.record.seq = 11;
    inactive.record.entered = false;
    resign_space_presence(&mut inactive);
    let response = request_json(
        &app,
        "POST",
        "/api/ingest/event",
        json!(space_node_event("tombstone-source", 1, &inactive)),
    )
    .await;
    assert_eq!(response.0, StatusCode::OK, "{}", response.1);
    ingest_space_heartbeat(
        &app,
        "tombstone-source",
        &SigningKey::from_bytes(&[19_u8; 32]),
        now,
    )
    .await;
    let absent = request(&app, "GET", list_path).await;
    assert_eq!(absent.1["presences"], json!([]));
    assert_eq!(absent.1["identities"], json!([]));
    assert_eq!(request(&app, "GET", &raw_path).await.1, json!(inactive));
    pool.close().await;
    db.cleanup().await;
}

#[tokio::test]
async fn space_entered_tombstone_uses_existing_sequence_and_survives_replay() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;
    let active = signed_space_presence(10, "preserved activity");
    let path = format!(
        "/api/spaces/presence/{}?network_id=test-network&space_id=the-ville",
        active.record.agent_did
    );
    let raw_path = format!(
        "/api/spaces/presence/{}/record?network_id=test-network&space_id=the-ville",
        active.record.agent_did
    );
    assert_eq!(
        request_json(
            &app,
            "POST",
            "/api/ingest/event",
            json!(space_node_event("entered-node", 1, &active))
        )
        .await
        .0,
        StatusCode::OK
    );
    ingest_space_heartbeat(
        &app,
        "entered-node",
        &SigningKey::from_bytes(&[19_u8; 32]),
        chrono::Utc::now().timestamp_millis(),
    )
    .await;
    assert_eq!(request(&app, "GET", &path).await.0, StatusCode::OK);
    let mut inactive = active.clone();
    inactive.record.seq += 1;
    inactive.record.entered = false;
    resign_space_presence(&mut inactive);
    assert_eq!(
        request_json(
            &app,
            "POST",
            "/api/ingest/event",
            json!(space_node_event("entered-node", 2, &inactive))
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(request(&app, "GET", &path).await.0, StatusCode::NOT_FOUND);
    assert_eq!(request(&app, "GET", &raw_path).await.1, json!(inactive));
    assert_eq!(
        request(
            &app,
            "GET",
            "/api/spaces/presence?network_id=test-network&space_id=the-ville"
        )
        .await
        .1["presences"],
        json!([]),
        "inactive latest declaration must not appear in the resident snapshot"
    );
    let mut equal_sequence = active.clone();
    equal_sequence.record.seq = inactive.record.seq;
    resign_space_presence(&mut equal_sequence);
    for (index, replay) in [&active, &equal_sequence].into_iter().enumerate() {
        let event = space_node_event(&format!("replayed-node-{index}"), 1, replay);
        assert_eq!(
            request_json(&app, "POST", "/api/ingest/event", json!(event))
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(request(&app, "GET", &raw_path).await.1, json!(inactive));
    }
    let mut snapshot = signed_snapshot(
        "replayed-snapshot-node",
        SnapshotContents {
            network_name: None,
            network_org_name: None,
            peers: &[],
            public_blocks: &[],
            public_topics: &[],
            public_topic_messages: &[],
            swarm_task_activity: json!({}),
            tasks: &[],
            organizations: &[],
            leaderboard: &[],
        },
    );
    snapshot.payload.space_presences = vec![active.clone()];
    resign_snapshot(&mut snapshot);
    assert_eq!(
        request_json(&app, "POST", "/api/ingest/snapshot", json!(snapshot))
            .await
            .0,
        StatusCode::OK
    );
    ingest_space_heartbeat(
        &app,
        "entered-node",
        &SigningKey::from_bytes(&[19_u8; 32]),
        chrono::Utc::now().timestamp_millis(),
    )
    .await;
    assert_eq!(request(&app, "GET", &path).await.0, StatusCode::NOT_FOUND);
    assert_eq!(request(&app, "GET", &raw_path).await.1, json!(inactive));
    let pool = db.pool().await;
    db::init_schema(&pool).await.unwrap();
    db::init_schema(&pool).await.unwrap();
    assert_eq!(request(&app, "GET", &raw_path).await.1, json!(inactive));
    let mut reentered = inactive.clone();
    reentered.record.seq += 1;
    reentered.record.entered = true;
    resign_space_presence(&mut reentered);
    assert_eq!(
        request_json(
            &app,
            "POST",
            "/api/ingest/event",
            json!(space_node_event("entered-node", 3, &reentered))
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        request(&app, "GET", &path).await.1["presence"],
        json!(reentered)
    );
    assert_eq!(reentered.record.from_tile, active.record.from_tile);
    assert_eq!(reentered.record.activity, active.record.activity);
    pool.close().await;
    db.cleanup().await;
}

#[test]
fn space_legacy_signed_record_missing_entered_keeps_signature_and_defaults_inactive() {
    let presence = signed_space_presence(100, "legacy activity");
    let mut raw = json!(presence);
    raw["record"].as_object_mut().unwrap().remove("entered");
    raw["record"].as_object_mut().unwrap().remove("network_id");
    let key = SigningKey::from_bytes(&[19_u8; 32]);
    raw["signature"] = json!(
        base64::engine::general_purpose::STANDARD.encode(
            key.sign(&canonical_bytes(&raw["record"]).unwrap())
                .to_bytes()
        )
    );
    let decoded: wattetheria_gateway_contract::SignedSpacePresence =
        serde_json::from_value(raw.clone()).unwrap();
    assert!(!decoded.record.entered);
    wattetheria_gateway::verify::verify_signed_space_presence(&decoded).unwrap();
    assert_eq!(json!(decoded), raw);
}

#[tokio::test]
async fn space_sequence_record_retains_old_inactive_floor_and_strict_updates() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;
    let pool = db.pool().await;
    let source_id = uuid::Uuid::new_v4();
    sqlx::query("insert into node_sources(id,name,export_url,source_status) values($1,'retired source','http://127.0.0.1/retired','suspended')")
        .bind(source_id).execute(&pool).await.unwrap();
    let mut old = signed_space_presence(u64::MAX - 2, "retained old activity");
    old.record.space_version = "retained-old-map".to_owned();
    resign_space_presence(&mut old);
    sqlx::query("insert into gateway_space_presence(network_id,space_id,agent_did,seq,source_node_id,source_id,payload) values('test-network',$1,$2,$3::text::numeric,'retired-node',$4,$5)")
        .bind(&old.record.space_id).bind(&old.record.agent_did).bind(old.record.seq.to_string())
        .bind(source_id).bind(sqlx::types::Json(&old)).execute(&pool).await.unwrap();
    let path = format!(
        "/api/spaces/presence/{}/record?network_id=test-network&space_id=the-ville",
        old.record.agent_did
    );
    let raw = request(&app, "GET", &path).await;
    assert_eq!(raw.0, StatusCode::OK);
    assert_eq!(raw.1, json!(old));
    assert_eq!(
        request(
            &app,
            "GET",
            "/api/spaces/presence?network_id=test-network&space_id=the-ville"
        )
        .await
        .1["presences"],
        json!([])
    );
    assert_eq!(
        request(
            &app,
            "GET",
            &format!(
                "/api/spaces/presence/{}?network_id=test-network&space_id=the-ville",
                old.record.agent_did
            )
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(
            &app,
            "GET",
            "/api/spaces/presence/did:key:another-agent/record?network_id=test-network&space_id=the-ville"
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(&app, "GET", &path.replace("the-ville", "other-space"))
            .await
            .0,
        StatusCode::NOT_FOUND
    );

    let current = signed_space_presence(u64::MAX - 1, "recovered current activity");
    let accepted = space_node_event("recovered-node", 1, &current);
    let response = request_json(&app, "POST", "/api/ingest/event", json!(accepted)).await;
    assert_eq!(response.0, StatusCode::OK, "{}", response.1);
    ingest_space_heartbeat(
        &app,
        "recovered-node",
        &SigningKey::from_bytes(&[19_u8; 32]),
        chrono::Utc::now().timestamp_millis(),
    )
    .await;
    assert_eq!(request(&app, "GET", &path).await.1, json!(current));
    assert_eq!(
        request(
            &app,
            "GET",
            "/api/spaces/presence?network_id=test-network&space_id=the-ville"
        )
        .await
        .1["presences"],
        json!([current])
    );
    for (index, seq) in [u64::MAX - 1, u64::MAX - 3].into_iter().enumerate() {
        let stale = signed_space_presence(seq, "must not overwrite recovered current");
        let event = space_node_event(&format!("stale-node-{index}"), 1, &stale);
        assert_eq!(
            request_json(&app, "POST", "/api/ingest/event", json!(event))
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(request(&app, "GET", &path).await.1, json!(current));
    }
    let mut bad = signed_space_presence(u64::MAX, "signed before tampering");
    bad.record.activity = "invalid inner signature".to_owned();
    let bad = space_node_event("invalid-inner-node", 1, &bad);
    assert_eq!(
        request_json(&app, "POST", "/api/ingest/event", json!(bad))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(request(&app, "GET", &path).await.1, json!(current));
    let mut current_inactive = current.clone();
    current_inactive.record.seq = u64::MAX;
    resign_space_presence(&mut current_inactive);
    sqlx::query("update gateway_space_presence set source_id=$1,seq=$2::text::numeric,payload=$3")
        .bind(source_id)
        .bind(current_inactive.record.seq.to_string())
        .bind(sqlx::types::Json(&current_inactive))
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(request(&app, "GET", &path).await.1, json!(current_inactive));
    assert_eq!(
        request(
            &app,
            "GET",
            "/api/spaces/presence?network_id=test-network&space_id=the-ville"
        )
        .await
        .1["presences"],
        json!([])
    );
    pool.close().await;
    db.cleanup().await;
}

#[tokio::test]
async fn space_activity_limit_is_identical_for_gateway_signed_records() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;
    let accepted = signed_space_presence(1, &"界".repeat(2000));
    let event = space_node_event("activity-limit-valid", 1, &accepted);
    assert_eq!(
        request_json(&app, "POST", "/api/ingest/event", json!(event))
            .await
            .0,
        StatusCode::OK
    );
    ingest_space_heartbeat(
        &app,
        "activity-limit-valid",
        &SigningKey::from_bytes(&[19_u8; 32]),
        chrono::Utc::now().timestamp_millis(),
    )
    .await;
    for (index, activity) in ["界".repeat(2001), "bad\u{0007}control".to_owned()]
        .into_iter()
        .enumerate()
    {
        let invalid = signed_space_presence(2, &activity);
        let event = space_node_event(&format!("activity-limit-invalid-{index}"), 1, &invalid);
        assert_eq!(
            request_json(&app, "POST", "/api/ingest/event", json!(event))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        request(
            &app,
            "GET",
            "/api/spaces/presence?network_id=test-network&space_id=the-ville"
        )
        .await
        .1["presences"],
        json!([accepted])
    );
    drop(app);
    db.cleanup().await;
}

#[tokio::test]
async fn captured_production_heartbeat_is_ephemeral_and_updates_only_the_latest_proof() {
    let event: SignedNodeEvent = serde_json::from_str(r#"{"payload":{"event_id":"did:key:z6MkuYnqQgqL5V2FTyze9przT6FVSuLLCjivtVsMCT4YDSGL:1791849137537","node_id":"did:key:z6MkuYnqQgqL5V2FTyze9przT6FVSuLLCjivtVsMCT4YDSGL","public_key":"4EoFsyOBOwCrF6R8zhFon9+IONr98pbl74CKEYHWEa0=","signer_agent_did":"did:key:z6MkuYnqQgqL5V2FTyze9przT6FVSuLLCjivtVsMCT4YDSGL","seq":1791849137537,"timestamp":1791849177,"data_kind":"presence","event_kind":"node.presence.heartbeat","visibility":"public","provisional_policy":"ephemeral_only","scope":{"node_id":"did:key:z6MkuYnqQgqL5V2FTyze9przT6FVSuLLCjivtVsMCT4YDSGL"},"identity_key":"did:key:z6MkuYnqQgqL5V2FTyze9przT6FVSuLLCjivtVsMCT4YDSGL","payload":{"agent_did":"did:key:z6MkuYnqQgqL5V2FTyze9przT6FVSuLLCjivtVsMCT4YDSGL","heartbeat_interval_sec":20,"last_heartbeat_ms":1791849177000,"node_id":"did:key:z6MkuYnqQgqL5V2FTyze9przT6FVSuLLCjivtVsMCT4YDSGL"}},"signature":"cbbH7vSjfni/IhvYqVjYqqebV9je2m1abh9HS0hM/OP/vgucPrnGCeoQMtQ51YQOOwULOurFieaDMBFH/FTLDA=="}"#).unwrap();
    assert_eq!(
        event.payload.provisional_policy,
        ProvisionalExportPolicy::EphemeralOnly
    );
    let db = TestDatabase::new().await;
    let pool = db.pool().await;
    db::init_schema(&pool).await.unwrap();
    let (sender, _) = tokio::sync::broadcast::channel(64);
    let state = AppState {
        pool: pool.clone(),
        node_client: NodeClient::new(5).unwrap(),
        registry_client: RegistryClient::new(5).unwrap(),
        nats: None,
        registry_admin_token: None,
        bootstrap_registry_urls: vec![],
        gateway_identity: None,
        gateway_network: None,
        gateway_sync_tx: None,
        ui_stream_tx: UiStreamHub::new(sender),
    };
    let mut receiver = state.ui_stream_tx.subscribe(Some(DataKind::Presence));
    let app = http::router(state);
    assert_eq!(
        request_json(&app, "POST", "/api/ingest/event", json!(event))
            .await
            .0,
        StatusCode::OK
    );
    let frame = receiver.try_recv().unwrap();
    assert_eq!(frame.event.cursor, 0);
    assert!(frame.event.provisional);
    assert_eq!(frame.event.payload, event.payload.payload);
    assert_eq!(frame.event.generated_at, event.payload.timestamp);
    assert_eq!(
        request(
            &app,
            "GET",
            "/api/spaces/presence?network_id=test-network&space_id=the-ville"
        )
        .await
        .1["node_presences"],
        json!([event.payload.payload])
    );
    assert_eq!(
        request_json(&app, "POST", "/api/ingest/event", json!(event))
            .await
            .0,
        StatusCode::OK
    );
    assert!(matches!(
        receiver.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    let mut invalid_outer = event.clone();
    invalid_outer.payload.payload["last_heartbeat_ms"] = json!(1791849177001_i64);
    assert_eq!(
        request_json(&app, "POST", "/api/ingest/event", json!(invalid_outer))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(
            &app,
            "GET",
            "/api/spaces/presence?network_id=test-network&space_id=the-ville"
        )
        .await
        .1["node_presences"],
        json!([event.payload.payload])
    );
    assert!(matches!(
        receiver.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from gateway_ui_events")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from gateway_p2p_outbox")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    pool.close().await;
    db.cleanup().await;
}

#[tokio::test]
async fn node_heartbeat_uses_authenticated_identity_and_original_monotonic_proof_time() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;
    let mut event = signed_node_event(
        "heartbeat-node",
        DataKind::Presence,
        "node.presence.heartbeat",
        json!({}),
    );
    let heartbeat = wattetheria_gateway_contract::space::NodePresence {
        node_id: event.payload.node_id.clone(),
        agent_did: event.payload.signer_agent_did.clone(),
        last_heartbeat_ms: chrono::Utc::now().timestamp_millis(),
        heartbeat_interval_sec: 20,
    };
    event.payload.payload = serde_json::to_value(&heartbeat).unwrap();
    event.payload.provisional_policy = ProvisionalExportPolicy::EphemeralOnly;
    resign_node_event(&mut event);
    assert_eq!(
        request_json(
            &app,
            "POST",
            "/api/ingest/event",
            serde_json::to_value(&event).unwrap()
        )
        .await
        .0,
        StatusCode::OK
    );
    let response = request(
        &app,
        "GET",
        "/api/spaces/presence?network_id=test-network&space_id=the-ville",
    )
    .await;
    assert_eq!(response.1["node_presences"], json!([heartbeat]));
    let mut stale = event.clone();
    stale.payload.event_id = "heartbeat-node:stale".to_owned();
    stale.payload.payload["last_heartbeat_ms"] = json!(heartbeat.last_heartbeat_ms - 1000);
    resign_node_event(&mut stale);
    assert_eq!(
        request_json(
            &app,
            "POST",
            "/api/ingest/event",
            serde_json::to_value(stale).unwrap()
        )
        .await
        .1["status"],
        "duplicate"
    );
    let mut forged = event.clone();
    forged.payload.event_id = "heartbeat-node:forged".to_owned();
    forged.payload.payload["agent_did"] = json!(signed_space_presence(1, "other").record.agent_did);
    resign_node_event(&mut forged);
    assert_eq!(
        request_json(
            &app,
            "POST",
            "/api/ingest/event",
            serde_json::to_value(forged).unwrap()
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    for policy in [
        ProvisionalExportPolicy::NeverBeforeConfirmation,
        ProvisionalExportPolicy::ProvisionalWithDowngrade,
    ] {
        let mut incorrect_policy = event.clone();
        incorrect_policy.payload.provisional_policy = policy;
        resign_node_event(&mut incorrect_policy);
        assert_eq!(
            request_json(&app, "POST", "/api/ingest/event", json!(incorrect_policy))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }
    let mut incorrect_interval = event.clone();
    incorrect_interval.payload.payload["heartbeat_interval_sec"] = json!(0);
    resign_node_event(&mut incorrect_interval);
    assert_eq!(
        request_json(&app, "POST", "/api/ingest/event", json!(incorrect_interval))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let mut snapshot = signed_snapshot(
        "heartbeat-node",
        SnapshotContents {
            network_name: None,
            network_org_name: None,
            peers: &[],
            public_blocks: &[],
            public_topics: &[],
            public_topic_messages: &[],
            swarm_task_activity: json!({}),
            tasks: &[],
            organizations: &[],
            leaderboard: &[],
        },
    );
    let mut old = heartbeat.clone();
    old.last_heartbeat_ms -= 1000;
    snapshot.payload.node_presence = Some(old);
    resign_snapshot(&mut snapshot);
    assert_eq!(
        request_json(
            &app,
            "POST",
            "/api/ingest/snapshot",
            serde_json::to_value(snapshot).unwrap()
        )
        .await
        .0,
        StatusCode::OK
    );
    let response = request(
        &app,
        "GET",
        "/api/spaces/presence?network_id=test-network&space_id=the-ville",
    )
    .await;
    assert_eq!(
        response.1["node_presences"],
        json!([heartbeat]),
        "old snapshot must not refresh heartbeat as receipt time"
    );
    let pool = db.pool().await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "select count(*) from gateway_ui_events where data_kind='presence'"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );
    pool.close().await;
    db.cleanup().await;
}

#[tokio::test]
async fn node_heartbeat_accepts_bounded_proof_intervals_without_durable_history() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;
    let mut accepted = Vec::new();
    for interval in [1, 20, 60, 300, 0, -1, 301] {
        let mut event = signed_node_event(
            &format!("interval-event-{interval}"),
            DataKind::Presence,
            "node.presence.heartbeat",
            json!({}),
        );
        let heartbeat = wattetheria_gateway_contract::space::NodePresence {
            node_id: event.payload.node_id.clone(),
            agent_did: event.payload.signer_agent_did.clone(),
            last_heartbeat_ms: 1_710_000_000_000,
            heartbeat_interval_sec: interval,
        };
        event.payload.payload = json!(heartbeat);
        event.payload.provisional_policy = ProvisionalExportPolicy::EphemeralOnly;
        resign_node_event(&mut event);
        let response = request_json(&app, "POST", "/api/ingest/event", json!(event)).await;
        let valid = (1..=300).contains(&interval);
        assert_eq!(
            response.0,
            if valid {
                StatusCode::OK
            } else {
                StatusCode::BAD_REQUEST
            },
            "interval {interval}: {}",
            response.1
        );
        if valid {
            accepted.push(heartbeat);
            accepted.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        }
        let response = request(
            &app,
            "GET",
            "/api/spaces/presence?network_id=test-network&space_id=the-ville",
        )
        .await;
        assert_eq!(response.0, StatusCode::OK);
        assert_eq!(response.1["node_presences"], json!(accepted));
    }
    let pool = db.pool().await;
    for table in ["gateway_ui_events", "gateway_p2p_outbox"] {
        assert_eq!(
            sqlx::query_scalar::<_, i64>(&format!("select count(*) from {table}"))
                .fetch_one(&pool)
                .await
                .unwrap(),
            0,
            "ephemeral heartbeat must not enter {table}"
        );
    }
    pool.close().await;
    db.cleanup().await;
}

#[tokio::test]
async fn signed_snapshot_projects_only_bounded_heartbeat_intervals_and_keeps_signed_payload() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;
    let pool = db.pool().await;
    let mut accepted = Vec::new();
    for interval in [1, 20, 60, 300, 0, -1, 301] {
        let mut snapshot = signed_snapshot(
            &format!("interval-snapshot-{interval}"),
            SnapshotContents {
                network_name: None,
                network_org_name: None,
                peers: &[],
                public_blocks: &[],
                public_topics: &[],
                public_topic_messages: &[],
                swarm_task_activity: json!({}),
                tasks: &[],
                organizations: &[],
                leaderboard: &[],
            },
        );
        let heartbeat = wattetheria_gateway_contract::space::NodePresence {
            node_id: snapshot.payload.node_id.clone(),
            agent_did: snapshot.signer_agent_did.clone(),
            last_heartbeat_ms: 1_710_000_000_000,
            heartbeat_interval_sec: interval,
        };
        snapshot.payload.node_presence = Some(heartbeat.clone());
        resign_snapshot(&mut snapshot);
        let response = request_json(&app, "POST", "/api/ingest/snapshot", json!(snapshot)).await;
        assert_eq!(
            response.0,
            StatusCode::OK,
            "interval {interval}: {}",
            response.1
        );
        let stored: (sqlx::types::Json<Value>, String) =
            sqlx::query_as("select payload,signature from node_snapshots where node_id=$1")
                .bind(&snapshot.payload.node_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stored.0.0, json!(snapshot.payload));
        assert_eq!(stored.1, snapshot.signature);
        if (1..=300).contains(&interval) {
            accepted.push(heartbeat);
            accepted.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        }
        let response = request(
            &app,
            "GET",
            "/api/spaces/presence?network_id=test-network&space_id=the-ville",
        )
        .await;
        assert_eq!(response.0, StatusCode::OK);
        assert_eq!(response.1["node_presences"], json!(accepted));
    }
    pool.close().await;
    db.cleanup().await;
}

#[tokio::test]
async fn signed_snapshot_isolates_invalid_space_items_without_changing_the_signed_payload() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;
    let pool = db.pool().await;
    let mut old = signed_space_presence(100, "old package resident");
    old.record.space_version = "sha256:old-package".to_owned();
    resign_space_presence(&mut old);
    sqlx::query("insert into gateway_space_presence(network_id,space_id,agent_did,seq,source_node_id,payload) values('test-network',$1,$2,$3::text::numeric,$4,$5)")
        .bind(&old.record.space_id).bind(&old.record.agent_did).bind(old.record.seq.to_string())
        .bind("mixed-snapshot-node").bind(sqlx::types::Json(&old)).execute(&pool).await.unwrap();
    let response = request(
        &app,
        "GET",
        "/api/spaces/presence?network_id=test-network&space_id=the-ville",
    )
    .await;
    assert_eq!(
        response.1["presences"],
        json!([]),
        "a signed record without its source heartbeat is not a visible resident"
    );
    let raw_path = format!(
        "/api/spaces/presence/{}/record?network_id=test-network&space_id=the-ville",
        old.record.agent_did
    );
    assert_eq!(request(&app, "GET", &raw_path).await.1, json!(old));
    let valid = signed_space_presence(101, "new package resident");
    let mut invalid = signed_space_presence(999, "valid signature before tampering");
    invalid.record.activity = "unsigned forged activity".to_owned();
    old.record.seq = 1000;
    resign_space_presence(&mut old);
    let mut snapshot = signed_snapshot(
        "mixed-snapshot-node",
        SnapshotContents {
            network_name: None,
            network_org_name: None,
            peers: &[],
            public_blocks: &[],
            public_topics: &[],
            public_topic_messages: &[],
            swarm_task_activity: json!({}),
            tasks: &[json!({"id":"legitimate-task","title":"Existing task"})],
            organizations: &[],
            leaderboard: &[],
        },
    );
    snapshot.payload.public_board_messages =
        vec![json!({"message_id":"legitimate-board","content":"Existing board message"})];
    snapshot.payload.space_presences = vec![invalid, old.clone(), valid.clone()];
    snapshot.payload.node_presence = Some(wattetheria_gateway_contract::space::NodePresence {
        node_id: snapshot.payload.node_id.clone(),
        agent_did: "wrong authenticated agent".to_owned(),
        last_heartbeat_ms: chrono::Utc::now().timestamp_millis(),
        heartbeat_interval_sec: 20,
    });
    resign_snapshot(&mut snapshot);
    let response = request_json(&app, "POST", "/api/ingest/snapshot", json!(snapshot)).await;
    assert_eq!(response.0, StatusCode::OK, "{}", response.1);
    let stored: (sqlx::types::Json<Value>, String) = sqlx::query_as(
        "select payload,signature from node_snapshots where node_id='mixed-snapshot-node'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        stored.0.0,
        json!(snapshot.payload),
        "original signed payload must not be sanitized"
    );
    assert_eq!(stored.1, snapshot.signature);
    let response = request(
        &app,
        "GET",
        "/api/spaces/presence?network_id=test-network&space_id=the-ville",
    )
    .await;
    assert_eq!(response.1["presences"], json!([]));
    assert_eq!(response.1["node_presences"], json!([]));
    assert_eq!(request(&app, "GET", &raw_path).await.1, json!(old));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from gateway_space_presence")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "select count(*) from gateway_ui_events where data_kind='space_presence'"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    for kind in ["task_summary", "board_activity"] {
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "select count(*) from gateway_projection_rows where data_kind=$1"
            )
            .bind(kind)
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
    }
    let mut forged_outer = snapshot.clone();
    forged_outer.payload.generated_at += 100;
    forged_outer
        .payload
        .tasks
        .push(json!({"id":"unsigned-task"}));
    assert_eq!(
        request_json(&app, "POST", "/api/ingest/snapshot", json!(forged_outer))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let stored: sqlx::types::Json<Value> = sqlx::query_scalar(
        "select payload from node_snapshots where node_id='mixed-snapshot-node'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored.0, json!(snapshot.payload));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "select count(*) from gateway_projection_rows where data_kind='task_summary'"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    pool.close().await;
    db.cleanup().await;
}

#[tokio::test]
async fn original_full_snapshot_preserves_signed_fields_and_rejects_each_field_tamper() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;
    let pool = db.pool().await;
    let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
    let public_key =
        base64::engine::general_purpose::STANDARD.encode(signing_key.verifying_key().as_bytes());
    let signer = did_key_from_public_key_b64(&public_key);
    for (index, nodes) in [
        None,
        Some(json!([])),
        Some(json!([{"id": "native-node", "running": true}])),
        None,
    ]
    .into_iter()
    .enumerate()
    {
        let node_id = format!("original-full-snapshot-{index}");
        let presence =
            signed_space_presence(u64::MAX - 3 + index as u64, "original native activity");
        wattetheria_gateway::verify::verify_signed_space_presence(&presence).unwrap();
        let mut payload = json!({
            "generated_at": 1_710_000_000 + index,
            "node_id": node_id,
            "agent_identity": signer,
            "public_id": "public-native-agent",
            "public_key": public_key,
            "network_status": {"total_nodes": 1},
            "peers": [],
            "operator": {"id": "native-agent"},
            "rpc_logs": [],
            "public_blocks": [],
            "public_topics": [],
            "public_topic_messages": [],
            "public_board_messages": [{"message_id": format!("native-board-{index}"), "content": "original board"}],
            "space_presences": [presence],
            "swarm_task_activity": {},
            "tasks": [{"id": format!("native-task-{index}"), "title": "Original task"}],
            "organizations": [],
            "leaderboard": []
        });
        if let Some(nodes) = nodes {
            payload["nodes"] = nodes;
        }
        if index == 3 {
            payload.as_object_mut().unwrap().remove("agent_identity");
            payload.as_object_mut().unwrap().remove("public_id");
        }
        let signature = base64::engine::general_purpose::STANDARD.encode(
            signing_key
                .sign(&canonical_bytes(&payload).unwrap())
                .to_bytes(),
        );
        let original =
            json!({"payload": payload, "signature": signature, "signer_agent_did": signer});
        let typed: SignedPublicClientSnapshot = serde_json::from_value(original.clone()).unwrap();
        assert_eq!(
            json!(typed),
            original,
            "typed decoding must preserve the signed shape"
        );
        wattetheria_gateway::verify::verify_signed_snapshot(&typed, Some(&signer)).unwrap();
        let response = request_json(&app, "POST", "/api/ingest/snapshot", original.clone()).await;
        assert_eq!(response.0, StatusCode::OK, "{}", response.1);
        ingest_space_heartbeat(
            &app,
            &node_id,
            &SigningKey::from_bytes(&[19_u8; 32]),
            chrono::Utc::now().timestamp_millis(),
        )
        .await;
        for (field, tampered_value) in [
            ("agent_identity", json!("unsigned-identity")),
            ("public_id", json!("unsigned-public-id")),
            ("nodes", json!([{"id": "unsigned-node"}])),
        ] {
            let mut tampered = original.clone();
            tampered["payload"][field] = tampered_value;
            let response = request_json(&app, "POST", "/api/ingest/snapshot", tampered).await;
            assert_eq!(
                response.0,
                StatusCode::BAD_REQUEST,
                "{field}: {}",
                response.1
            );
        }
        let stored: (sqlx::types::Json<Value>, String) =
            sqlx::query_as("select payload, signature from node_snapshots where node_id=$1")
                .bind(&node_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stored.0.0, original["payload"]);
        assert_eq!(stored.1, signature);
        let restored: SignedPublicClientSnapshot = serde_json::from_value(json!({
            "payload": stored.0.0, "signature": stored.1, "signer_agent_did": signer
        }))
        .unwrap();
        wattetheria_gateway::verify::verify_signed_snapshot(&restored, Some(&signer)).unwrap();
        let response = request(
            &app,
            "GET",
            "/api/spaces/presence?network_id=test-network&space_id=the-ville",
        )
        .await;
        assert_eq!(response.1["presences"], json!([presence]));
    }
    for kind in ["task_summary", "board_activity"] {
        let count = sqlx::query_scalar::<_, i64>(
            "select count(*) from gateway_projection_rows where data_kind=$1",
        )
        .bind(kind)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 4);
    }
    pool.close().await;
    db.cleanup().await;
}

#[tokio::test]
async fn snapshot_presence_recovery_publishes_only_newer_original_signed_records() {
    let db = TestDatabase::new().await;
    let pool = db.pool().await;
    db::init_schema(&pool).await.unwrap();
    let (sender, _) = tokio::sync::broadcast::channel(64);
    let state = AppState {
        pool: pool.clone(),
        node_client: NodeClient::new(5).unwrap(),
        registry_client: RegistryClient::new(5).unwrap(),
        nats: None,
        registry_admin_token: None,
        bootstrap_registry_urls: vec![],
        gateway_identity: None,
        gateway_network: None,
        gateway_sync_tx: None,
        ui_stream_tx: UiStreamHub::new(sender),
    };
    let mut receiver = state.ui_stream_tx.subscribe(Some(DataKind::SpacePresence));
    let app = http::router(state);
    let presence = signed_space_presence(1, "restored");
    let mut snapshot = signed_snapshot(
        "snapshot-recovery-node",
        SnapshotContents {
            network_name: None,
            network_org_name: None,
            peers: &[],
            public_blocks: &[],
            public_topics: &[],
            public_topic_messages: &[],
            swarm_task_activity: json!({}),
            tasks: &[],
            organizations: &[],
            leaderboard: &[],
        },
    );
    snapshot.payload.space_presences = vec![presence.clone()];
    resign_snapshot(&mut snapshot);
    assert_eq!(
        request_json(
            &app,
            "POST",
            "/api/ingest/snapshot",
            serde_json::to_value(&snapshot).unwrap()
        )
        .await
        .0,
        StatusCode::OK
    );
    let frame = receiver.try_recv().unwrap();
    assert_eq!(frame.event.payload, json!(presence));
    assert_eq!(frame.event.generated_at, presence.record.updated_at / 1000);
    assert!(frame.event.cursor > 0);
    assert!(matches!(
        receiver.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    snapshot.payload.generated_at += 1;
    resign_snapshot(&mut snapshot);
    assert_eq!(
        request_json(
            &app,
            "POST",
            "/api/ingest/snapshot",
            serde_json::to_value(&snapshot).unwrap()
        )
        .await
        .0,
        StatusCode::OK
    );
    assert!(matches!(
        receiver.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    let newer = signed_space_presence(2, "newer recovered");
    snapshot.payload.generated_at += 1;
    snapshot.payload.space_presences = vec![newer.clone()];
    resign_snapshot(&mut snapshot);
    assert_eq!(
        request_json(
            &app,
            "POST",
            "/api/ingest/snapshot",
            serde_json::to_value(&snapshot).unwrap()
        )
        .await
        .0,
        StatusCode::OK
    );
    let frame = receiver.try_recv().unwrap();
    assert_eq!(frame.event.payload, json!(newer));
    assert!(matches!(
        receiver.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    snapshot.payload.generated_at += 1;
    snapshot.payload.space_presences = vec![presence];
    resign_snapshot(&mut snapshot);
    assert_eq!(
        request_json(
            &app,
            "POST",
            "/api/ingest/snapshot",
            serde_json::to_value(&snapshot).unwrap()
        )
        .await
        .0,
        StatusCode::OK
    );
    assert!(matches!(
        receiver.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "select count(*) from gateway_ui_events where data_kind='space_presence'"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        2
    );
    pool.close().await;
    db.cleanup().await;
}

#[tokio::test]
async fn space_presence_display_names_follow_visible_matching_snapshots() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;
    let mut snapshot = signed_snapshot(
        "names-node",
        SnapshotContents {
            network_name: None,
            network_org_name: None,
            peers: &[],
            public_blocks: &[],
            public_topics: &[],
            public_topic_messages: &[],
            swarm_task_activity: json!({}),
            tasks: &[],
            organizations: &[],
            leaderboard: &[],
        },
    );
    let mut presence = signed_space_presence(10, "name refresh preserves movement");
    presence.record.agent_did = snapshot.signer_agent_did.clone();
    presence.public_key = snapshot.payload.public_key.clone();
    let key = SigningKey::from_bytes(&[11_u8; 32]);
    presence.signature = base64::engine::general_purpose::STANDARD.encode(
        key.sign(&canonical_bytes(&presence.record).unwrap())
            .to_bytes(),
    );
    assert_eq!(
        request_json(
            &app,
            "POST",
            "/api/ingest/event",
            json!(space_node_event("names-node", 1, &presence))
        )
        .await
        .0,
        StatusCode::OK
    );
    ingest_space_heartbeat(
        &app,
        "names-node",
        &SigningKey::from_bytes(&[11_u8; 32]),
        chrono::Utc::now().timestamp_millis(),
    )
    .await;
    let path = "/api/spaces/presence?network_id=test-network&space_id=the-ville";
    let did = presence.record.agent_did.clone();
    let identities = |name: Option<&str>| json!([{"network_id":"test-network","agent_did":did,"node_id":"names-node","display_name":name}]);
    let response = request(&app, "GET", path).await;
    assert_eq!(response.0, StatusCode::OK);
    assert_eq!(response.1["identities"], identities(None));
    assert_eq!(response.1["presences"], json!([presence]));

    snapshot.payload.network_status["network_id"] = json!("test-network");
    snapshot.payload.operator["display_name"] = json!("MRX");
    resign_snapshot(&mut snapshot);
    assert_eq!(
        request_json(&app, "POST", "/api/ingest/snapshot", json!(snapshot))
            .await
            .0,
        StatusCode::OK
    );
    let first = snapshot.clone();
    for (name, expected) in [
        (json!("MRX"), Some("MRX")),
        (json!("Renamed Agent"), Some("Renamed Agent")),
        (json!("  "), None),
        (json!(null), None),
        (json!({"name":"not a string"}), None),
        (json!("Restored"), Some("Restored")),
    ] {
        snapshot.payload.generated_at += 1;
        snapshot.payload.operator["display_name"] = name;
        resign_snapshot(&mut snapshot);
        let ingested = request_json(&app, "POST", "/api/ingest/snapshot", json!(snapshot)).await;
        assert_eq!(ingested.0, StatusCode::OK, "{}", ingested.1);
        for query_path in [path, "/api/spaces/presence?space_id=the-ville"] {
            let response = request(&app, "GET", query_path).await;
            assert_eq!(response.0, StatusCode::OK);
            assert_eq!(response.1["identities"], identities(expected));
            assert_eq!(response.1["presences"], json!([presence]));
        }
    }
    assert_eq!(
        request_json(&app, "POST", "/api/ingest/snapshot", json!(first))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        request(&app, "GET", path).await.1["identities"],
        identities(Some("Restored"))
    );

    snapshot.payload.generated_at += 1;
    snapshot.payload.network_status["network_id"] = json!("another-network");
    resign_snapshot(&mut snapshot);
    assert_eq!(
        request_json(&app, "POST", "/api/ingest/snapshot", json!(snapshot))
            .await
            .0,
        StatusCode::OK
    );
    let response = request(&app, "GET", path).await;
    assert_eq!(response.1["identities"], identities(None));
    assert_eq!(response.1["presences"], json!([presence]));

    snapshot.payload.generated_at += 1;
    snapshot.payload.network_status["network_id"] = json!("test-network");
    let other_key = SigningKey::from_bytes(&[23_u8; 32]);
    snapshot.payload.public_key =
        base64::engine::general_purpose::STANDARD.encode(other_key.verifying_key().as_bytes());
    snapshot.signer_agent_did = did_key_from_public_key_b64(&snapshot.payload.public_key);
    snapshot.signature = base64::engine::general_purpose::STANDARD.encode(
        other_key
            .sign(&canonical_bytes(&snapshot.payload).unwrap())
            .to_bytes(),
    );
    assert_eq!(
        request_json(&app, "POST", "/api/ingest/snapshot", json!(snapshot))
            .await
            .0,
        StatusCode::OK
    );
    let response = request(&app, "GET", path).await;
    assert_eq!(response.1["identities"], identities(None));
    assert_eq!(response.1["presences"], json!([presence]));

    snapshot.payload.generated_at += 1;
    snapshot.payload.public_key = presence.public_key.clone();
    snapshot.signer_agent_did = did.clone();
    resign_snapshot(&mut snapshot);
    assert_eq!(
        request_json(&app, "POST", "/api/ingest/snapshot", json!(snapshot))
            .await
            .0,
        StatusCode::OK
    );
    let pool = db.pool().await;
    let source_id = uuid::Uuid::new_v4();
    sqlx::query("insert into node_sources(id,name,export_url,source_status) values($1,'names source','http://127.0.0.1/names','active')")
        .bind(source_id).execute(&pool).await.unwrap();
    sqlx::query("update node_snapshots set source_id=$1 where node_id='names-node'")
        .bind(source_id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        request(&app, "GET", path).await.1["identities"],
        identities(Some("Restored"))
    );
    sqlx::query("update node_sources set source_status='suspended' where id=$1")
        .bind(source_id)
        .execute(&pool)
        .await
        .unwrap();
    let response = request(&app, "GET", path).await;
    assert_eq!(response.1["identities"], identities(None));
    assert_eq!(response.1["presences"], json!([presence]));
    pool.close().await;
    db.cleanup().await;
}

#[tokio::test]
async fn space_presence_latest_is_agent_signed_and_sequence_ordered_across_nodes() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;
    let presence = signed_space_presence(10, "first");
    let newer = signed_space_presence(11, "newer");
    let agent_did = &presence.record.agent_did;
    for (node, sequence, record, expected) in [
        ("node-a", 1, presence.clone(), "ok"),
        ("node-b", 2, newer.clone(), "ok"),
        ("node-c", 3, presence.clone(), "duplicate"),
        ("node-d", 4, newer.clone(), "duplicate"),
    ] {
        let event = space_node_event(node, sequence, &record);
        let response = request_json(
            &app,
            "POST",
            "/api/ingest/event",
            serde_json::to_value(event).unwrap(),
        )
        .await;
        assert_eq!(response.0, StatusCode::OK, "{}", response.1);
        assert_eq!(response.1["status"], expected);
    }
    ingest_space_heartbeat(
        &app,
        "node-b",
        &SigningKey::from_bytes(&[19_u8; 32]),
        chrono::Utc::now().timestamp_millis(),
    )
    .await;
    let response = request(
        &app,
        "GET",
        "/api/spaces/presence?network_id=test-network&space_id=the-ville",
    )
    .await;
    assert_eq!(response.0, StatusCode::OK);
    assert_eq!(response.1["presences"], json!([newer]));
    assert!(response.1["server_time_ms"].as_i64().unwrap() > 1_000_000_000_000);
    let response = request(
        &app,
        "GET",
        &format!("/api/spaces/presence/{agent_did}?network_id=test-network&space_id=the-ville"),
    )
    .await;
    assert_eq!(response.0, StatusCode::OK);
    assert_eq!(response.1["presence"]["record"]["seq"], 11);
    let pool = db.pool().await;
    let count: i64 = sqlx::query_scalar(
        "select count(*) from gateway_ui_events where data_kind='space_presence'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 2, "stale records must not enter public WS replay");
    let source: String = sqlx::query_scalar("select source_node_id from gateway_space_presence")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(source, "node-b");
    let mut forged = newer.clone();
    forged.record.activity = "forged".to_owned();
    let event = space_node_event("node-attacker", 5, &forged);
    let response = request_json(
        &app,
        "POST",
        "/api/ingest/event",
        serde_json::to_value(event).unwrap(),
    )
    .await;
    assert_eq!(response.0, StatusCode::BAD_REQUEST);
    let mut wrong_did = signed_space_presence(12, "wrong did");
    wrong_did.record.agent_did =
        signed_node_event("other", DataKind::Presence, "heartbeat", json!({}))
            .payload
            .signer_agent_did;
    let event = space_node_event("node-attacker", 6, &wrong_did);
    assert_eq!(
        request_json(
            &app,
            "POST",
            "/api/ingest/event",
            serde_json::to_value(event).unwrap()
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(
            &app,
            "GET",
            "/api/spaces/presence/absent?network_id=test-network&space_id=the-ville"
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(
            &app,
            "GET",
            "/api/spaces/presence?network_id=test-network&space_id=unknown"
        )
        .await
        .0,
        StatusCode::OK
    );
    pool.close().await;
    db.cleanup().await;
}

#[tokio::test]
async fn space_presence_place_filter_uses_current_tile_and_schema_upgrade_preserves_data() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;
    let mut presence = signed_space_presence(1, "opaque signed geometry");
    presence.record.space_id = "unknown-space".to_owned();
    presence.record.space_version = "sha256:unknown-map".to_owned();
    presence.record.from_tile = [u32::MAX, u32::MAX];
    presence.record.path = "URDL".to_owned();
    presence.record.destination_place_id = "unknown-place".to_owned();
    presence.record.object_place_id = Some("unknown-object".to_owned());
    for seq in 1..=3 {
        presence.record.seq = seq;
        presence.record.depart_at =
            chrono::Utc::now().timestamp_millis() + if seq == 2 { 60_000 } else { -1_000 };
        resign_space_presence(&mut presence);
        let event = space_node_event("node-a", seq, &presence);
        let response = request_json(&app, "POST", "/api/ingest/event", json!(event)).await;
        assert_eq!(response.0, StatusCode::OK, "{}", response.1);
        if seq == 1 {
            ingest_space_heartbeat(
                &app,
                "node-a",
                &SigningKey::from_bytes(&[19_u8; 32]),
                chrono::Utc::now().timestamp_millis(),
            )
            .await;
        }
        let response = request(
            &app,
            "GET",
            "/api/spaces/presence?network_id=test-network&space_id=unknown-space",
        )
        .await;
        assert_eq!(response.0, StatusCode::OK);
        assert_eq!(response.1["presences"], json!([presence]));
        for path in [
            "/api/spaces/presence?network_id=test-network&space_id=unknown-space&place_id=unknown-place",
            "/api/spaces/presence?network_id=test-network&place_id=unknown-object",
        ] {
            let response = request(&app, "GET", path).await;
            assert_eq!(response.0, StatusCode::BAD_REQUEST, "{}", response.1);
            let message = response.1.to_string().to_lowercase();
            assert!(
                message.contains("main") && message.contains("client"),
                "{message}"
            );
        }
    }
    let pool = db.pool().await;
    db::init_schema(&pool).await.unwrap();
    db::init_schema(&pool).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from gateway_space_presence")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from gateway_ui_events")
            .fetch_one(&pool)
            .await
            .unwrap(),
        3
    );
    pool.close().await;
    db.cleanup().await;
}

#[tokio::test]
async fn space_schema_upgrades_existing_gateway_tables_idempotently_without_data_loss() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;
    let event = signed_node_event(
        "old-node",
        DataKind::BoardActivity,
        "board.message.published",
        json!({"message_id":"old-message","feed_key":"wattetheria.board.general","author_public_id":"old-agent","body":"Preserved"}),
    );
    assert_eq!(
        request_json(
            &app,
            "POST",
            "/api/ingest/event",
            serde_json::to_value(event).unwrap()
        )
        .await
        .0,
        StatusCode::OK
    );
    let pool = db.pool().await;
    sqlx::query(
        "drop table gateway_space_presence,gateway_space_events,gateway_space_node_presence",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("create table gateway_space_presence(space_id text not null,agent_did text not null,seq numeric(20,0) not null,source_node_id text not null,source_id uuid null,payload jsonb not null,primary key(space_id,agent_did))")
        .execute(&pool).await.unwrap();
    let mut legacy = json!(signed_space_presence(u64::MAX - 1, "legacy original body"));
    legacy["record"]
        .as_object_mut()
        .unwrap()
        .remove("network_id");
    legacy["record"].as_object_mut().unwrap().remove("entered");
    let key = SigningKey::from_bytes(&[19_u8; 32]);
    legacy["signature"] = json!(
        base64::engine::general_purpose::STANDARD.encode(
            key.sign(&canonical_bytes(&legacy["record"]).unwrap())
                .to_bytes()
        )
    );
    let decoded: wattetheria_gateway_contract::SignedSpacePresence =
        serde_json::from_value(legacy.clone()).unwrap();
    wattetheria_gateway::verify::verify_signed_space_presence(&decoded).unwrap();
    let source_id = uuid::Uuid::new_v4();
    sqlx::query("insert into node_sources(id,name,export_url,source_status) values($1,'legacy source','http://127.0.0.1/legacy','active')")
        .bind(source_id).execute(&pool).await.unwrap();
    sqlx::query("insert into gateway_space_presence(space_id,agent_did,seq,source_node_id,source_id,payload) values('the-ville',$1,$2::text::numeric,'legacy-node',$3,$4)")
        .bind(&decoded.record.agent_did).bind(decoded.record.seq.to_string())
        .bind(source_id).bind(sqlx::types::Json(&legacy)).execute(&pool).await.unwrap();
    db::init_schema(&pool).await.unwrap();
    db::init_schema(&pool).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "select count(*) from gateway_ui_events where event_id='old-node:1'"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "select count(*) from gateway_projection_rows where data_kind='board_activity'"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from gateway_space_presence")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from gateway_space_events")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    let stored: (
        String,
        String,
        Option<uuid::Uuid>,
        String,
        sqlx::types::Json<Value>,
    ) = sqlx::query_as(
        "select network_id,source_node_id,source_id,seq::text,payload from gateway_space_presence",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored.0, "");
    assert_eq!(stored.1, "legacy-node");
    assert_eq!(stored.2, Some(source_id));
    assert_eq!(stored.3, decoded.record.seq.to_string());
    assert_eq!(stored.4.0, legacy);
    let response = request(
        &app,
        "GET",
        &format!(
            "/api/spaces/presence/{}/record?network_id=&space_id=the-ville",
            decoded.record.agent_did
        ),
    )
    .await;
    assert_eq!(response.0, StatusCode::OK);
    assert_eq!(response.1, legacy);
    assert_eq!(
        request(&app, "GET", "/api/spaces/presence?network_id=test-network")
            .await
            .1["presences"],
        json!([])
    );
    let modern = signed_space_presence(1, "new namespace independent floor");
    let response = request_json(
        &app,
        "POST",
        "/api/ingest/event",
        json!(space_node_event("modern-node", 1, &modern)),
    )
    .await;
    assert_eq!(response.0, StatusCode::OK, "{}", response.1);
    ingest_space_heartbeat(
        &app,
        "modern-node",
        &SigningKey::from_bytes(&[19_u8; 32]),
        chrono::Utc::now().timestamp_millis(),
    )
    .await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from gateway_space_presence")
            .fetch_one(&pool)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        request(&app, "GET", "/api/spaces/presence?network_id=test-network")
            .await
            .1["presences"],
        json!([modern])
    );
    pool.close().await;
    db.cleanup().await;
}

#[tokio::test]
async fn space_presence_isolates_same_agent_and_space_by_network() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;
    let first = signed_space_presence(100, "first network");
    let mut second = signed_space_presence(1, "second network");
    second.record.network_id = "other-network".to_owned();
    resign_space_presence(&mut second);
    for (index, presence) in [&first, &second].into_iter().enumerate() {
        let node = format!("network-node-{index}");
        let response = request_json(
            &app,
            "POST",
            "/api/ingest/event",
            json!(space_node_event(&node, 1, presence)),
        )
        .await;
        assert_eq!(response.0, StatusCode::OK, "{}", response.1);
        ingest_space_heartbeat(
            &app,
            &node,
            &SigningKey::from_bytes(&[19_u8; 32]),
            chrono::Utc::now().timestamp_millis(),
        )
        .await;
    }
    let mut forged_network = first.clone();
    forged_network.record.network_id = second.record.network_id.clone();
    let response = request_json(
        &app,
        "POST",
        "/api/ingest/event",
        json!(space_node_event("network-tamper-node", 1, &forged_network)),
    )
    .await;
    assert_eq!(response.0, StatusCode::BAD_REQUEST, "{}", response.1);
    for presence in [&first, &second] {
        let path = format!(
            "/api/spaces/presence?network_id={}&space_id=the-ville",
            presence.record.network_id
        );
        let response = request(&app, "GET", &path).await;
        assert_eq!(response.0, StatusCode::OK);
        assert_eq!(response.1["presences"], json!([presence]));
        let raw = format!(
            "/api/spaces/presence/{}/record?network_id={}",
            presence.record.agent_did, presence.record.network_id
        );
        assert_eq!(request(&app, "GET", &raw).await.1, json!(presence));
        let single = format!(
            "/api/spaces/presence/{}?network_id={}",
            presence.record.agent_did, presence.record.network_id
        );
        assert_eq!(
            request(&app, "GET", &single).await.1["presence"],
            json!(presence)
        );
    }
    let observed = request(&app, "GET", "/api/spaces/presence").await;
    assert_eq!(observed.0, StatusCode::OK);
    assert!(observed.1["network_id"].is_null());
    assert_eq!(observed.1["presences"], json!([second, first]));
    assert_eq!(
        observed.1["identities"],
        json!([
            {"network_id":"other-network","agent_did":second.record.agent_did,"node_id":"network-node-1","display_name":null},
            {"network_id":"test-network","agent_did":first.record.agent_did,"node_id":"network-node-0","display_name":null}
        ])
    );
    let events = request(&app, "GET", "/api/spaces/events?space_id=the-ville").await;
    assert_eq!(events.0, StatusCode::OK);
    assert_eq!(events.1["events"], json!([]));
    for path in [
        "/api/spaces/presence?network_id=",
        "/api/spaces/presence/absent?space_id=the-ville",
        "/api/spaces/presence/absent/record?space_id=the-ville",
        "/api/spaces/events?network_id=",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
    }
    let response = request(
        &app,
        "GET",
        "/api/spaces/presence?network_id=test-network&space_id=unknown",
    )
    .await;
    assert_eq!(response.0, StatusCode::OK);
    assert_eq!(response.1["presences"], json!([]));
    let pool = db.pool().await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from gateway_space_presence")
            .fetch_one(&pool)
            .await
            .unwrap(),
        2
    );
    pool.close().await;
    db.cleanup().await;
}

#[tokio::test]
async fn space_observations_keep_network_sequence_floors_before_space_and_entry_filters() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;
    let first = signed_space_presence(100, "first network");
    let mut second = signed_space_presence(1, "second network");
    second.record.network_id = "other-network".to_owned();
    resign_space_presence(&mut second);
    for (node, presence) in [("observation-a", &first), ("observation-b", &second)] {
        assert_eq!(
            request_json(
                &app,
                "POST",
                "/api/ingest/event",
                json!(space_node_event(node, 1, presence))
            )
            .await
            .0,
            StatusCode::OK
        );
        ingest_space_heartbeat(
            &app,
            node,
            &SigningKey::from_bytes(&[19_u8; 32]),
            chrono::Utc::now().timestamp_millis(),
        )
        .await;
    }
    let mut moved = first.clone();
    moved.record.seq = 101;
    moved.record.space_id = "another-space".to_owned();
    resign_space_presence(&mut moved);
    assert_eq!(
        request_json(
            &app,
            "POST",
            "/api/ingest/event",
            json!(space_node_event("observation-a", 2, &moved))
        )
        .await
        .0,
        StatusCode::OK
    );
    let visible = request(&app, "GET", "/api/spaces/presence?space_id=the-ville").await;
    assert_eq!(visible.0, StatusCode::OK);
    assert_eq!(visible.1["presences"], json!([second]));
    assert_eq!(
        request(&app, "GET", "/api/spaces/presence").await.1["presences"],
        json!([second, moved])
    );
    let mut inactive = moved.clone();
    inactive.record.seq = 102;
    inactive.record.entered = false;
    resign_space_presence(&mut inactive);
    assert_eq!(
        request_json(
            &app,
            "POST",
            "/api/ingest/event",
            json!(space_node_event("observation-a", 3, &inactive))
        )
        .await
        .0,
        StatusCode::OK
    );
    let pool = db.pool().await;
    let before: Vec<(String, String, String)> = sqlx::query_as(
        "select network_id,space_id,payload::text from gateway_space_presence order by network_id,space_id",
    ).fetch_all(&pool).await.unwrap();
    for path in [
        "/api/spaces/presence",
        "/api/spaces/presence?space_id=the-ville",
    ] {
        let response = request(&app, "GET", path).await;
        assert_eq!(response.0, StatusCode::OK);
        assert_eq!(response.1["presences"], json!([second]));
    }
    let raw = format!(
        "/api/spaces/presence/{}/record?network_id=test-network",
        first.record.agent_did
    );
    assert_eq!(request(&app, "GET", &raw).await.1, json!(inactive));
    let after: Vec<(String, String, String)> = sqlx::query_as(
        "select network_id,space_id,payload::text from gateway_space_presence order by network_id,space_id",
    ).fetch_all(&pool).await.unwrap();
    assert_eq!(
        after, before,
        "observation queries must not rewrite stored signed declarations"
    );
    pool.close().await;
    db.cleanup().await;
}

#[tokio::test]
async fn space_snapshot_namespaces_presence_ui_events_by_network() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;
    let first = signed_space_presence(10, "snapshot first network");
    let mut second = first.clone();
    second.record.network_id = "other-network".to_owned();
    resign_space_presence(&mut second);
    let mut snapshot = signed_snapshot(
        "multi-network-snapshot-node",
        SnapshotContents {
            network_name: None,
            network_org_name: None,
            peers: &[],
            public_blocks: &[],
            public_topics: &[],
            public_topic_messages: &[],
            swarm_task_activity: json!({}),
            tasks: &[],
            organizations: &[],
            leaderboard: &[],
        },
    );
    assert_ne!(
        snapshot.payload.agent_identity.as_deref(),
        Some(first.record.agent_did.as_str())
    );
    snapshot.payload.space_presences = vec![first.clone(), second.clone()];
    resign_snapshot(&mut snapshot);
    let response = request_json(&app, "POST", "/api/ingest/snapshot", json!(snapshot)).await;
    assert_eq!(response.0, StatusCode::OK, "{}", response.1);
    ingest_space_heartbeat(
        &app,
        "multi-network-snapshot-node",
        &SigningKey::from_bytes(&[19_u8; 32]),
        chrono::Utc::now().timestamp_millis(),
    )
    .await;
    for presence in [&first, &second] {
        let path = format!(
            "/api/spaces/presence?network_id={}&space_id={}",
            presence.record.network_id, presence.record.space_id,
        );
        let response = request(&app, "GET", &path).await;
        assert_eq!(response.0, StatusCode::OK);
        assert_eq!(response.1["presences"], json!([presence]));
    }
    let pool = db.pool().await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from gateway_space_presence")
            .fetch_one(&pool)
            .await
            .unwrap(),
        2
    );
    let ui_rows: Vec<(String, sqlx::types::Json<Value>)> = sqlx::query_as(
        "select event_id,payload from gateway_ui_events where data_kind='space_presence'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(ui_rows.len(), 2);
    for presence in [&first, &second] {
        let event_id = format!(
            "space-presence:{}:{}:{}:{}",
            presence.record.network_id,
            presence.record.space_id,
            presence.record.agent_did,
            presence.record.seq,
        );
        let row = ui_rows.iter().find(|(id, _)| id == &event_id).unwrap();
        assert_eq!(row.1.0, json!(presence));
    }
    let stored: (sqlx::types::Json<Value>, String) = sqlx::query_as(
        "select payload,signature from node_snapshots where node_id='multi-network-snapshot-node'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored.0.0, json!(snapshot.payload));
    assert_eq!(stored.1, snapshot.signature);
    pool.close().await;
    db.cleanup().await;
}

#[tokio::test]
async fn space_presence_global_sequence_precedes_space_filter_and_tombstone_replays() {
    for newest_first in [false, true] {
        let db = TestDatabase::new().await;
        let app = test_app(&db.database_url).await;
        let old = signed_space_presence(100, "old space");
        let mut newest = signed_space_presence(101, "new space");
        newest.record.space_id = "second-space".to_owned();
        resign_space_presence(&mut newest);
        let arrivals = if newest_first {
            [&newest, &old]
        } else {
            [&old, &newest]
        };
        for (index, presence) in arrivals.into_iter().enumerate() {
            let node = format!("cross-space-{index}");
            let response = request_json(
                &app,
                "POST",
                "/api/ingest/event",
                json!(space_node_event(&node, 1, presence)),
            )
            .await;
            assert_eq!(response.0, StatusCode::OK, "{}", response.1);
            ingest_space_heartbeat(
                &app,
                &node,
                &SigningKey::from_bytes(&[19_u8; 32]),
                chrono::Utc::now().timestamp_millis(),
            )
            .await;
        }
        let all = "/api/spaces/presence?network_id=test-network";
        let old_list = "/api/spaces/presence?network_id=test-network&space_id=the-ville";
        let old_single = format!(
            "/api/spaces/presence/{}?network_id=test-network&space_id=the-ville",
            old.record.agent_did
        );
        let raw = format!(
            "/api/spaces/presence/{}/record?network_id=test-network",
            old.record.agent_did
        );
        assert_eq!(
            request(&app, "GET", all).await.1["presences"],
            json!([newest])
        );
        assert_eq!(
            request(&app, "GET", old_list).await.1["presences"],
            json!([])
        );
        assert_eq!(
            request(&app, "GET", &old_single).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(request(&app, "GET", &raw).await.1, json!(newest));
        let mut tombstone = old.clone();
        tombstone.record.seq = 102;
        tombstone.record.entered = false;
        resign_space_presence(&mut tombstone);
        for (node, presence) in [
            ("inactive-newest", &tombstone),
            ("stale-other-space", &newest),
            ("stale-old-space", &old),
        ] {
            let response = request_json(
                &app,
                "POST",
                "/api/ingest/event",
                json!(space_node_event(node, 1, presence)),
            )
            .await;
            assert_eq!(response.0, StatusCode::OK, "{}", response.1);
            assert_eq!(request(&app, "GET", &raw).await.1, json!(tombstone));
        }
        assert_eq!(request(&app, "GET", all).await.1["presences"], json!([]));
        assert_eq!(
            request(&app, "GET", &old_single).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            request(
                &app,
                "GET",
                "/api/spaces/presence?network_id=test-network&space_id=second-space"
            )
            .await
            .1["presences"],
            json!([])
        );
        let mut missing_entered = json!(newest);
        missing_entered["record"]["space_id"] = json!("third-space");
        missing_entered["record"]["seq"] = json!(103);
        missing_entered["record"]
            .as_object_mut()
            .unwrap()
            .remove("entered");
        let key = SigningKey::from_bytes(&[19_u8; 32]);
        missing_entered["signature"] = json!(
            base64::engine::general_purpose::STANDARD.encode(
                key.sign(&canonical_bytes(&missing_entered["record"]).unwrap())
                    .to_bytes()
            )
        );
        let decoded: wattetheria_gateway_contract::SignedSpacePresence =
            serde_json::from_value(missing_entered.clone()).unwrap();
        assert!(!decoded.record.entered);
        wattetheria_gateway::verify::verify_signed_space_presence(&decoded).unwrap();
        let response = request_json(
            &app,
            "POST",
            "/api/ingest/event",
            json!(space_node_event("missing-entered-newest", 1, &decoded)),
        )
        .await;
        assert_eq!(response.0, StatusCode::OK, "{}", response.1);
        assert_eq!(request(&app, "GET", &raw).await.1, missing_entered);
        assert_eq!(request(&app, "GET", all).await.1["presences"], json!([]));
        let single = format!(
            "/api/spaces/presence/{}?network_id=test-network",
            old.record.agent_did
        );
        assert_eq!(request(&app, "GET", &single).await.0, StatusCode::NOT_FOUND);
        assert_eq!(
            request(&app, "GET", old_list).await.1["presences"],
            json!([])
        );
        let pool = db.pool().await;
        assert_eq!(
            sqlx::query_scalar::<_, i64>("select count(*) from gateway_space_presence")
                .fetch_one(&pool)
                .await
                .unwrap(),
            3
        );
        pool.close().await;
        db.cleanup().await;
    }
}

#[tokio::test]
async fn space_presence_inactive_highest_source_does_not_resurrect_older_space() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;
    let old = signed_space_presence(100, "active old source");
    let mut highest = signed_space_presence(101, "highest source");
    highest.record.space_id = "second-space".to_owned();
    resign_space_presence(&mut highest);
    for (node, presence) in [
        ("active-source-node", &old),
        ("inactive-source-node", &highest),
    ] {
        let response = request_json(
            &app,
            "POST",
            "/api/ingest/event",
            json!(space_node_event(node, 1, presence)),
        )
        .await;
        assert_eq!(response.0, StatusCode::OK, "{}", response.1);
        ingest_space_heartbeat(
            &app,
            node,
            &SigningKey::from_bytes(&[19_u8; 32]),
            chrono::Utc::now().timestamp_millis(),
        )
        .await;
    }
    let pool = db.pool().await;
    let source_id = uuid::Uuid::new_v4();
    sqlx::query("insert into node_sources(id,name,export_url,source_status) values($1,'highest source','http://127.0.0.1/highest','active')")
        .bind(source_id).execute(&pool).await.unwrap();
    sqlx::query("update gateway_space_presence set source_id=$1 where source_node_id='inactive-source-node'")
        .bind(source_id).execute(&pool).await.unwrap();
    assert_eq!(
        request(&app, "GET", "/api/spaces/presence?network_id=test-network")
            .await
            .1["presences"],
        json!([highest])
    );
    let raw = format!(
        "/api/spaces/presence/{}/record?network_id=test-network",
        old.record.agent_did
    );
    let single = format!(
        "/api/spaces/presence/{}?network_id=test-network",
        old.record.agent_did
    );
    for status in ["suspended", "invalid"] {
        sqlx::query("update node_sources set source_status=$1 where id=$2")
            .bind(status)
            .bind(source_id)
            .execute(&pool)
            .await
            .unwrap();
        for path in [
            "/api/spaces/presence?network_id=test-network",
            "/api/spaces/presence?network_id=test-network&space_id=the-ville",
            "/api/spaces/presence?network_id=test-network&space_id=second-space",
        ] {
            let response = request(&app, "GET", path).await;
            assert_eq!(response.0, StatusCode::OK);
            assert_eq!(response.1["presences"], json!([]), "{status} {path}");
        }
        assert_eq!(request(&app, "GET", &single).await.0, StatusCode::NOT_FOUND);
        assert_eq!(request(&app, "GET", &raw).await.1, json!(highest));
    }
    pool.close().await;
    db.cleanup().await;
}

fn signed_space_presence(
    seq: u64,
    activity: &str,
) -> wattetheria_gateway_contract::SignedSpacePresence {
    let key = SigningKey::from_bytes(&[19_u8; 32]);
    let public_key =
        base64::engine::general_purpose::STANDARD.encode(key.verifying_key().as_bytes());
    let mut presence = wattetheria_gateway_contract::SignedSpacePresence {
        record: wattetheria_gateway_contract::SpacePresenceRecord {
            agent_did: did_key_from_public_key_b64(&public_key),
            avatar_id: Some(24),
            network_id: "test-network".to_owned(),
            space_id: "the-ville".to_owned(),
            space_version: "sha256:test-map".to_owned(),
            seq,
            entered: true,
            from_tile: [19, 58],
            path: String::new(),
            depart_at: chrono::Utc::now().timestamp_millis(),
            destination_place_id: "adam-smiths-house".to_owned(),
            activity: activity.to_owned(),
            object_place_id: None,
            updated_at: chrono::Utc::now().timestamp_millis(),
        },
        public_key,
        signature: String::new(),
    };
    resign_space_presence(&mut presence);
    presence
}

#[tokio::test]
async fn space_activity_object_validation_matches_signed_product_contract() {
    let db = TestDatabase::new().await;
    let pool = db.pool().await;
    db::init_schema(&pool).await.unwrap();
    let (sender, _) = tokio::sync::broadcast::channel(64);
    let state = AppState {
        pool: pool.clone(),
        node_client: NodeClient::new(5).unwrap(),
        registry_client: RegistryClient::new(5).unwrap(),
        nats: None,
        registry_admin_token: None,
        bootstrap_registry_urls: vec![],
        gateway_identity: None,
        gateway_network: None,
        gateway_sync_tx: None,
        ui_stream_tx: UiStreamHub::new(sender),
    };
    let mut receiver = state.ui_stream_tx.subscribe(Some(DataKind::SpacePresence));
    let app = http::router(state);
    let mut valid = signed_space_presence(1, "using sink");
    valid.record.from_tile = [20, 68];
    valid.record.destination_place_id = "adam-smiths-house/bathroom".to_owned();
    valid.record.object_place_id = Some("adam-smiths-house/bathroom/bathroom-sink".to_owned());
    resign_space_presence(&mut valid);
    let mut wrong_kind = valid.clone();
    wrong_kind.record.seq = 2;
    wrong_kind.record.object_place_id = Some(valid.record.destination_place_id.clone());
    let mut wrong_tile = valid.clone();
    wrong_tile.record.seq = 3;
    wrong_tile.record.from_tile = [22, 66];
    resign_space_presence(&mut wrong_tile);
    let latest = wrong_tile.clone();
    let mut zero_sequence = valid.clone();
    zero_sequence.record.seq = 0;
    for (mut presence, expected) in [
        (valid.clone(), StatusCode::OK),
        (wrong_kind, StatusCode::OK),
        (wrong_tile, StatusCode::OK),
        (zero_sequence, StatusCode::BAD_REQUEST),
    ] {
        resign_space_presence(&mut presence);
        let event = space_node_event("object-validation-node", presence.record.seq, &presence);
        let response = request_json(&app, "POST", "/api/ingest/event", json!(event)).await;
        assert_eq!(response.0, expected, "{}", response.1);
        if expected == StatusCode::OK {
            assert_eq!(receiver.try_recv().unwrap().event.payload, json!(presence));
        }
        assert!(matches!(
            receiver.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
    }
    ingest_space_heartbeat(
        &app,
        "object-validation-node",
        &SigningKey::from_bytes(&[19_u8; 32]),
        chrono::Utc::now().timestamp_millis(),
    )
    .await;
    let response = request(
        &app,
        "GET",
        "/api/spaces/presence?network_id=test-network&space_id=the-ville",
    )
    .await;
    assert_eq!(response.1["presences"], json!([latest]));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from gateway_space_presence")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "select count(*) from gateway_ui_events where data_kind='space_presence'"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        3
    );
    pool.close().await;
    db.cleanup().await;
}

#[tokio::test]
async fn world_event_accepts_only_pinned_authority_and_deduplicates_relay_replays() {
    let key = SigningKey::from_bytes(&[23_u8; 32]);
    let pins = json!({
        "space-test-network":hex::encode(key.verifying_key().as_bytes()),
        "other-space-test-network":hex::encode(key.verifying_key().as_bytes())
    });
    let configured = std::env::var("WATTETHERIA_GATEWAY_TRUSTED_NETWORK_GENESIS_FILE")
        .ok()
        .and_then(|path| std::fs::read(path).ok())
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    if configured != Some(pins.clone()) {
        let path = std::env::temp_dir().join(format!(
            "gateway-space-authority-{}.json",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, serde_json::to_vec(&pins).unwrap()).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "world_event_accepts_only_pinned_authority_and_deduplicates_relay_replays",
                "--nocapture",
            ])
            .env("WATTETHERIA_GATEWAY_TRUSTED_NETWORK_GENESIS_FILE", &path)
            .output()
            .unwrap();
        std::fs::remove_file(path).unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let db = TestDatabase::new().await;
    let pool = db.pool().await;
    db::init_schema(&pool).await.unwrap();
    let (sender, _) = tokio::sync::broadcast::channel(64);
    let state = AppState {
        pool: pool.clone(),
        node_client: NodeClient::new(5).unwrap(),
        registry_client: RegistryClient::new(5).unwrap(),
        nats: None,
        registry_admin_token: None,
        bootstrap_registry_urls: vec![],
        gateway_identity: None,
        gateway_network: None,
        gateway_sync_tx: None,
        ui_stream_tx: UiStreamHub::new(sender),
    };
    let mut receiver = state.ui_stream_tx.subscribe(Some(DataKind::WorldEvent));
    let app = http::router(state);
    let mut announcement = wattswarm_protocol::types::EventAnnouncementPayload {
        announcement_id: "concert-one".to_owned(),
        network_id: "space-test-network".to_owned(),
        authority_node_id: hex::encode(key.verifying_key().as_bytes()),
        issued_at: chrono::Utc::now().timestamp_millis() as u64,
        content: json!({"event_id":"concert-one","space_id":"the-ville","place_id":"johnson-park","title":"Concert","description":"Public music","starts_at":1_800_000_000_000_i64,"ends_at":1_800_003_600_000_i64}),
        authority_signature: String::new(),
    };
    announcement.authority_signature = hex::encode(
        key.sign(&canonical_bytes(&announcement.unsigned_payload()).unwrap())
            .to_bytes(),
    );
    let value = serde_json::to_value(&announcement).unwrap();
    let mut pins = std::collections::BTreeMap::new();
    pins.insert(
        announcement.network_id.clone(),
        announcement.authority_node_id.clone(),
    );
    wattetheria_gateway::space::validate_world_event_with_authorities(&value, &pins).unwrap();
    assert!(
        wattetheria_gateway::space::validate_world_event_with_authorities(
            &value,
            &std::collections::BTreeMap::new()
        )
        .is_err()
    );
    let mut wrong_pin = pins.clone();
    wrong_pin.insert(
        announcement.network_id.clone(),
        hex::encode(
            SigningKey::from_bytes(&[24_u8; 32])
                .verifying_key()
                .as_bytes(),
        ),
    );
    assert!(
        wattetheria_gateway::space::validate_world_event_with_authorities(&value, &wrong_pin)
            .is_err()
    );
    let mut tampered = value.clone();
    tampered["content"]["title"] = json!("forged");
    assert!(
        wattetheria_gateway::space::validate_world_event_with_authorities(&tampered, &pins)
            .is_err()
    );
    for (node, expected) in [("relay-one", "ok"), ("relay-two", "duplicate")] {
        let mut event = signed_node_event(
            node,
            DataKind::WorldEvent,
            "space.world_event.published",
            value.clone(),
        );
        event.payload.provisional_policy = ProvisionalExportPolicy::NeverBeforeConfirmation;
        event.payload.timestamp = chrono::Utc::now().timestamp();
        resign_node_event(&mut event);
        assert_ne!(
            event.payload.public_key,
            base64::engine::general_purpose::STANDARD.encode(key.verifying_key().as_bytes())
        );
        let response = request_json(
            &app,
            "POST",
            "/api/ingest/event",
            serde_json::to_value(event).unwrap(),
        )
        .await;
        assert_eq!(response.0, StatusCode::OK, "{}", response.1);
        assert_eq!(response.1["status"], expected);
    }
    assert_eq!(receiver.try_recv().unwrap().event.payload, value);
    for (id, title, equal_end) in [
        ("empty-title", "", false),
        ("blank-title", "  ", false),
        ("equal-end", "Concert", true),
        ("  ", "Concert", false),
    ] {
        let mut malformed = announcement.clone();
        malformed.announcement_id = id.to_owned();
        malformed.content["event_id"] = json!(id);
        malformed.content["title"] = json!(title);
        if equal_end {
            malformed.content["ends_at"] = malformed.content["starts_at"].clone();
        }
        malformed.authority_signature = hex::encode(
            key.sign(&canonical_bytes(&malformed.unsigned_payload()).unwrap())
                .to_bytes(),
        );
        let mut event = signed_node_event(
            "malformed-product-relay",
            DataKind::WorldEvent,
            "space.world_event.published",
            json!(malformed),
        );
        event.payload.provisional_policy = ProvisionalExportPolicy::NeverBeforeConfirmation;
        resign_node_event(&mut event);
        let response = request_json(&app, "POST", "/api/ingest/event", json!(event)).await;
        assert_eq!(response.0, StatusCode::BAD_REQUEST, "{}", response.1);
        assert!(matches!(
            receiver.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
    }
    let response = request(
        &app,
        "GET",
        "/api/spaces/events?network_id=space-test-network&space_id=the-ville&place_id=johnson-park",
    )
    .await;
    assert_eq!(response.0, StatusCode::OK);
    assert_eq!(response.1["events"], json!([value]));
    let response = request(
        &app,
        "GET",
        "/api/spaces/events?network_id=space-test-network&space_id=the-ville&place_id=adam-smiths-house",
    )
    .await;
    assert_eq!(response.1["events"], json!([]));
    let mut unknown = announcement.clone();
    unknown.network_id = "untrusted-network".to_owned();
    unknown.authority_signature = hex::encode(
        key.sign(&canonical_bytes(&unknown.unsigned_payload()).unwrap())
            .to_bytes(),
    );
    let mut unknown_event = signed_node_event(
        "relay-unknown",
        DataKind::WorldEvent,
        "space.world_event.published",
        serde_json::to_value(unknown).unwrap(),
    );
    unknown_event.payload.provisional_policy = ProvisionalExportPolicy::NeverBeforeConfirmation;
    resign_node_event(&mut unknown_event);
    assert_eq!(
        request_json(
            &app,
            "POST",
            "/api/ingest/event",
            serde_json::to_value(unknown_event).unwrap()
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let mut event = signed_node_event(
        "relay-forged",
        DataKind::WorldEvent,
        "space.world_event.published",
        tampered,
    );
    event.payload.provisional_policy = ProvisionalExportPolicy::NeverBeforeConfirmation;
    resign_node_event(&mut event);
    assert_eq!(
        request_json(
            &app,
            "POST",
            "/api/ingest/event",
            serde_json::to_value(event).unwrap()
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert!(matches!(
        receiver.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from gateway_space_events")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "select count(*) from gateway_ui_events where data_kind='world_event'"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    let mut recovered = announcement.clone();
    recovered.announcement_id = "concert-recovered".to_owned();
    recovered.content["event_id"] = json!("concert-recovered");
    recovered.content["space_id"] = json!("unknown-space");
    recovered.content["place_id"] = json!("unknown-place");
    recovered.authority_signature = hex::encode(
        key.sign(&canonical_bytes(&recovered.unsigned_payload()).unwrap())
            .to_bytes(),
    );
    let recovered = serde_json::to_value(recovered).unwrap();
    let mut untrusted = serde_json::to_value(&announcement).unwrap();
    untrusted["network_id"] = json!("untrusted-network");
    let mut snapshot = signed_snapshot(
        "world-snapshot-relay",
        SnapshotContents {
            network_name: None,
            network_org_name: None,
            peers: &[],
            public_blocks: &[],
            public_topics: &[],
            public_topic_messages: &[],
            swarm_task_activity: json!({}),
            tasks: &[json!({"id":"mission-preserved","title":"Existing mission"})],
            organizations: &[],
            leaderboard: &[],
        },
    );
    snapshot.payload.world_events = vec![recovered.clone(), untrusted];
    resign_snapshot(&mut snapshot);
    assert_eq!(
        request_json(
            &app,
            "POST",
            "/api/ingest/snapshot",
            serde_json::to_value(&snapshot).unwrap()
        )
        .await
        .0,
        StatusCode::OK
    );
    snapshot.payload.generated_at += 1;
    assert_eq!(receiver.try_recv().unwrap().event.payload, recovered);
    resign_snapshot(&mut snapshot);
    assert_eq!(
        request_json(
            &app,
            "POST",
            "/api/ingest/snapshot",
            serde_json::to_value(&snapshot).unwrap()
        )
        .await
        .0,
        StatusCode::OK
    );
    let response = request(
        &app,
        "GET",
        "/api/spaces/events?network_id=space-test-network",
    )
    .await;
    assert!(matches!(
        receiver.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert_eq!(response.1["events"].as_array().unwrap().len(), 2);
    assert!(
        response.1["events"]
            .as_array()
            .unwrap()
            .contains(&recovered)
    );
    for (path, expected) in [
        (
            "/api/spaces/events?network_id=space-test-network&space_id=unknown-space&place_id=unknown-place",
            json!([recovered]),
        ),
        (
            "/api/spaces/events?network_id=space-test-network&space_id=the-ville",
            json!([value]),
        ),
        (
            "/api/spaces/events?network_id=space-test-network&place_id=unknown-place",
            json!([recovered]),
        ),
        ("/api/spaces/events?network_id=other-network", json!([])),
        (
            "/api/spaces/events?network_id=space-test-network&space_id=not-present",
            json!([]),
        ),
    ] {
        let response = request(&app, "GET", path).await;
        assert_eq!(response.0, StatusCode::OK, "{}", response.1);
        assert_eq!(response.1["events"], expected);
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "select count(*) from gateway_ui_events where data_kind='world_event'"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        2
    );
    assert_eq!(sqlx::query_scalar::<_,i64>("select count(*) from gateway_projection_rows where data_kind='task_summary' and identity_key='mission-preserved'").fetch_one(&pool).await.unwrap(),1,"unknown authority must not block other snapshot read models");
    let mut other_network = announcement.clone();
    other_network.network_id = "other-space-test-network".to_owned();
    other_network.authority_signature = hex::encode(
        key.sign(&canonical_bytes(&other_network.unsigned_payload()).unwrap())
            .to_bytes(),
    );
    let mut event = signed_node_event(
        "other-network-relay",
        DataKind::WorldEvent,
        "space.world_event.published",
        json!(other_network),
    );
    event.payload.provisional_policy = ProvisionalExportPolicy::NeverBeforeConfirmation;
    resign_node_event(&mut event);
    let ingested = request_json(&app, "POST", "/api/ingest/event", json!(event)).await;
    assert_eq!(ingested.0, StatusCode::OK, "{}", ingested.1);
    let observed = request(&app, "GET", "/api/spaces/events?space_id=the-ville").await;
    assert_eq!(observed.0, StatusCode::OK);
    assert_eq!(observed.1["events"], json!([other_network, value]));
    assert_eq!(
        request(
            &app,
            "GET",
            "/api/spaces/events?network_id=space-test-network&space_id=the-ville"
        )
        .await
        .1["events"],
        json!([value])
    );
    pool.close().await;
    db.cleanup().await;
}

fn resign_space_presence(presence: &mut wattetheria_gateway_contract::SignedSpacePresence) {
    let key = SigningKey::from_bytes(&[19_u8; 32]);
    presence.signature = base64::engine::general_purpose::STANDARD.encode(
        key.sign(&canonical_bytes(&presence.record).unwrap())
            .to_bytes(),
    );
}

#[tokio::test]
async fn space_snapshot_bootstrap_returns_every_latest_presence_and_preserves_newer_seq() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;
    let mut presences = Vec::new();
    for index in 0..205u8 {
        let key = SigningKey::from_bytes(&[index; 32]);
        let mut presence = signed_space_presence(1, "bootstrap");
        presence.public_key =
            base64::engine::general_purpose::STANDARD.encode(key.verifying_key().as_bytes());
        presence.record.agent_did = did_key_from_public_key_b64(&presence.public_key);
        presence.signature = base64::engine::general_purpose::STANDARD.encode(
            key.sign(&canonical_bytes(&presence.record).unwrap())
                .to_bytes(),
        );
        presences.push(presence);
    }
    let mut snapshot = signed_snapshot(
        "bootstrap-node",
        SnapshotContents {
            network_name: None,
            network_org_name: None,
            peers: &[],
            public_blocks: &[],
            public_topics: &[],
            public_topic_messages: &[],
            swarm_task_activity: json!({}),
            tasks: &[],
            organizations: &[],
            leaderboard: &[],
        },
    );
    snapshot.payload.space_presences = presences.clone();
    resign_snapshot(&mut snapshot);
    let response = request_json(
        &app,
        "POST",
        "/api/ingest/snapshot",
        serde_json::to_value(&snapshot).unwrap(),
    )
    .await;
    assert_eq!(response.0, StatusCode::OK, "{}", response.1);
    for index in 0..205u8 {
        ingest_space_heartbeat(
            &app,
            "bootstrap-node",
            &SigningKey::from_bytes(&[index; 32]),
            chrono::Utc::now().timestamp_millis(),
        )
        .await;
    }
    let response = request(
        &app,
        "GET",
        "/api/spaces/presence?network_id=test-network&space_id=the-ville",
    )
    .await;
    assert_eq!(
        response.1["presences"].as_array().unwrap().len(),
        205,
        "REST bootstrap must not use WS replay's 200 limit"
    );
    let newer = signed_space_presence(2, "fresh event");
    let event = space_node_event("event-node", 1, &newer);
    assert_eq!(
        request_json(
            &app,
            "POST",
            "/api/ingest/event",
            serde_json::to_value(&event).unwrap()
        )
        .await
        .0,
        StatusCode::OK
    );
    snapshot.payload.generated_at += 1;
    resign_snapshot(&mut snapshot);
    assert_eq!(
        request_json(
            &app,
            "POST",
            "/api/ingest/snapshot",
            serde_json::to_value(&snapshot).unwrap()
        )
        .await
        .0,
        StatusCode::OK
    );
    let response = request(
        &app,
        "GET",
        &format!(
            "/api/spaces/presence/{}?network_id=test-network&space_id=the-ville",
            newer.record.agent_did
        ),
    )
    .await;
    assert_eq!(response.1["presence"], json!(newer));
    let mut invalid = snapshot.clone();
    invalid.payload.generated_at += 100;
    invalid.payload.space_presences[0].record.activity = "unsigned forged activity".to_owned();
    assert_eq!(
        request_json(
            &app,
            "POST",
            "/api/ingest/snapshot",
            serde_json::to_value(invalid).unwrap()
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let pool = db.pool().await;
    let persisted: sqlx::types::Json<Value> =
        sqlx::query_scalar("select payload from node_snapshots where node_id='bootstrap-node'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        persisted.0["generated_at"],
        json!(snapshot.payload.generated_at),
        "invalid outer signature must be rejected before snapshot mutation"
    );
    pool.close().await;
    db.cleanup().await;
}

fn space_node_event(
    node: &str,
    seq: u64,
    presence: &wattetheria_gateway_contract::SignedSpacePresence,
) -> SignedNodeEvent {
    let mut event = signed_node_event(
        node,
        DataKind::SpacePresence,
        "space.presence.changed",
        serde_json::to_value(presence).unwrap(),
    );
    event.payload.event_id = format!("{node}:{seq}");
    event.payload.seq = seq;
    event.payload.timestamp = chrono::Utc::now().timestamp();
    event.payload.provisional_policy = ProvisionalExportPolicy::NeverBeforeConfirmation;
    resign_node_event(&mut event);
    event
}

fn signed_space_heartbeat(
    node_id: &str,
    key: &SigningKey,
    last_heartbeat_ms: i64,
    heartbeat_interval_sec: i64,
) -> SignedNodeEvent {
    let mut event = signed_node_event(
        node_id,
        DataKind::Presence,
        "node.presence.heartbeat",
        json!({}),
    );
    event.payload.public_key =
        base64::engine::general_purpose::STANDARD.encode(key.verifying_key().as_bytes());
    event.payload.signer_agent_did = did_key_from_public_key_b64(&event.payload.public_key);
    event.payload.event_id = format!("{node_id}:heartbeat:{last_heartbeat_ms}");
    event.payload.timestamp = last_heartbeat_ms / 1000;
    event.payload.provisional_policy = ProvisionalExportPolicy::EphemeralOnly;
    event.payload.payload = json!({
        "node_id": node_id,
        "agent_did": event.payload.signer_agent_did,
        "last_heartbeat_ms": last_heartbeat_ms,
        "heartbeat_interval_sec": heartbeat_interval_sec,
    });
    event.signature = base64::engine::general_purpose::STANDARD.encode(
        key.sign(&canonical_bytes(&event.payload).unwrap())
            .to_bytes(),
    );
    event
}

async fn ingest_space_heartbeat(
    app: &Router,
    node_id: &str,
    key: &SigningKey,
    last_heartbeat_ms: i64,
) {
    let event = signed_space_heartbeat(node_id, key, last_heartbeat_ms, 20);
    let response = request_json(app, "POST", "/api/ingest/event", json!(event)).await;
    assert_eq!(response.0, StatusCode::OK, "{}", response.1);
}

#[tokio::test]
async fn local_network_identifier_uses_visible_metadata_without_product_activity() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;
    let path = "/api/network/status?federation=local";
    let empty = request(&app, "GET", path).await;
    assert_eq!(empty.0, StatusCode::OK);
    assert_eq!(empty.1.get("network_id"), Some(&Value::Null));
    let mut snapshot = signed_snapshot(
        "clean-network-node",
        SnapshotContents {
            network_name: None,
            network_org_name: None,
            peers: &[],
            public_blocks: &[],
            public_topics: &[],
            public_topic_messages: &[],
            swarm_task_activity: json!({}),
            tasks: &[],
            organizations: &[],
            leaderboard: &[],
        },
    );
    snapshot.payload.network_status["network_id"] = json!("metadata-network");
    resign_snapshot(&mut snapshot);
    let response = request_json(&app, "POST", "/api/ingest/snapshot", json!(snapshot)).await;
    assert_eq!(response.0, StatusCode::OK, "{}", response.1);
    assert_eq!(
        request(&app, "GET", path).await.1["network_id"],
        "metadata-network"
    );
    assert_eq!(
        request(&app, "GET", "/api/network/nodes?federation=local")
            .await
            .1,
        json!([])
    );
    assert!(snapshot.payload.space_presences.is_empty());
    assert!(snapshot.payload.world_events.is_empty());
    assert!(snapshot.payload.public_board_messages.is_empty());
    assert!(snapshot.payload.public_topics.is_empty());
    assert!(snapshot.payload.public_topic_messages.is_empty());
    let pool = db.pool().await;
    let source_id = uuid::Uuid::new_v4();
    sqlx::query("insert into node_sources(id,name,export_url,source_status) values($1,'network metadata','http://127.0.0.1/network-metadata','active')")
        .bind(source_id).execute(&pool).await.unwrap();
    for (index, payload, expected) in [
        (json!({"network_id":"metadata-network"}), json!("metadata-network")),
        (json!({"network_status":{"network_id":"other-network"}}), Value::Null),
        (json!({"network_id":"metadata-network","network_status":{"network_id":"other-network"}}), Value::Null),
        (json!({"network_status":{"network_id":"metadata-network"}}), json!("metadata-network")),
    ].into_iter().enumerate().map(|(index, (payload, expected))| (index, payload, expected)) {
        db::upsert_projection_row(&pool, UpsertProjectionRecord {
            data_kind: "network_projection",
            identity_key: "network-metadata-source",
            source_node_id: "network-metadata-source",
            source_id: Some(source_id),
            generated_at: 1_710_000_001 + index as i64,
            visibility: "public",
            payload: &payload,
            provenance: &json!({"source":"network metadata test"}),
        }).await.unwrap();
        assert_eq!(request(&app, "GET", path).await.1["network_id"], expected);
    }
    let conflicting = json!({"network_id":"inactive-network"});
    db::upsert_projection_row(
        &pool,
        UpsertProjectionRecord {
            data_kind: "network_projection",
            identity_key: "network-metadata-source",
            source_node_id: "network-metadata-source",
            source_id: Some(source_id),
            generated_at: 1_710_000_010,
            visibility: "public",
            payload: &conflicting,
            provenance: &json!({"source":"network metadata test"}),
        },
    )
    .await
    .unwrap();
    assert!(request(&app, "GET", path).await.1["network_id"].is_null());
    for status in ["suspended", "invalid"] {
        sqlx::query("update node_sources set source_status=$1 where id=$2")
            .bind(status)
            .bind(source_id)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            request(&app, "GET", path).await.1["network_id"],
            "metadata-network"
        );
    }
    let stored: (sqlx::types::Json<Value>, String) = sqlx::query_as(
        "select payload,signature from node_snapshots where node_id='clean-network-node'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored.0.0, json!(snapshot.payload));
    assert_eq!(stored.1, snapshot.signature);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from gateway_space_presence")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from gateway_space_events")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("select count(*) from gateway_ui_events")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    pool.close().await;
    db.cleanup().await;
}

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

    let pool = db.pool().await;
    let outbox_count: i64 = sqlx::query_scalar("select count(*) from gateway_p2p_outbox")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(outbox_count, 0);

    db.cleanup().await;
}

#[tokio::test]
async fn ingest_snapshot_announces_applied_snapshot_to_p2p_sync() {
    let db = TestDatabase::new().await;
    let pool = db::connect(&db.database_url).await.unwrap();
    db::init_schema(&pool).await.unwrap();
    let (ui_stream_tx, _) = tokio::sync::broadcast::channel(64);
    let (gateway_sync_tx, mut gateway_sync_rx) = tokio::sync::mpsc::channel(8);
    let app = http::router(AppState {
        pool,
        node_client: NodeClient::new(5).unwrap(),
        registry_client: RegistryClient::new(5).unwrap(),
        nats: None,
        registry_admin_token: Some("registry-secret".to_string()),
        bootstrap_registry_urls: Vec::new(),
        gateway_identity: None,
        gateway_network: None,
        gateway_sync_tx: Some(gateway_sync_tx),
        ui_stream_tx: UiStreamHub::new(ui_stream_tx),
    });
    let snapshot = signed_snapshot(
        "node-p2p-announce",
        SnapshotContents {
            network_name: None,
            network_org_name: None,
            peers: &[],
            public_blocks: &[],
            public_topics: &[],
            public_topic_messages: &[],
            swarm_task_activity: json!({}),
            tasks: &[json!({"id":"task-p2p-announce"})],
            organizations: &[],
            leaderboard: &[],
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

    let command = tokio::time::timeout(std::time::Duration::from_secs(1), gateway_sync_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let GatewayP2pSyncCommand = command;

    let pool = db.pool().await;
    let row: (String, serde_json::Value) = sqlx::query_as(
        "select command_kind, payload from gateway_p2p_outbox where dedupe_key = $1",
    )
    .bind(format!(
        "snapshot:{}:{}",
        snapshot.payload.node_id, snapshot.payload.generated_at
    ))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.0, db::P2P_OUTBOX_COMMAND_SNAPSHOT);
    assert_eq!(row.1["node_id"].as_str(), Some("node-p2p-announce"));

    db.cleanup().await;
}

#[tokio::test]
async fn ingest_node_event_announces_applied_event_to_p2p_sync() {
    let db = TestDatabase::new().await;
    let pool = db::connect(&db.database_url).await.unwrap();
    db::init_schema(&pool).await.unwrap();
    let (ui_stream_tx, _) = tokio::sync::broadcast::channel(64);
    let (gateway_sync_tx, mut gateway_sync_rx) = tokio::sync::mpsc::channel(8);
    let app = http::router(AppState {
        pool,
        node_client: NodeClient::new(5).unwrap(),
        registry_client: RegistryClient::new(5).unwrap(),
        nats: None,
        registry_admin_token: Some("registry-secret".to_string()),
        bootstrap_registry_urls: Vec::new(),
        gateway_identity: None,
        gateway_network: None,
        gateway_sync_tx: Some(gateway_sync_tx),
        ui_stream_tx: UiStreamHub::new(ui_stream_tx),
    });
    let event = signed_node_event(
        "node-p2p-event",
        DataKind::MissionLifecycle,
        "mission.published",
        json!({"id":"task-p2p-event","status":"published"}),
    );

    let ingest = request_json(
        &app,
        "POST",
        "/api/ingest/event",
        serde_json::to_value(&event).unwrap(),
    )
    .await;
    assert_eq!(ingest.0, StatusCode::OK);

    let command = tokio::time::timeout(std::time::Duration::from_secs(1), gateway_sync_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let GatewayP2pSyncCommand = command;

    let pool = db.pool().await;
    let row: (String, serde_json::Value) = sqlx::query_as(
        "select command_kind, payload from gateway_p2p_outbox where dedupe_key = $1",
    )
    .bind(format!("event:{}", event.payload.event_id))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.0, db::P2P_OUTBOX_COMMAND_EVENT);
    assert_eq!(row.1["payload"]["event_id"], event.payload.event_id);
    assert_eq!(row.1["signature"], event.signature);

    db.cleanup().await;
}

#[tokio::test]
async fn p2p_outbox_claim_ack_release_and_retry_limit_are_consistent() {
    let db = TestDatabase::new().await;
    let pool = db.pool().await;
    db::init_schema(&pool).await.unwrap();
    for index in 0..2 {
        sqlx::query(
            r#"
            insert into gateway_p2p_outbox (dedupe_key, command_kind, payload)
            values ($1, $2, $3)
            "#,
        )
        .bind(format!("test-outbox-{index}"))
        .bind(db::P2P_OUTBOX_COMMAND_EVENT)
        .bind(sqlx::types::Json(json!({"index": index})))
        .execute(&pool)
        .await
        .unwrap();
    }

    let (first_claim, second_claim) = tokio::join!(
        db::claim_p2p_outbox(&pool, 1),
        db::claim_p2p_outbox(&pool, 1)
    );
    let first = first_claim.unwrap().pop().unwrap();
    let second = second_claim.unwrap().pop().unwrap();
    assert_ne!(first.id, second.id);
    assert_eq!(first.attempts, 1);
    assert_eq!(second.attempts, 1);
    assert!(db::claim_p2p_outbox(&pool, 2).await.unwrap().is_empty());

    assert!(!db::release_p2p_outbox(&pool, first.id).await.unwrap());
    assert!(db::claim_p2p_outbox(&pool, 1).await.unwrap().is_empty());
    sqlx::query(
        "update gateway_p2p_outbox set claimed_until = now() - interval '1 second' where id = $1",
    )
    .bind(first.id)
    .execute(&pool)
    .await
    .unwrap();
    let retried = db::claim_p2p_outbox(&pool, 1).await.unwrap().pop().unwrap();
    assert_eq!(retried.id, first.id);
    assert_eq!(retried.attempts, 2);
    db::ack_p2p_outbox(&pool, retried.id).await.unwrap();

    sqlx::query("update gateway_p2p_outbox set attempts = $2, claimed_until = null where id = $1")
        .bind(second.id)
        .bind(db::P2P_OUTBOX_MAX_ATTEMPTS - 1)
        .execute(&pool)
        .await
        .unwrap();
    let exhausted = db::claim_p2p_outbox(&pool, 1).await.unwrap().pop().unwrap();
    assert_eq!(exhausted.attempts, db::P2P_OUTBOX_MAX_ATTEMPTS);
    assert!(db::release_p2p_outbox(&pool, exhausted.id).await.unwrap());

    let remaining: i64 = sqlx::query_scalar("select count(*) from gateway_p2p_outbox")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining, 0);

    drop(pool);
    db.cleanup().await;
}

#[tokio::test]
async fn earliest_ui_event_cursor_stops_at_first_visible_source_event() {
    let db = TestDatabase::new().await;
    let pool = db.pool().await;
    db::init_schema(&pool).await.unwrap();
    let suspended_source_id = uuid::Uuid::new_v4();
    let active_source_id = uuid::Uuid::new_v4();
    for (id, name, status) in [
        (suspended_source_id, "suspended", "suspended"),
        (active_source_id, "active", "active"),
    ] {
        db::insert_node_source(
            &pool,
            db::InsertNodeSourceRecord {
                id,
                name,
                export_url: &format!("https://{name}.example/export"),
                wattetheria_snapshot_export_url: None,
                wattetheria_events_export_url: None,
                wattswarm_ui_base_url: None,
                wattswarm_sync_grpc_endpoint: None,
                region: None,
                expected_signer_agent_did: None,
                expected_wattswarm_node_id: None,
                source_status: status,
                transport_capabilities: None,
                transport_contact_material: None,
            },
        )
        .await
        .unwrap();
    }
    for (source_id, event_id) in [
        (suspended_source_id, "event-suspended"),
        (active_source_id, "event-active"),
    ] {
        db::insert_ui_event(
            &pool,
            db::InsertUiEventRecord {
                event_id,
                source_id: Some(source_id),
                node_id: "node-cursor-test",
                signer_agent_did: "did:key:cursor-test",
                data_kind: "presence",
                event_kind: "presence.updated",
                visibility: "public",
                provisional: false,
                topic_id: None,
                organization_id: None,
                task_id: None,
                generated_at: 1,
                payload: &json!({"event_id": event_id}),
                ingest_path: "test",
                source_cursor_or_seq: None,
            },
        )
        .await
        .unwrap();
    }

    let active_cursor: i64 =
        sqlx::query_scalar("select cursor from gateway_ui_events where event_id = 'event-active'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        db::earliest_ui_event_cursor(&pool).await.unwrap(),
        Some(active_cursor)
    );

    drop(pool);
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
async fn public_hives_member_count_uses_latest_subscription_projection_state() {
    let db = TestDatabase::new().await;
    let pool = db.pool().await;
    db::init_schema(&pool).await.unwrap();
    let app = test_app(&db.database_url).await;
    let provenance = json!({"ingest_path": "test"});
    let hive = json!({
        "topic_id": "topic-members",
        "hive_id": "topic-members",
        "network_id": "mainnet:test",
        "feed_key": "crew.chat",
        "scope_hint": "group:crew-7",
        "display_name": "Crew Hive",
        "last_message_at": "2026-03-18T02:00:00Z"
    });
    db::upsert_projection_row(
        &pool,
        UpsertProjectionRecord {
            data_kind: "hive_metadata",
            identity_key: "topic-members",
            source_node_id: "node-owner",
            source_id: None,
            generated_at: 100,
            visibility: "public",
            payload: &hive,
            provenance: &provenance,
        },
    )
    .await
    .unwrap();

    for subscriber in ["node-alpha", "node-beta"] {
        let subscription = json!({
            "subscription_id": format!("mainnet:test\u{1f}crew.chat\u{1f}group:crew-7\u{1f}{subscriber}"),
            "network_id": "mainnet:test",
            "feed_key": "crew.chat",
            "scope_hint": "group:crew-7",
            "subscriber_node_id": subscriber,
            "active": true,
            "updated_at": 110
        });
        db::upsert_projection_row(
            &pool,
            UpsertProjectionRecord {
                data_kind: "hive_subscription",
                identity_key: subscription["subscription_id"].as_str().unwrap(),
                source_node_id: subscriber,
                source_id: None,
                generated_at: 110,
                visibility: "public",
                payload: &subscription,
                provenance: &provenance,
            },
        )
        .await
        .unwrap();
    }

    let hives = request(&app, "GET", "/api/hives?limit=10").await;
    assert_eq!(hives.0, StatusCode::OK);
    assert_eq!(hives.1[0]["member_count"].as_u64(), Some(2));

    let inactive = json!({
        "subscription_id": "mainnet:test\u{1f}crew.chat\u{1f}group:crew-7\u{1f}node-beta",
        "network_id": "mainnet:test",
        "feed_key": "crew.chat",
        "scope_hint": "group:crew-7",
        "subscriber_node_id": "node-beta",
        "active": false,
        "updated_at": 120
    });
    db::upsert_projection_row(
        &pool,
        UpsertProjectionRecord {
            data_kind: "hive_subscription",
            identity_key: inactive["subscription_id"].as_str().unwrap(),
            source_node_id: "node-beta",
            source_id: None,
            generated_at: 120,
            visibility: "public",
            payload: &inactive,
            provenance: &provenance,
        },
    )
    .await
    .unwrap();

    let hives = request(&app, "GET", "/api/hives?limit=10").await;
    assert_eq!(hives.0, StatusCode::OK);
    assert_eq!(hives.1[0]["member_count"].as_u64(), Some(1));

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
        gateway_sync_tx: None,
        ui_stream_tx: UiStreamHub::new(ui_stream_tx),
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

    let duplicate_cursor =
        wattetheria_gateway::streaming::persist_signed_node_event(&state, &event, None, None)
            .await
            .unwrap();
    assert_eq!(duplicate_cursor, None);
    let duplicate_streamed = ui_stream_rx.recv().await.unwrap();
    assert_eq!(duplicate_streamed.event_id, event.payload.event_id);
    assert_eq!(duplicate_streamed.cursor, 0);

    let persisted_count: i64 = sqlx::query_scalar("select count(*) from gateway_ui_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(persisted_count, 0);

    drop(pool);
    db.cleanup().await;
}

#[tokio::test]
async fn duplicate_event_from_shared_database_is_replayed_to_local_stream() {
    let db = TestDatabase::new().await;
    let pool = db.pool().await;
    db::init_schema(&pool).await.unwrap();

    let (ui_stream_tx_a, _) = tokio::sync::broadcast::channel(64);
    let (ui_stream_tx_b, mut ui_stream_rx_b) = tokio::sync::broadcast::channel(64);
    let (gateway_sync_tx, _gateway_sync_rx) = tokio::sync::mpsc::channel(8);
    let state_a = AppState {
        pool: pool.clone(),
        node_client: NodeClient::new(5).unwrap(),
        registry_client: RegistryClient::new(5).unwrap(),
        nats: None,
        registry_admin_token: Some("registry-secret".to_string()),
        bootstrap_registry_urls: Vec::new(),
        gateway_identity: None,
        gateway_network: None,
        gateway_sync_tx: Some(gateway_sync_tx),
        ui_stream_tx: UiStreamHub::new(ui_stream_tx_a),
    };
    let state_b = AppState {
        pool: pool.clone(),
        node_client: NodeClient::new(5).unwrap(),
        registry_client: RegistryClient::new(5).unwrap(),
        nats: None,
        registry_admin_token: Some("registry-secret".to_string()),
        bootstrap_registry_urls: Vec::new(),
        gateway_identity: None,
        gateway_network: None,
        gateway_sync_tx: None,
        ui_stream_tx: UiStreamHub::new(ui_stream_tx_b),
    };
    let event = signed_node_event(
        "node-shared-db",
        DataKind::MissionLifecycle,
        "mission.published",
        json!({"id":"mission-shared-db","status":"published"}),
    );

    let first_cursor =
        wattetheria_gateway::streaming::persist_signed_node_event(&state_a, &event, None, None)
            .await
            .unwrap();
    assert!(first_cursor.is_some());
    let outbox_count: i64 = sqlx::query_scalar(
        "select count(*) from gateway_p2p_outbox where command_kind = 'event_v1'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(outbox_count, 1);

    let duplicate_cursor =
        wattetheria_gateway::streaming::persist_signed_node_event(&state_b, &event, None, None)
            .await
            .unwrap();
    assert_eq!(duplicate_cursor, None);
    let streamed = tokio::time::timeout(std::time::Duration::from_secs(1), ui_stream_rx_b.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(streamed.event_id, event.payload.event_id);

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
async fn public_board_messages_are_ingested_from_signed_snapshot() {
    let db = TestDatabase::new().await;
    let snapshot = signed_snapshot_with_board(
        "node-board-snapshot",
        SnapshotContents {
            network_name: None,
            network_org_name: None,
            peers: &[],
            public_blocks: &[],
            public_topics: &[],
            public_topic_messages: &[],
            swarm_task_activity: json!({}),
            tasks: &[],
            organizations: &[],
            leaderboard: &[],
        },
        &[json!({
            "message_id": "board-snapshot-1",
            "source": "network",
            "category": "general",
            "network_id": "network-board",
            "feed_key": "wattetheria.board.general",
            "scope_hint": "group:board-general",
            "author_node_id": "node-board-author",
            "content": {"text": "snapshot board message"},
            "created_at": 1_780_114_500
        })],
    );
    let app = test_app(&db.database_url).await;
    let ingest = request_json(
        &app,
        "POST",
        "/api/ingest/snapshot",
        serde_json::to_value(&snapshot).unwrap(),
    )
    .await;
    assert_eq!(ingest.0, StatusCode::OK);

    let board = request(
        &app,
        "GET",
        "/api/board?source=network&category=general&network_id=network-board&limit=10&federation=local",
    )
    .await;
    assert_eq!(board.0, StatusCode::OK);
    assert_eq!(board.1.as_array().unwrap().len(), 1);
    assert_eq!(board.1[0]["message_id"].as_str(), Some("board-snapshot-1"));
    assert_eq!(board.1[0]["category"].as_str(), Some("general"));
    assert_eq!(
        board.1[0]["source_node_id"].as_str(),
        Some("node-board-snapshot")
    );

    db.cleanup().await;
}

#[tokio::test]
async fn forged_global_board_announcements_are_dropped_on_snapshot_and_push() {
    let db = TestDatabase::new().await;
    let impostor = SigningKey::from_bytes(&[29_u8; 32]);
    let mut announcement = wattswarm_protocol::types::EventAnnouncementPayload {
        announcement_id: "forged-concert".to_owned(),
        network_id: "space-test-network".to_owned(),
        authority_node_id: hex::encode(impostor.verifying_key().as_bytes()),
        issued_at: 1_800_000_000_000,
        content: json!({"event_id":"forged-concert","space_id":"the-ville","place_id":"johnson-park","title":"Forged","starts_at":1_800_000_000_000_i64,"ends_at":1_800_003_600_000_i64}),
        authority_signature: String::new(),
    };
    announcement.authority_signature = hex::encode(
        impostor
            .sign(&canonical_bytes(&announcement.unsigned_payload()).unwrap())
            .to_bytes(),
    );
    let forged = json!({
        "message_id": "forged-global",
        "source": "global",
        "category": "global",
        "global_kind": "EventAnnouncement",
        "content": {"type": "EventAnnouncement", "payload": announcement},
        "world_event": announcement.content,
        "created_at": 1_780_114_500
    });
    let snapshot = signed_snapshot_with_board(
        "node-board-forger",
        SnapshotContents {
            network_name: None,
            network_org_name: None,
            peers: &[],
            public_blocks: &[],
            public_topics: &[],
            public_topic_messages: &[],
            swarm_task_activity: json!({}),
            tasks: &[],
            organizations: &[],
            leaderboard: &[],
        },
        &[
            forged.clone(),
            json!({
                "message_id": "plain-with-event",
                "source": "network",
                "category": "general",
                "content": {"text": "hello"},
                "world_event": announcement.content,
                "created_at": 1_780_114_400
            }),
        ],
    );
    let app = test_app(&db.database_url).await;
    let ingest = request_json(
        &app,
        "POST",
        "/api/ingest/snapshot",
        serde_json::to_value(&snapshot).unwrap(),
    )
    .await;
    assert_eq!(ingest.0, StatusCode::OK);

    let mut pushed = forged.clone();
    pushed["message_id"] = json!("forged-global-push");
    let mut event = signed_node_event(
        "node-board-forger",
        DataKind::BoardActivity,
        "board.message.posted",
        pushed,
    );
    event.payload.provisional_policy = ProvisionalExportPolicy::NeverBeforeConfirmation;
    event.payload.scope.task_id = None;
    event.payload.identity_key = Some("forged-global-push".to_string());
    resign_node_event(&mut event);
    let push = request_json(
        &app,
        "POST",
        "/api/ingest/event",
        serde_json::to_value(&event).unwrap(),
    )
    .await;
    assert_ne!(push.0, StatusCode::OK);

    let board = request(&app, "GET", "/api/board?limit=10&federation=local").await;
    assert_eq!(board.0, StatusCode::OK);
    let rows = board.1.as_array().unwrap();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["message_id"].as_str(), Some("plain-with-event"));
    assert!(rows[0].get("world_event").is_none());

    db.cleanup().await;
}

#[tokio::test]
async fn board_message_event_materializes_board_projection() {
    let db = TestDatabase::new().await;
    let app = test_app(&db.database_url).await;
    let mut event = signed_node_event(
        "node-board-event",
        DataKind::BoardActivity,
        "board.message.posted",
        json!({
            "message_id": "board-event-1",
            "author_node_id": "node-board-author",
            "source": "service",
            "category": "services",
            "network_id": "network-board",
            "service_name": "weather-agent",
            "feed_key": "wattetheria.board.services",
            "scope_hint": "group:board-services",
            "content": {"text": "event board message"},
            "created_at": 1_780_114_500
        }),
    );
    event.payload.provisional_policy = ProvisionalExportPolicy::NeverBeforeConfirmation;
    event.payload.scope.task_id = None;
    event.payload.identity_key = Some("board-event-1".to_string());
    resign_node_event(&mut event);

    let ingest = request_json(
        &app,
        "POST",
        "/api/ingest/event",
        serde_json::to_value(&event).unwrap(),
    )
    .await;
    assert_eq!(ingest.0, StatusCode::OK);

    let board = request(
        &app,
        "GET",
        "/api/board?source=services&service_name=weather-agent&limit=10&federation=local",
    )
    .await;
    assert_eq!(board.0, StatusCode::OK);
    assert_eq!(board.1.as_array().unwrap().len(), 1);
    assert_eq!(board.1[0]["message_id"].as_str(), Some("board-event-1"));
    assert_eq!(board.1[0]["source"].as_str(), Some("service"));
    assert_eq!(
        board.1[0]["source_node_id"].as_str(),
        Some("node-board-event")
    );

    db.cleanup().await;
}

#[tokio::test]
async fn board_event_stream_payload_matches_rest_projection() {
    let db = TestDatabase::new().await;
    let pool = db.pool().await;
    db::init_schema(&pool).await.unwrap();
    let (sender, _) = tokio::sync::broadcast::channel(64);
    let state = AppState {
        pool: pool.clone(),
        node_client: NodeClient::new(5).unwrap(),
        registry_client: RegistryClient::new(5).unwrap(),
        nats: None,
        registry_admin_token: None,
        bootstrap_registry_urls: vec![],
        gateway_identity: None,
        gateway_network: None,
        gateway_sync_tx: None,
        ui_stream_tx: UiStreamHub::new(sender),
    };
    let mut receiver = state.ui_stream_tx.subscribe(Some(DataKind::BoardActivity));
    let app = http::router(state);
    // Live node board events carry no created_at; the projection fills it from the event time.
    let mut event = signed_node_event(
        "node-board-live",
        DataKind::BoardActivity,
        "board.message.posted",
        json!({
            "message_id": "board-live-1",
            "author_agent_did": "did:key:board-live-author",
            "source": "network",
            "category": "general",
            "network_id": "network-board",
            "feed_key": "wattetheria.board.general",
            "scope_hint": "group:board-general",
            "content": "hello town"
        }),
    );
    event.payload.provisional_policy = ProvisionalExportPolicy::NeverBeforeConfirmation;
    event.payload.scope.task_id = None;
    event.payload.identity_key = Some("board-live-1".to_string());
    resign_node_event(&mut event);

    let ingest = request_json(
        &app,
        "POST",
        "/api/ingest/event",
        serde_json::to_value(&event).unwrap(),
    )
    .await;
    assert_eq!(ingest.0, StatusCode::OK);

    let board = request(
        &app,
        "GET",
        "/api/board?source=network&category=general&limit=10&federation=local",
    )
    .await;
    assert_eq!(board.0, StatusCode::OK);
    let rest = &board.1[0];
    // Event timestamps are seconds; board created_at is milliseconds like the node's own store.
    assert_eq!(rest["created_at"], json!(event.payload.timestamp * 1000));
    let live = receiver.try_recv().unwrap().event.payload;
    let replay = db::list_ui_events_after(
        &pool,
        db::ListUiEventsQuery {
            cursor: 0,
            data_kind: Some("board_activity"),
            node_id: None,
            topic_id: None,
            organization_id: None,
            task_id: None,
            limit: 10,
        },
    )
    .await
    .unwrap();
    let replayed = &replay[0].payload.0;
    for key in [
        "message_id",
        "created_at",
        "source_node_id",
        "network_id",
        "content",
    ] {
        assert_eq!(live[key], rest[key], "live stream {key}");
        assert_eq!(replayed[key], rest[key], "replayed stream {key}");
    }

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
    write_test_relay_urls(&remote_state_dir);
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
    if !contact_has_direct_addr(&remote_contact) {
        db.cleanup().await;
        return;
    }
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
        gateway_sync_tx: None,
        ui_stream_tx: UiStreamHub::new(ui_stream_tx),
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
        gateway_sync_tx: None,
        ui_stream_tx: UiStreamHub::new(ui_stream_tx),
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
        gateway_sync_tx: None,
        ui_stream_tx: UiStreamHub::new(ui_stream_tx),
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
        gateway_sync_tx: None,
        ui_stream_tx: UiStreamHub::new(ui_stream_tx),
    })
}

async fn test_app_with_network(
    database_url: &str,
) -> (Router, GatewayNetworkRuntime, GatewayNetworkHandle) {
    let pool = db::connect(database_url).await.unwrap();
    db::init_schema(&pool).await.unwrap();
    let (ui_stream_tx, _) = tokio::sync::broadcast::channel(64);
    let state_dir = unique_state_dir("gateway-local");
    write_test_relay_urls(&state_dir);
    let runtime = GatewayNetworkRuntime::new(
        GatewayNetworkNode::generate(wattetheria_gateway::config::GatewayP2pConfig {
            enabled: true,
            state_dir,
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
        gateway_sync_tx: None,
        ui_stream_tx: UiStreamHub::new(ui_stream_tx),
    });
    (app, runtime, gateway_network)
}

fn unique_state_dir(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4().simple()))
}

fn write_test_relay_urls(state_dir: &Path) {
    std::fs::create_dir_all(state_dir).unwrap();
    std::fs::write(
        state_dir.join("startup_config.json"),
        r#"{"relay_urls":["https://relay.example.invalid/"]}"#,
    )
    .unwrap();
}

fn contact_has_direct_addr(contact: &TransportContactMaterial) -> bool {
    contact
        .extra
        .get("direct_addrs")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|items| !items.is_empty())
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
    if std::env::var_os("WATTETHERIA_GATEWAY_TEST_DATABASE_URL").is_none() {
        POSTGRES_READY.get_or_init(|| {
            let status = Command::new("docker")
                .args([
                    "compose",
                    "-f",
                    "../../docker-compose.yml",
                    "-f",
                    "../../docker-compose.dev.yml",
                    "up",
                    "-d",
                    "postgres",
                ])
                .current_dir(env!("CARGO_MANIFEST_DIR"))
                .status()
                .expect("run docker compose with the dev overlay up -d postgres");
            assert!(status.success(), "postgres compose service failed to start");
        });
    }

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

fn signed_snapshot_with_board(
    node_id: &str,
    contents: SnapshotContents<'_>,
    board_messages: &[Value],
) -> SignedPublicClientSnapshot {
    let mut snapshot = signed_snapshot(node_id, contents);
    snapshot.payload.public_board_messages = board_messages.to_vec();
    resign_snapshot(&mut snapshot);
    snapshot
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
        agent_identity: None,
        public_id: None,
        public_key: public_key.clone(),
        network_name: contents.network_name.map(str::to_string),
        network_org_name: contents.network_org_name.map(str::to_string),
        network_status: json!({
            "total_nodes": contents.peers.len() + 1,
            "active_nodes": contents.peers.len() + 1,
            "health_percent": 100,
            "avg_latency_ms": 0
        }),
        nodes: None,
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
        public_board_messages: vec![],
        space_presences: vec![],
        node_presence: None,
        world_events: vec![],
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

fn resign_snapshot(snapshot: &mut SignedPublicClientSnapshot) {
    let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
    snapshot.signature = base64::engine::general_purpose::STANDARD.encode(
        signing_key
            .sign(&canonical_bytes(&snapshot.payload).unwrap())
            .to_bytes(),
    );
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
