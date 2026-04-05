use crate::db;
use crate::gateway_network::{GatewayNetworkHandle, persist_snapshot_artifact};
use crate::models::{
    BootstrapRegistryEntry, DiscoveredGatewayEntry, GatewayRegistryQuery, ListQuery,
    RegisterGatewayRequest, RegisterGatewayResponse, RegisterNodeRequest, RegisterNodeResponse,
    ReviewGatewayRequest, SelfRegisterGatewayBatchResponse, SelfRegisterGatewayRequest,
    SelfRegisterGatewayResponse, SignedPublicClientSnapshot, SyncRequest, SyncResult,
    TopicMessageQuery, TopicQuery,
};
use crate::state::AppState;
use crate::verify::{verify_signed_gateway_manifest, verify_signed_snapshot};
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{
    Json, Router,
    routing::{get, post},
};
use serde_json::{Value, json};
use uuid::Uuid;
use wattswarm_network_transport_core::{PeerTransportCapabilities, TransferIntent, TransferKind};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/nodes/register", post(register_node))
        .route("/api/nodes/sync", post(sync_nodes))
        .route("/api/ingest/snapshot", post(ingest_snapshot))
        .route("/api/registry/self-manifest", get(self_manifest))
        .route("/api/registry/self-register", post(self_register_gateway))
        .route("/api/registry/bootstrap", get(list_bootstrap_registries))
        .route("/api/registry/discovery", get(discovery_gateways))
        .route("/api/registry/gateways/register", post(register_gateway))
        .route("/api/registry/gateways", get(list_public_gateways))
        .route(
            "/api/registry/gateways/{gateway_id}",
            get(get_public_gateway),
        )
        .route("/api/admin/registry/gateways", get(list_admin_gateways))
        .route(
            "/api/admin/registry/gateways/{gateway_id}/review",
            post(review_gateway),
        )
        .route("/api/nodes", get(list_nodes))
        .route("/api/network/status", get(network_status))
        .route("/api/peers", get(peers))
        .route("/api/topics", get(public_topics))
        .route("/api/topic-messages", get(public_topic_messages))
        .route("/api/tasks", get(tasks))
        .route("/api/organizations", get(organizations))
        .route("/api/leaderboard", get(leaderboard))
        .with_state(state)
}

async fn healthz(State(state): State<AppState>) -> Response {
    match db::counts(&state.pool).await {
        Ok((source_count, snapshot_count)) => Json(json!({
            "status": "ok",
            "sources": source_count,
            "snapshots": snapshot_count,
        }))
        .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn register_node(
    State(state): State<AppState>,
    Json(body): Json<RegisterNodeRequest>,
) -> Response {
    if body.name.trim().is_empty() || body.export_url.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "name and export_url are required"})),
        )
            .into_response();
    }
    let source_id = Uuid::new_v4();
    match db::insert_node_source(
        &state.pool,
        db::InsertNodeSourceRecord {
            id: source_id,
            name: body.name.trim(),
            export_url: body.export_url.trim(),
            region: body.region.as_deref(),
            expected_signer_agent_did: body.expected_signer_agent_did.as_deref(),
            transport_capabilities: body
                .transport_capabilities
                .as_ref()
                .map(serde_json::to_value)
                .transpose()
                .unwrap_or(None)
                .as_ref(),
            transport_contact_material: body
                .transport_contact_material
                .as_ref()
                .map(serde_json::to_value)
                .transpose()
                .unwrap_or(None)
                .as_ref(),
        },
    )
    .await
    {
        Ok(()) => {
            let event = json!({
                "event": "gateway.node.registered",
                "source_id": source_id,
                "name": body.name.trim(),
                "export_url": body.export_url.trim(),
                "region": body.region,
                "timestamp": db::now_rfc3339(),
            });
            let _ = state.publish_event("gateway.node.registered", &event).await;
            (
                StatusCode::CREATED,
                Json(RegisterNodeResponse {
                    source_id,
                    name: body.name,
                    export_url: body.export_url,
                }),
            )
                .into_response()
        }
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn register_gateway(
    State(state): State<AppState>,
    Json(body): Json<RegisterGatewayRequest>,
) -> Response {
    if let Err(error) = verify_signed_gateway_manifest(&body.manifest) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": error.to_string()})),
        )
            .into_response();
    }
    match db::upsert_gateway_manifest(
        &state.pool,
        db::UpsertGatewayManifestRecord {
            manifest: &body.manifest,
        },
    )
    .await
    {
        Ok(entry) => {
            let event = json!({
                "event": "gateway.registry.registered",
                "gateway_id": entry.gateway_id,
                "base_url": entry.base_url,
                "status": entry.status,
                "discovery_tier": entry.discovery_tier,
                "timestamp": db::now_rfc3339(),
            });
            let _ = state
                .publish_event("gateway.registry.registered", &event)
                .await;
            (
                StatusCode::CREATED,
                Json(RegisterGatewayResponse {
                    gateway_id: entry.gateway_id,
                    status: entry.status,
                    discovery_tier: entry.discovery_tier,
                }),
            )
                .into_response()
        }
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn self_manifest(State(state): State<AppState>) -> Response {
    let Some(identity) = &state.gateway_identity else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "gateway identity is not configured"})),
        )
            .into_response();
    };
    match identity.signed_manifest() {
        Ok(manifest) => Json(manifest).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn self_register_gateway(
    State(state): State<AppState>,
    Json(body): Json<SelfRegisterGatewayRequest>,
) -> Response {
    let Some(identity) = &state.gateway_identity else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "gateway identity is not configured"})),
        )
            .into_response();
    };
    let registry_urls = if let Some(registry_url) = body.registry_url.as_deref() {
        if registry_url.trim().is_empty() {
            Vec::new()
        } else {
            vec![registry_url.to_string()]
        }
    } else {
        state.bootstrap_registry_urls.clone()
    };
    if registry_urls.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "registry_url is required or bootstrap registries must be configured"})),
        )
            .into_response();
    }
    let manifest = match identity.signed_manifest() {
        Ok(manifest) => manifest,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": error.to_string()})),
            )
                .into_response();
        }
    };
    let request = RegisterGatewayRequest { manifest };
    let mut results = Vec::with_capacity(registry_urls.len());
    for registry_url in registry_urls {
        let register_url = crate::registry_client::normalized_registry_register_url(&registry_url);
        let payload = match state
            .registry_client
            .register_manifest(&registry_url, &request)
            .await
        {
            Ok(payload) => payload,
            Err(error) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({"error": error.to_string(), "registry_url": register_url})),
                )
                    .into_response();
            }
        };
        let event = json!({
            "event": "gateway.registry.self_registered",
            "gateway_id": payload.gateway_id,
            "registry_url": register_url,
            "status": payload.status,
            "discovery_tier": payload.discovery_tier,
            "timestamp": db::now_rfc3339(),
        });
        let _ = state
            .publish_event("gateway.registry.self_registered", &event)
            .await;
        results.push(SelfRegisterGatewayResponse {
            registry_url: register_url,
            gateway_id: payload.gateway_id,
            status: payload.status,
            discovery_tier: payload.discovery_tier,
        });
    }
    Json(SelfRegisterGatewayBatchResponse { results }).into_response()
}

async fn list_public_gateways(
    State(state): State<AppState>,
    Query(query): Query<GatewayRegistryQuery>,
) -> Response {
    match db::list_gateway_registry_entries(
        &state.pool,
        Some("approved"),
        query.tier.as_deref(),
        query.region.as_deref(),
        query.role.as_deref(),
    )
    .await
    {
        Ok(entries) => Json(entries).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn list_bootstrap_registries(State(state): State<AppState>) -> Response {
    Json(
        state
            .bootstrap_registry_urls
            .iter()
            .map(|registry_url| BootstrapRegistryEntry {
                registry_url: registry_url.clone(),
            })
            .collect::<Vec<_>>(),
    )
    .into_response()
}

async fn discovery_gateways(
    State(state): State<AppState>,
    Query(query): Query<GatewayRegistryQuery>,
) -> Response {
    let mut discovered = Vec::<DiscoveredGatewayEntry>::new();
    let local_entries = match db::list_gateway_registry_entries(
        &state.pool,
        Some("approved"),
        query.tier.as_deref(),
        query.region.as_deref(),
        query.role.as_deref(),
    )
    .await
    {
        Ok(entries) => entries,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": error.to_string()})),
            )
                .into_response();
        }
    };
    discovered.extend(
        local_entries
            .into_iter()
            .map(|gateway| DiscoveredGatewayEntry {
                source_registry_url: "local".to_string(),
                gateway,
            }),
    );

    for registry_url in &state.bootstrap_registry_urls {
        match state
            .registry_client
            .fetch_public_gateways(registry_url)
            .await
        {
            Ok(entries) => {
                for gateway in entries {
                    if gateway_matches_filters(&gateway, &query)
                        && !discovered.iter().any(|entry| {
                            entry.gateway.gateway_id == gateway.gateway_id
                                || entry.gateway.base_url == gateway.base_url
                        })
                    {
                        discovered.push(DiscoveredGatewayEntry {
                            source_registry_url:
                                crate::registry_client::normalized_registry_list_url(registry_url),
                            gateway,
                        });
                    }
                }
            }
            Err(error) => {
                let event = json!({
                    "event": "gateway.registry.discovery_fetch_failed",
                    "registry_url": registry_url,
                    "error": error.to_string(),
                    "timestamp": db::now_rfc3339(),
                });
                let _ = state
                    .publish_event("gateway.registry.discovery_fetch_failed", &event)
                    .await;
            }
        }
    }

    Json(discovered).into_response()
}

fn gateway_matches_filters(
    gateway: &crate::models::GatewayRegistryEntry,
    query: &GatewayRegistryQuery,
) -> bool {
    if let Some(region) = query.region.as_deref()
        && gateway.region.as_deref() != Some(region)
    {
        return false;
    }
    if let Some(tier) = query.tier.as_deref()
        && gateway.discovery_tier != tier
    {
        return false;
    }
    if let Some(role) = query.role.as_deref()
        && !gateway.roles.iter().any(|candidate| candidate == role)
    {
        return false;
    }
    true
}

async fn get_public_gateway(
    State(state): State<AppState>,
    Path(gateway_id): Path<String>,
) -> Response {
    match db::get_gateway_registry_entry(&state.pool, &gateway_id).await {
        Ok(Some(entry)) if entry.status == "approved" => Json(entry).into_response(),
        Ok(Some(_)) | Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "gateway not found"})),
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn list_admin_gateways(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<GatewayRegistryQuery>,
) -> Response {
    if let Some(response) = authorize_registry_admin(&state, &headers) {
        return response;
    }
    match db::list_gateway_registry_entries(
        &state.pool,
        None,
        query.tier.as_deref(),
        query.region.as_deref(),
        query.role.as_deref(),
    )
    .await
    {
        Ok(entries) => Json(entries).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn review_gateway(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(gateway_id): Path<String>,
    Json(body): Json<ReviewGatewayRequest>,
) -> Response {
    if let Some(response) = authorize_registry_admin(&state, &headers) {
        return response;
    }
    let status = match normalized_gateway_registry_status(&body.status) {
        Ok(status) => status,
        Err(error) => {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": error}))).into_response();
        }
    };
    let discovery_tier = match normalized_gateway_discovery_tier(body.discovery_tier.as_deref()) {
        Ok(tier) => tier,
        Err(error) => {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": error}))).into_response();
        }
    };
    match db::review_gateway_manifest(
        &state.pool,
        &gateway_id,
        status,
        discovery_tier,
        body.reason.as_deref(),
        body.reviewed_by.as_deref(),
    )
    .await
    {
        Ok(Some(entry)) => {
            let event = json!({
                "event": "gateway.registry.reviewed",
                "gateway_id": entry.gateway_id,
                "status": entry.status,
                "discovery_tier": entry.discovery_tier,
                "reviewed_by": entry.reviewed_by,
                "timestamp": db::now_rfc3339(),
            });
            let _ = state
                .publish_event("gateway.registry.reviewed", &event)
                .await;
            Json(entry).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "gateway not found"})),
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn sync_nodes(State(state): State<AppState>, Json(body): Json<SyncRequest>) -> Response {
    let sources = match resolve_sources(&state, body.source_id).await {
        Ok(sources) => sources,
        Err(response) => return response,
    };
    let known_snapshots = match db::list_snapshots(&state.pool).await {
        Ok(rows) => rows,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": error.to_string()})),
            )
                .into_response();
        }
    };
    let mut results = Vec::with_capacity(sources.len());
    for source in sources {
        let known_snapshot = known_snapshots
            .iter()
            .find(|row| row.source_id == Some(source.id));
        let fetched = match fetch_snapshot_for_source(&state, &source, known_snapshot).await {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let message = error.to_string();
                let _ =
                    db::update_source_sync_status(&state.pool, source.id, "error", Some(&message))
                        .await;
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({"error": message, "source_id": source.id})),
                )
                    .into_response();
            }
        };
        if let Err(error) =
            verify_signed_snapshot(&fetched, source.expected_signer_agent_did.as_deref())
        {
            let message = error.to_string();
            let _ =
                db::update_source_sync_status(&state.pool, source.id, "invalid", Some(&message))
                    .await;
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": message, "source_id": source.id})),
            )
                .into_response();
        }
        if let Err(error) = ingest_signed_snapshot(&state, &fetched, Some(source.id), None).await {
            let message = error.to_string();
            let _ = db::update_source_sync_status(&state.pool, source.id, "error", Some(&message))
                .await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": message, "source_id": source.id})),
            )
                .into_response();
        }
        let _ = db::update_source_sync_status(&state.pool, source.id, "ok", None).await;
        results.push(SyncResult {
            source_id: Some(source.id),
            node_id: fetched.payload.node_id,
            signer_agent_did: fetched.signer_agent_did,
            generated_at: fetched.payload.generated_at,
        });
    }
    Json(results).into_response()
}

async fn fetch_snapshot_for_source(
    state: &AppState,
    source: &crate::models::NodeSourceRow,
    known_snapshot: Option<&crate::models::SnapshotRow>,
) -> anyhow::Result<SignedPublicClientSnapshot> {
    if let Some(snapshot) = try_fetch_snapshot_via_iroh(state, source, known_snapshot).await? {
        return Ok(snapshot);
    }
    state
        .node_client
        .fetch_signed_snapshot(&source.export_url)
        .await
}

async fn try_fetch_snapshot_via_iroh(
    state: &AppState,
    source: &crate::models::NodeSourceRow,
    known_snapshot: Option<&crate::models::SnapshotRow>,
) -> anyhow::Result<Option<SignedPublicClientSnapshot>> {
    let Some(handle) = state.gateway_network.as_ref() else {
        return Ok(None);
    };
    let Some(contact) = source
        .transport_contact_material
        .as_ref()
        .map(|value| value.0.clone())
    else {
        return Ok(None);
    };
    let Some(snapshot) = known_snapshot else {
        return Ok(None);
    };
    let fetched = state
        .node_client
        .fetch_signed_snapshot_via_iroh(
            &handle.state_dir,
            &handle.local_peer_id,
            &contact,
            &snapshot.node_id,
        )
        .await?;
    Ok(Some(fetched))
}

fn authorize_registry_admin(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    let Some(expected_token) = state.registry_admin_token.as_deref() else {
        return Some(
            (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "registry admin token is not configured"})),
            )
                .into_response(),
        );
    };
    let Some(value) = headers.get("authorization") else {
        return Some(
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "missing authorization header"})),
            )
                .into_response(),
        );
    };
    let Ok(value) = value.to_str() else {
        return Some(
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "invalid authorization header"})),
            )
                .into_response(),
        );
    };
    let provided = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "));
    match provided {
        Some(token) if token == expected_token => None,
        _ => Some(
            (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "invalid registry admin token"})),
            )
                .into_response(),
        ),
    }
}

fn normalized_gateway_registry_status(status: &str) -> Result<&'static str, &'static str> {
    match status {
        "pending" => Ok("pending"),
        "approved" => Ok("approved"),
        "rejected" => Ok("rejected"),
        "suspended" => Ok("suspended"),
        _ => Err("unsupported status; expected pending, approved, rejected, or suspended"),
    }
}

fn normalized_gateway_discovery_tier(
    discovery_tier: Option<&str>,
) -> Result<&'static str, &'static str> {
    match discovery_tier.unwrap_or("community") {
        "official" => Ok("official"),
        "verified" => Ok("verified"),
        "community" => Ok("community"),
        "manual" => Ok("manual"),
        _ => Err("unsupported discovery_tier; expected official, verified, community, or manual"),
    }
}

async fn ingest_snapshot(
    State(state): State<AppState>,
    Json(snapshot): Json<SignedPublicClientSnapshot>,
) -> Response {
    match ingest_signed_snapshot(&state, &snapshot, None, None).await {
        Ok(()) => Json(json!({
            "status": "ok",
            "node_id": snapshot.payload.node_id,
            "signer_agent_did": snapshot.signer_agent_did,
            "generated_at": snapshot.payload.generated_at,
        }))
        .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn list_nodes(State(state): State<AppState>) -> Response {
    match db::list_node_sources(&state.pool).await {
        Ok(sources) => {
            let snapshots = match db::list_snapshots(&state.pool).await {
                Ok(rows) => rows,
                Err(error) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": error.to_string()})),
                    )
                        .into_response();
                }
            };
            let response = sources
                .into_iter()
                .map(|source| {
                    let snapshot = snapshots
                        .iter()
                        .find(|row| row.source_id == Some(source.id));
                    json!({
                        "source_id": source.id,
                        "name": source.name,
                        "export_url": source.export_url,
                        "region": source.region,
                        "expected_signer_agent_did": source.expected_signer_agent_did,
                        "last_sync_at": source.last_sync_at,
                        "last_sync_status": source.last_sync_status,
                        "last_error": source.last_error,
                        "transport_capabilities": source.transport_capabilities.as_ref().map(|value| json!(value.0)),
                        "transport_contact_material": source.transport_contact_material.as_ref().map(|value| json!(value.0)),
                        "recommended_routes": source.transport_capabilities.as_ref().map(|value| recommended_routes(&value.0)),
                        "snapshot": snapshot.map(|row| json!({
                            "node_id": row.node_id,
                            "signer_agent_did": row.signer_agent_did,
                            "generated_at": row.generated_at,
                            "ingested_at": row.ingested_at,
                            "network_name": row.payload.0["network_name"],
                            "network_org_name": row.payload.0["network_org_name"],
                        })),
                    })
                })
                .chain(
                    snapshots
                        .iter()
                        .filter(|row| row.source_id.is_none())
                        .map(|row| {
                            json!({
                                "source_id": Value::Null,
                                "name": row.node_id,
                                "export_url": Value::Null,
                                "region": Value::Null,
                                "expected_signer_agent_did": Value::Null,
                                "last_sync_at": row.ingested_at,
                                "last_sync_status": "push",
                                "last_error": Value::Null,
                                "transport_capabilities": Value::Null,
                                "transport_contact_material": Value::Null,
                                "recommended_routes": Value::Null,
                                "snapshot": {
                                    "node_id": row.node_id,
                                    "signer_agent_did": row.signer_agent_did,
                                    "generated_at": row.generated_at,
                                    "ingested_at": row.ingested_at,
                                    "network_name": row.payload.0["network_name"],
                                    "network_org_name": row.payload.0["network_org_name"],
                                },
                            })
                        }),
                )
                .collect::<Vec<_>>();
            Json(response).into_response()
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn ingest_signed_snapshot(
    state: &AppState,
    snapshot: &SignedPublicClientSnapshot,
    source_id: Option<Uuid>,
    expected_signer_agent_did: Option<&str>,
) -> anyhow::Result<()> {
    verify_signed_snapshot(snapshot, expected_signer_agent_did)?;
    let payload_json = serde_json::to_value(&snapshot.payload)?;
    if let Some(handle) = &state.gateway_network {
        persist_snapshot_artifact(&handle.state_dir, snapshot)?;
    }
    db::upsert_snapshot(
        &state.pool,
        db::UpsertSnapshotRecord {
            source_id,
            node_id: &snapshot.payload.node_id,
            signer_agent_did: &snapshot.signer_agent_did,
            public_key: &snapshot.payload.public_key,
            generated_at: snapshot.payload.generated_at,
            payload: &payload_json,
            signature: &snapshot.signature,
        },
    )
    .await?;
    let event = json!({
        "event": "gateway.snapshot.ingested",
        "source_id": source_id,
        "node_id": snapshot.payload.node_id,
        "signer_agent_did": snapshot.signer_agent_did,
        "generated_at": snapshot.payload.generated_at,
        "timestamp": db::now_rfc3339(),
    });
    let _ = state
        .publish_event("gateway.snapshot.ingested", &event)
        .await;
    Ok(())
}

async fn network_status(State(state): State<AppState>) -> Response {
    match db::list_snapshots(&state.pool).await {
        Ok(rows) => {
            let snapshots = rows.iter().map(|row| &row.payload.0).collect::<Vec<_>>();
            let network_name = single_shared_string(&snapshots, "network_name");
            let network_org_name = single_shared_string(&snapshots, "network_org_name");
            let total_nodes = snapshots.len();
            let total_peers = snapshots
                .iter()
                .map(|payload| payload["peers"].as_array().map_or(0, Vec::len))
                .sum::<usize>();
            let total_tasks = snapshots
                .iter()
                .map(|payload| payload["tasks"].as_array().map_or(0, Vec::len))
                .sum::<usize>();
            let total_organizations = snapshots
                .iter()
                .map(|payload| payload["organizations"].as_array().map_or(0, Vec::len))
                .sum::<usize>();
            let total_topics = snapshots
                .iter()
                .map(|payload| payload["public_topics"].as_array().map_or(0, Vec::len))
                .sum::<usize>();
            let total_topic_messages = snapshots
                .iter()
                .map(|payload| {
                    payload["public_topic_messages"]
                        .as_array()
                        .map_or(0, Vec::len)
                })
                .sum::<usize>();
            Json(json!({
                "status": "ok",
                "nodes": total_nodes,
                "peers": total_peers,
                "tasks": total_tasks,
                "organizations": total_organizations,
                "topics": total_topics,
                "topic_messages": total_topic_messages,
                "network_name": network_name,
                "network_org_name": network_org_name,
                "gateway_runtime": state.gateway_network.as_ref().map(gateway_runtime_status),
                "updated_at": db::now_rfc3339(),
            }))
            .into_response()
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

fn gateway_runtime_status(runtime: &GatewayNetworkHandle) -> Value {
    json!({
        "peer_id": runtime.info.peer_id,
        "listen_addrs": runtime.info.listen_addrs,
        "transport_capabilities": runtime.info.transport_capabilities,
        "transport_contact_material": runtime.info.transport_contact_material,
        "nat_status": runtime.info.nat_status,
        "nat_public_address": runtime.info.nat_public_address,
        "nat_confidence": runtime.info.nat_confidence,
        "relay_reservations": runtime.info.relay_reservations,
        "peer_health": runtime.info.peer_health.iter().map(|entry| json!({
            "peer": entry.peer,
            "score": entry.score,
            "blacklisted": entry.blacklisted,
            "reputation_tier": entry.reputation_tier,
            "quarantined": entry.quarantined,
            "quarantine_remaining_ms": entry.quarantine_remaining_ms,
            "ban_remaining_ms": entry.ban_remaining_ms,
            "throttle_factor_percent": entry.throttle_factor_percent,
        })).collect::<Vec<_>>(),
    })
}

fn recommended_routes(capabilities: &PeerTransportCapabilities) -> Value {
    json!({
        "control_message": route_for(capabilities, TransferKind::ControlMessage, 512, false),
        "backfill_chunk": route_for(capabilities, TransferKind::BackfillChunk, 128 * 1024, false),
        "artifact_blob": route_for(capabilities, TransferKind::ArtifactBlob, 128 * 1024, true),
        "checkpoint_snapshot": route_for(capabilities, TransferKind::CheckpointSnapshot, 128 * 1024, true),
    })
}

fn route_for(
    capabilities: &PeerTransportCapabilities,
    kind: TransferKind,
    payload_bytes: usize,
    requires_streaming: bool,
) -> &'static str {
    wattswarm_network_transport_core::TransportRouter::select(
        &TransferIntent {
            kind,
            payload_bytes,
            requires_streaming,
        },
        Some(capabilities),
    )
    .as_str()
}

fn single_shared_string(snapshots: &[&Value], key: &str) -> Value {
    let mut values = snapshots
        .iter()
        .filter_map(|payload| payload[key].as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    match values.as_slice() {
        [value] => Value::String(value.clone()),
        _ => Value::Null,
    }
}

async fn peers(State(state): State<AppState>, Query(query): Query<ListQuery>) -> Response {
    aggregate_array_endpoint(
        &state,
        query.limit.unwrap_or(200),
        "peers",
        |source_id, value| attach_source(value, source_id),
    )
    .await
}

async fn public_topics(State(state): State<AppState>, Query(query): Query<TopicQuery>) -> Response {
    aggregate_public_topics_endpoint(&state, query).await
}

async fn public_topic_messages(
    State(state): State<AppState>,
    Query(query): Query<TopicMessageQuery>,
) -> Response {
    aggregate_public_topic_messages_endpoint(&state, query).await
}

async fn tasks(State(state): State<AppState>, Query(query): Query<ListQuery>) -> Response {
    aggregate_array_endpoint(
        &state,
        query.limit.unwrap_or(200),
        "tasks",
        |source_id, value| attach_source(value, source_id),
    )
    .await
}

async fn organizations(State(state): State<AppState>, Query(query): Query<ListQuery>) -> Response {
    aggregate_array_endpoint(
        &state,
        query.limit.unwrap_or(200),
        "organizations",
        |source_id, value| attach_source(value, source_id),
    )
    .await
}

async fn leaderboard(State(state): State<AppState>, Query(query): Query<ListQuery>) -> Response {
    aggregate_array_endpoint(
        &state,
        query.limit.unwrap_or(200),
        "leaderboard",
        |source_id, value| attach_source(value, source_id),
    )
    .await
}

async fn aggregate_public_topics_endpoint(state: &AppState, query: TopicQuery) -> Response {
    match db::list_snapshots(&state.pool).await {
        Ok(rows) => {
            let mut values = Vec::new();
            for row in rows {
                if let Some(entries) = row.payload.0["public_topics"].as_array() {
                    for entry in entries.iter().cloned() {
                        let topic = attach_snapshot_metadata(
                            attach_source(entry, row.node_id.clone()),
                            row.generated_at,
                        );
                        if matches_topic_filters(&topic, &query) {
                            values.push(topic);
                        }
                    }
                }
            }
            sort_values_desc_by_timestamp(&mut values);
            dedupe_values_by_key(&mut values, topic_identity_key);
            values.truncate(query.limit.unwrap_or(200));
            Json(values).into_response()
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn aggregate_public_topic_messages_endpoint(
    state: &AppState,
    query: TopicMessageQuery,
) -> Response {
    match db::list_snapshots(&state.pool).await {
        Ok(rows) => {
            let mut values = Vec::new();
            for row in rows {
                if let Some(entries) = row.payload.0["public_topic_messages"].as_array() {
                    for entry in entries.iter().cloned() {
                        let message = attach_snapshot_metadata(
                            attach_source(entry, row.node_id.clone()),
                            row.generated_at,
                        );
                        if matches_topic_message_filters(&message, &query) {
                            values.push(message);
                        }
                    }
                }
            }
            sort_values_desc_by_timestamp(&mut values);
            dedupe_values_by_key(&mut values, topic_message_identity_key);
            values.truncate(query.limit.unwrap_or(500));
            Json(values).into_response()
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn aggregate_array_endpoint<F>(
    state: &AppState,
    limit: usize,
    key: &str,
    transform: F,
) -> Response
where
    F: Fn(String, Value) -> Value,
{
    match db::list_snapshots(&state.pool).await {
        Ok(rows) => {
            let mut values = Vec::new();
            for row in rows {
                if let Some(entries) = row.payload.0[key].as_array() {
                    values.extend(
                        entries
                            .iter()
                            .take(limit)
                            .cloned()
                            .map(|value| transform(row.node_id.clone(), value)),
                    );
                }
            }
            values.truncate(limit);
            Json(values).into_response()
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

fn attach_source(mut value: Value, source_node_id: String) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.insert("source_node_id".to_string(), Value::String(source_node_id));
    }
    value
}

fn attach_snapshot_metadata(mut value: Value, generated_at: i64) -> Value {
    if let Some(object) = value.as_object_mut()
        && !object.contains_key("snapshot_generated_at")
    {
        object.insert(
            "snapshot_generated_at".to_string(),
            Value::Number(generated_at.into()),
        );
    }
    value
}

fn matches_topic_filters(value: &Value, query: &TopicQuery) -> bool {
    matches_optional_string_filter(value, &["topic_id", "id"], query.topic_id.as_deref())
        && matches_optional_string_filter(
            value,
            &["organization_id", "organizationId"],
            query.organization_id.as_deref(),
        )
}

fn matches_topic_message_filters(value: &Value, query: &TopicMessageQuery) -> bool {
    matches_optional_string_filter(value, &["topic_id", "topicId"], query.topic_id.as_deref())
        && matches_optional_string_filter(
            value,
            &["organization_id", "organizationId"],
            query.organization_id.as_deref(),
        )
        && matches_optional_string_filter(
            value,
            &["author_id", "authorId", "sender_id", "senderId"],
            query.author_id.as_deref(),
        )
}

fn matches_optional_string_filter(value: &Value, keys: &[&str], expected: Option<&str>) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .is_some_and(|actual| actual == expected)
}

fn sort_values_desc_by_timestamp(values: &mut [Value]) {
    values.sort_by_key(|value| std::cmp::Reverse(topic_sort_timestamp(value)));
}

fn topic_sort_timestamp(value: &Value) -> i64 {
    for key in [
        "last_message_at",
        "updated_at",
        "created_at",
        "timestamp",
        "sent_at",
        "snapshot_generated_at",
    ] {
        if let Some(number) = value.get(key).and_then(value_to_timestamp) {
            return number;
        }
    }
    0
}

fn value_to_timestamp(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_str().and_then(parse_timestamp_str))
}

fn parse_timestamp_str(value: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|timestamp| timestamp.timestamp())
}

fn dedupe_values_by_key<F>(values: &mut Vec<Value>, key_fn: F)
where
    F: Fn(&Value) -> Option<String>,
{
    let mut seen = std::collections::BTreeSet::new();
    values.retain(|value| {
        let Some(identity) = key_fn(value) else {
            return true;
        };
        seen.insert(identity)
    });
}

fn topic_identity_key(value: &Value) -> Option<String> {
    topic_key_from_value(value, &["topic_id", "id"])
}

fn topic_message_identity_key(value: &Value) -> Option<String> {
    topic_key_from_value(value, &["message_id", "id"]).or_else(|| {
        let topic_id = value
            .get("topic_id")
            .or_else(|| value.get("topicId"))
            .and_then(Value::as_str)?;
        let author_id = value
            .get("author_id")
            .or_else(|| value.get("authorId"))
            .or_else(|| value.get("sender_id"))
            .or_else(|| value.get("senderId"))
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let timestamp = topic_sort_timestamp(value);
        let body = value
            .get("body")
            .or_else(|| value.get("content"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        Some(format!("{topic_id}:{author_id}:{timestamp}:{body}"))
    })
}

fn topic_key_from_value(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::to_string)
}

async fn resolve_sources(
    state: &AppState,
    source_id: Option<Uuid>,
) -> Result<Vec<crate::models::NodeSourceRow>, Response> {
    match source_id {
        Some(source_id) => match db::get_node_source(&state.pool, source_id).await {
            Ok(Some(source)) => Ok(vec![source]),
            Ok(None) => Err((
                StatusCode::NOT_FOUND,
                Json(json!({"error": "unknown source_id"})),
            )
                .into_response()),
            Err(error) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": error.to_string()})),
            )
                .into_response()),
        },
        None => match db::list_node_sources(&state.pool).await {
            Ok(sources) if !sources.is_empty() => Ok(sources),
            Ok(_) => Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "no node sources registered"})),
            )
                .into_response()),
            Err(error) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": error.to_string()})),
            )
                .into_response()),
        },
    }
}
