use crate::collectors::collect_wattswarm_read_models;
use crate::db;
use crate::gateway_network::persist_snapshot_artifact;
use crate::models::{
    BootstrapRegistryEntry, DiscoveredGatewayEntry, GatewayRegistryQuery, RegisterGatewayRequest,
    RegisterGatewayResponse, RegisterNodeRequest, RegisterNodeResponse, ReviewGatewayRequest,
    SelfRegisterGatewayBatchResponse, SelfRegisterGatewayRequest, SelfRegisterGatewayResponse,
    SignedPublicClientSnapshot, SyncRequest, SyncResult,
};
use crate::read_models::persist_snapshot_read_models;
use crate::state::AppState;
use crate::streaming;
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

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/nodes/register", post(register_node))
        .route("/api/nodes/sync", post(sync_nodes))
        .route("/api/ingest/snapshot", post(ingest_snapshot))
        .route("/api/ingest/event", post(streaming::ingest_node_event))
        .route("/api/stream", get(streaming::stream))
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
        .route(
            "/api/network/status",
            get(crate::public_api::network_status),
        )
        .route("/api/peers", get(crate::public_api::peers))
        .route("/api/topics", get(crate::public_api::public_topics))
        .route(
            "/api/topic-messages",
            get(crate::public_api::public_topic_messages),
        )
        .route("/api/friends", get(crate::public_api::friend_relationships))
        .route(
            "/api/friend-requests",
            get(crate::public_api::pending_friend_requests),
        )
        .route("/api/blocks", get(crate::public_api::public_blocks))
        .route("/api/dm/threads", get(crate::public_api::dm_threads))
        .route("/api/dm/messages", get(crate::public_api::dm_messages))
        .route("/api/tasks", get(crate::public_api::tasks))
        .route("/api/task-activity", get(crate::public_api::task_activity))
        .route("/api/organizations", get(crate::public_api::organizations))
        .route("/api/leaderboard", get(crate::public_api::leaderboard))
        .with_state(state)
}

async fn healthz(State(state): State<AppState>) -> Response {
    match db::counts(&state.pool).await {
        Ok(counts) => Json(json!({
            "status": "ok",
            "sources": counts.source_count,
            "active_sources": counts.active_source_count,
            "snapshots": counts.snapshot_count,
            "projections": counts.projection_count,
            "ui_events": counts.ui_event_count,
            "backfill_events": counts.backfill_event_count,
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
    let snapshot_export_url = body
        .wattetheria_snapshot_export_url
        .as_deref()
        .or(body.export_url.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if body.name.trim().is_empty() || snapshot_export_url.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "name and a wattetheria snapshot export URL are required"})),
        )
            .into_response();
    }
    let export_url = snapshot_export_url.expect("validated snapshot export url");
    let source_id = Uuid::new_v4();
    match db::insert_node_source(
        &state.pool,
        db::InsertNodeSourceRecord {
            id: source_id,
            name: body.name.trim(),
            export_url,
            wattetheria_snapshot_export_url: Some(export_url),
            wattetheria_events_export_url: body
                .wattetheria_events_export_url
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty()),
            wattswarm_ui_base_url: body
                .wattswarm_ui_base_url
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty()),
            wattswarm_sync_grpc_endpoint: body
                .wattswarm_sync_grpc_endpoint
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty()),
            region: body.region.as_deref(),
            expected_signer_agent_did: body.expected_signer_agent_did.as_deref(),
            expected_wattswarm_node_id: body.expected_wattswarm_node_id.as_deref(),
            source_status: match body.source_status.unwrap_or_default() {
                crate::contracts::SourceStatus::Active => "active",
                crate::contracts::SourceStatus::Suspended => "suspended",
                crate::contracts::SourceStatus::Rejected => "rejected",
            },
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
                "export_url": export_url,
                "region": body.region,
                "timestamp": db::now_rfc3339(),
            });
            let _ = state.publish_event("gateway.node.registered", &event).await;
            (
                StatusCode::CREATED,
                Json(RegisterNodeResponse {
                    source_id,
                    name: body.name,
                    export_url: export_url.to_string(),
                    source_status: body.source_status.unwrap_or_default(),
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
        let (sync_status, wattswarm_collect_error) = if let Err(error) =
            collect_wattswarm_read_models(&state, &source).await
        {
            let message = error.to_string();
            let _ =
                db::update_source_sync_status(&state.pool, source.id, "partial", Some(&message))
                    .await;
            ("partial".to_string(), Some(message))
        } else {
            let _ = db::update_source_sync_status(&state.pool, source.id, "ok", None).await;
            ("ok".to_string(), None)
        };
        results.push(SyncResult {
            source_id: Some(source.id),
            node_id: fetched.payload.node_id,
            signer_agent_did: fetched.signer_agent_did,
            generated_at: fetched.payload.generated_at,
            sync_status,
            wattswarm_collect_error,
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
        .fetch_signed_snapshot(
            source
                .wattetheria_snapshot_export_url
                .as_deref()
                .unwrap_or(&source.export_url),
        )
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
    let resolved_source = match db::find_node_source_for_identity(
        &state.pool,
        &snapshot.payload.node_id,
        &snapshot.signer_agent_did,
    )
    .await
    {
        Ok(source) => source,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": error.to_string()})),
            )
                .into_response();
        }
    };
    if resolved_source
        .as_ref()
        .is_some_and(|source| source.source_status != "active")
    {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "source is not active for push ingest"})),
        )
            .into_response();
    }
    match ingest_signed_snapshot(
        &state,
        &snapshot,
        resolved_source.as_ref().map(|source| source.id),
        resolved_source
            .as_ref()
            .and_then(|source| source.expected_signer_agent_did.as_deref()),
    )
    .await
    {
        Ok(_) => Json(json!({
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
                        "wattetheria_snapshot_export_url": source.wattetheria_snapshot_export_url,
                        "wattetheria_events_export_url": source.wattetheria_events_export_url,
                        "wattswarm_ui_base_url": source.wattswarm_ui_base_url,
                        "wattswarm_sync_grpc_endpoint": source.wattswarm_sync_grpc_endpoint,
                        "region": source.region,
                        "expected_signer_agent_did": source.expected_signer_agent_did,
                        "expected_wattswarm_node_id": source.expected_wattswarm_node_id,
                        "source_status": source.source_status,
                        "last_sync_at": source.last_sync_at,
                        "last_sync_status": source.last_sync_status,
                        "last_error": source.last_error,
                        "transport_capabilities": source.transport_capabilities.as_ref().map(|value| json!(value.0)),
                        "transport_contact_material": source.transport_contact_material.as_ref().map(|value| json!(value.0)),
                        "recommended_routes": source.transport_capabilities.as_ref().map(|value| crate::public_api::recommended_routes(&value.0)),
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
                                "wattetheria_snapshot_export_url": Value::Null,
                                "wattetheria_events_export_url": Value::Null,
                                "wattswarm_ui_base_url": Value::Null,
                                "wattswarm_sync_grpc_endpoint": Value::Null,
                                "region": Value::Null,
                                "expected_signer_agent_did": Value::Null,
                                "expected_wattswarm_node_id": Value::Null,
                                "source_status": "push",
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

pub(crate) async fn ingest_signed_snapshot(
    state: &AppState,
    snapshot: &SignedPublicClientSnapshot,
    source_id: Option<Uuid>,
    expected_signer_agent_did: Option<&str>,
) -> anyhow::Result<bool> {
    verify_signed_snapshot(snapshot, expected_signer_agent_did)?;
    let payload_json = serde_json::to_value(&snapshot.payload)?;
    if let Some(handle) = &state.gateway_network {
        persist_snapshot_artifact(&handle.state_dir, snapshot)?;
    }
    let applied = db::upsert_snapshot(
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
    if applied {
        persist_snapshot_read_models(&state.pool, source_id, &snapshot.payload).await?;
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
    }
    Ok(applied)
}

async fn resolve_sources(
    state: &AppState,
    source_id: Option<Uuid>,
) -> Result<Vec<crate::models::NodeSourceRow>, Response> {
    match source_id {
        Some(source_id) => match db::get_node_source(&state.pool, source_id).await {
            Ok(Some(source)) if source.source_status == "active" => Ok(vec![source]),
            Ok(Some(_)) => Err((
                StatusCode::CONFLICT,
                Json(json!({"error": "source is not active"})),
            )
                .into_response()),
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
            Ok(sources) => {
                let active = sources
                    .into_iter()
                    .filter(|source| source.source_status == "active")
                    .collect::<Vec<_>>();
                if !active.is_empty() {
                    Ok(active)
                } else {
                    Err((
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": "no active node sources registered"})),
                    )
                        .into_response())
                }
            }
            Err(error) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": error.to_string()})),
            )
                .into_response()),
        },
    }
}
