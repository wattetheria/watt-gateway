use crate::contracts::DataKind;
use crate::db;
use crate::gateway_network::GatewayNetworkHandle;
use crate::models::{GatewayRegistryEntry, ListQuery, TopicMessageQuery, TopicQuery};
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::time::Duration;
use wattswarm_network_transport_core::{PeerTransportCapabilities, TransferIntent, TransferKind};

const FEDERATION_LOCAL: &str = "local";

#[derive(Debug, Default, Deserialize)]
pub struct FederationQuery {
    pub federation: Option<String>,
}

pub async fn network_status(
    State(state): State<AppState>,
    Query(query): Query<FederationQuery>,
) -> Response {
    let mut status = match local_network_status_value(&state).await {
        Ok(value) => value,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": error.to_string()})),
            )
                .into_response();
        }
    };
    if federation_enabled(query.federation.as_deref()) {
        let remote_statuses =
            fetch_federated_objects(&state, "/api/network/status", Vec::new()).await;
        status = merge_network_status_values(status, remote_statuses);
    }
    axum::Json(status).into_response()
}

async fn local_network_status_value(state: &AppState) -> anyhow::Result<Value> {
    match db::list_visible_snapshots(&state.pool).await {
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
            let total_public_blocks = snapshots
                .iter()
                .map(|payload| payload["public_blocks"].as_array().map_or(0, Vec::len))
                .sum::<usize>();
            Ok(json!({
                "status": "ok",
                "nodes": total_nodes,
                "peers": total_peers,
                "tasks": total_tasks,
                "organizations": total_organizations,
                "topics": total_topics,
                "topic_messages": total_topic_messages,
                "public_blocks": total_public_blocks,
                "network_name": network_name,
                "network_org_name": network_org_name,
                "gateway_runtime": state.gateway_network.as_ref().map(gateway_runtime_status),
                "updated_at": db::now_rfc3339(),
            }))
        }
        Err(error) => Err(error),
    }
}

fn merge_network_status_values(mut local: Value, remotes: Vec<Value>) -> Value {
    let mut statuses = Vec::with_capacity(remotes.len() + 1);
    statuses.push(local.clone());
    statuses.extend(remotes);
    let count_keys = [
        "nodes",
        "peers",
        "tasks",
        "organizations",
        "topics",
        "topic_messages",
        "public_blocks",
    ];
    if let Some(object) = local.as_object_mut() {
        for key in count_keys {
            object.insert(
                key.to_string(),
                Value::Number(
                    statuses
                        .iter()
                        .map(|status| status.get(key).and_then(Value::as_u64).unwrap_or(0))
                        .sum::<u64>()
                        .into(),
                ),
            );
        }
        object.insert(
            "network_name".to_string(),
            single_shared_status_string(&statuses, "network_name"),
        );
        object.insert(
            "network_org_name".to_string(),
            single_shared_status_string(&statuses, "network_org_name"),
        );
        object.insert(
            "federated_gateways".to_string(),
            Value::Number((statuses.len().saturating_sub(1) as u64).into()),
        );
        object.insert("updated_at".to_string(), Value::String(db::now_rfc3339()));
    }
    local
}

fn single_shared_status_string(statuses: &[Value], key: &str) -> Value {
    let mut values = statuses
        .iter()
        .filter_map(|status| status.get(key).and_then(Value::as_str))
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

pub async fn peers(State(state): State<AppState>, Query(query): Query<ListQuery>) -> Response {
    let limit = query.limit.unwrap_or(200);
    match local_snapshot_array_values(&state, limit, "peers", |source_id, value| {
        attach_source(value, source_id)
    })
    .await
    {
        Ok(mut values) => {
            if federation_enabled(query.federation.as_deref()) {
                values.extend(
                    fetch_federated_arrays(
                        &state,
                        "/api/peers",
                        vec![("limit", limit.to_string())],
                    )
                    .await,
                );
                dedupe_values_by_key(&mut values, peer_identity_key);
            }
            values.truncate(limit);
            axum::Json(values).into_response()
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

pub async fn network_nodes(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Response {
    let limit = query.limit.unwrap_or(200);
    let mut values = match local_network_node_values(&state).await {
        Ok(values) => values,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": error.to_string()})),
            )
                .into_response();
        }
    };
    if federation_enabled(query.federation.as_deref()) {
        values.extend(
            fetch_federated_arrays(
                &state,
                "/api/network/nodes",
                vec![("limit", limit.to_string())],
            )
            .await,
        );
    }
    sort_values_desc_by_timestamp_with_fallback(&mut values, &["snapshot_generated_at"]);
    values.retain(has_valid_geo);
    dedupe_nodes_by_id(&mut values);
    values.truncate(limit);
    axum::Json(values).into_response()
}

async fn local_network_node_values(state: &AppState) -> anyhow::Result<Vec<Value>> {
    let mut values = projection_values(state, DataKind::NetworkProjection).await?;
    let rows = db::list_visible_snapshots(&state.pool).await?;
    for row in rows {
        values.extend(snapshot_geo_nodes(
            &row.payload.0,
            &row.node_id,
            row.generated_at.timestamp(),
        ));
    }
    Ok(values)
}

fn has_valid_geo(value: &Value) -> bool {
    let Some((latitude, longitude)) = geo_pair(value) else {
        return false;
    };
    matches!(latitude, Some(value) if (-90.0..=90.0).contains(&value))
        && matches!(longitude, Some(value) if (-180.0..=180.0).contains(&value))
}

fn geo_pair(value: &Value) -> Option<(Option<f64>, Option<f64>)> {
    let latitude = value
        .get("latitude")
        .or_else(|| value.get("lat"))
        .and_then(Value::as_f64);
    let longitude = value
        .get("longitude")
        .or_else(|| value.get("lng"))
        .or_else(|| value.get("lon"))
        .and_then(Value::as_f64);
    Some((latitude, longitude))
}

fn snapshot_geo_nodes(payload: &Value, source_node_id: &str, generated_at: i64) -> Vec<Value> {
    let mut nodes = Vec::new();
    if let Some(operator) = payload.get("operator") {
        nodes.push(snapshot_geo_node(
            operator.clone(),
            source_node_id,
            source_node_id,
            generated_at,
        ));
    }
    if let Some(peers) = payload.get("peers").and_then(Value::as_array) {
        nodes.extend(peers.iter().cloned().map(|peer| {
            let id = peer
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or(source_node_id)
                .to_string();
            snapshot_geo_node(peer, &id, source_node_id, generated_at)
        }));
    }
    nodes
}

fn snapshot_geo_node(
    mut value: Value,
    node_id: &str,
    source_node_id: &str,
    generated_at: i64,
) -> Value {
    if let Some(object) = value.as_object_mut() {
        object
            .entry("node_id")
            .or_insert_with(|| Value::String(node_id.to_string()));
        object
            .entry("source_node_id")
            .or_insert_with(|| Value::String(source_node_id.to_string()));
        object
            .entry("snapshot_generated_at")
            .or_insert_with(|| Value::Number(generated_at.into()));
    }
    value
}

fn dedupe_nodes_by_id(values: &mut Vec<Value>) {
    let mut seen = std::collections::HashSet::new();
    values.retain(|value| {
        let id = value
            .get("node_id")
            .or_else(|| value.get("id"))
            .or_else(|| value.get("source_node_id"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        !id.is_empty() && seen.insert(id)
    });
}

pub async fn public_hives(
    State(state): State<AppState>,
    Query(query): Query<TopicQuery>,
) -> Response {
    aggregate_public_hives_endpoint(&state, query).await
}

pub async fn public_hive_messages_by_query(
    State(state): State<AppState>,
    Query(query): Query<TopicMessageQuery>,
) -> Response {
    aggregate_public_hive_messages_endpoint(&state, query).await
}

pub async fn missions(State(state): State<AppState>, Query(query): Query<ListQuery>) -> Response {
    aggregate_federated_projection_endpoint(
        &state,
        query.limit.unwrap_or(200),
        query.federation.as_deref(),
        DataKind::TaskSummary,
        "/api/missions",
        mission_identity_key,
        &["updated_at", "created_at", "snapshot_generated_at"],
    )
    .await
}

pub async fn mission_activity(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Response {
    match db::list_visible_snapshots(&state.pool).await {
        Ok(rows) => {
            let limit = query.limit.unwrap_or(200);
            let mut tasks = Vec::new();
            let mut runs = Vec::new();
            for row in rows {
                let generated_at = row.payload.0["swarm_task_activity"]["generated_at"]
                    .as_i64()
                    .unwrap_or_else(|| row.generated_at.timestamp());
                if let Some(entries) = row.payload.0["swarm_task_activity"]["tasks"].as_array() {
                    tasks.extend(entries.iter().cloned().map(|value| {
                        attach_source(
                            attach_snapshot_generated_at(value, generated_at),
                            row.node_id.clone(),
                        )
                    }));
                }
                if let Some(entries) = row.payload.0["swarm_task_activity"]["runs"].as_array() {
                    runs.extend(entries.iter().cloned().map(|value| {
                        attach_source(
                            attach_snapshot_generated_at(value, generated_at),
                            row.node_id.clone(),
                        )
                    }));
                }
            }
            sort_values_desc_by_timestamp_with_fallback(
                &mut tasks,
                &["updated_at", "created_at", "snapshot_generated_at"],
            );
            sort_values_desc_by_timestamp_with_fallback(
                &mut runs,
                &["updated_at", "created_at", "snapshot_generated_at"],
            );
            dedupe_values_by_key(&mut tasks, task_activity_task_identity_key);
            dedupe_values_by_key(&mut runs, task_activity_run_identity_key);
            tasks.truncate(limit);
            runs.truncate(limit);
            axum::Json(json!({
                "generated_at": db::now_rfc3339(),
                "tasks": tasks,
                "runs": runs,
            }))
            .into_response()
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

pub async fn public_blocks(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Response {
    aggregate_projection_endpoint(&state, query.limit.unwrap_or(200), DataKind::PublicBlock).await
}

pub async fn organizations(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Response {
    aggregate_projection_endpoint(
        &state,
        query.limit.unwrap_or(200),
        DataKind::OrganizationSummary,
    )
    .await
}

pub async fn leaderboard(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Response {
    aggregate_federated_projection_endpoint(
        &state,
        query.limit.unwrap_or(200),
        query.federation.as_deref(),
        DataKind::RankingProjection,
        "/api/leaderboard",
        ranking_identity_key,
        &[
            "score",
            "watt",
            "updated_at",
            "created_at",
            "snapshot_generated_at",
        ],
    )
    .await
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

async fn aggregate_public_hives_endpoint(state: &AppState, query: TopicQuery) -> Response {
    match projection_values(state, DataKind::HiveMetadata).await {
        Ok(mut values) => {
            let member_counts = match projection_values(state, DataKind::HiveSubscription).await {
                Ok(subscriptions) => hive_member_counts(subscriptions),
                Err(error) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        axum::Json(json!({"error": error.to_string()})),
                    )
                        .into_response();
                }
            };
            if federation_enabled(query.federation.as_deref()) {
                let mut params = vec![("limit", query.limit.unwrap_or(200).to_string())];
                if let Some(value) = query.network_id.as_deref() {
                    params.push(("network_id", value.to_string()));
                }
                if let Some(value) = query.hive_id.as_deref() {
                    params.push(("hive_id", value.to_string()));
                }
                if let Some(value) = query.topic_id.as_deref() {
                    params.push(("topic_id", value.to_string()));
                }
                if let Some(value) = query.organization_id.as_deref() {
                    params.push(("organization_id", value.to_string()));
                }
                values.extend(fetch_federated_arrays(state, "/api/hives", params).await);
            }
            values.retain(|value| matches_hive_filters(value, &query));
            sort_values_desc_by_timestamp(&mut values);
            dedupe_values_by_key(&mut values, topic_identity_key);
            values.truncate(query.limit.unwrap_or(200));
            values = values
                .into_iter()
                .map(normalize_hive_value)
                .map(|value| attach_hive_member_count(value, &member_counts))
                .collect();
            axum::Json(values).into_response()
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn aggregate_public_hive_messages_endpoint(
    state: &AppState,
    query: TopicMessageQuery,
) -> Response {
    match projection_values(state, DataKind::HiveActivity).await {
        Ok(mut values) => {
            values.retain(|value| matches_hive_message_filters(value, &query));
            sort_values_desc_by_timestamp(&mut values);
            dedupe_values_by_key(&mut values, topic_message_identity_key);
            values.truncate(query.limit.unwrap_or(500));
            values = values.into_iter().map(normalize_hive_value).collect();
            axum::Json(values).into_response()
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn aggregate_projection_endpoint(
    state: &AppState,
    limit: usize,
    data_kind: DataKind,
) -> Response {
    match projection_values(state, data_kind).await {
        Ok(mut values) => {
            values.truncate(limit);
            axum::Json(values).into_response()
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn aggregate_federated_projection_endpoint<F>(
    state: &AppState,
    limit: usize,
    federation: Option<&str>,
    data_kind: DataKind,
    endpoint: &'static str,
    identity_key: F,
    sort_keys: &[&str],
) -> Response
where
    F: Fn(&Value) -> Option<String> + Copy,
{
    match projection_values(state, data_kind).await {
        Ok(mut values) => {
            if federation_enabled(federation) {
                values.extend(
                    fetch_federated_arrays(state, endpoint, vec![("limit", limit.to_string())])
                        .await,
                );
                sort_values_desc_by_timestamp_with_fallback(&mut values, sort_keys);
                dedupe_values_by_key(&mut values, identity_key);
            }
            values.truncate(limit);
            axum::Json(values).into_response()
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn local_snapshot_array_values<F>(
    state: &AppState,
    limit: usize,
    key: &str,
    transform: F,
) -> anyhow::Result<Vec<Value>>
where
    F: Fn(String, Value) -> Value,
{
    let rows = db::list_visible_snapshots(&state.pool).await?;
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
    Ok(values)
}

fn federation_enabled(value: Option<&str>) -> bool {
    !matches!(
        value.map(str::trim).map(str::to_ascii_lowercase).as_deref(),
        Some(FEDERATION_LOCAL | "none" | "false" | "0")
    )
}

async fn fetch_federated_arrays(
    state: &AppState,
    endpoint: &'static str,
    params: Vec<(&'static str, String)>,
) -> Vec<Value> {
    let mut values = Vec::new();
    let client = federated_gateway_client();
    for base_url in federated_gateway_base_urls(state, endpoint).await {
        let Some(url) = federated_gateway_url(&base_url, endpoint, &params) else {
            continue;
        };
        let Ok(response) = client.get(url).send().await else {
            continue;
        };
        let Ok(response) = response.error_for_status() else {
            continue;
        };
        let Ok(Value::Array(items)) = response.json::<Value>().await else {
            continue;
        };
        values.extend(items);
    }
    values
}

async fn fetch_federated_objects(
    state: &AppState,
    endpoint: &'static str,
    params: Vec<(&'static str, String)>,
) -> Vec<Value> {
    let mut values = Vec::new();
    let client = federated_gateway_client();
    for base_url in federated_gateway_base_urls(state, endpoint).await {
        let Some(url) = federated_gateway_url(&base_url, endpoint, &params) else {
            continue;
        };
        let Ok(response) = client.get(url).send().await else {
            continue;
        };
        let Ok(response) = response.error_for_status() else {
            continue;
        };
        let Ok(Value::Object(object)) = response.json::<Value>().await else {
            continue;
        };
        values.push(Value::Object(object));
    }
    values
}

async fn federated_gateway_base_urls(state: &AppState, endpoint: &'static str) -> Vec<String> {
    let mut base_urls = state
        .gateway_identity
        .as_ref()
        .map(|identity| identity.federation_peers().to_vec())
        .unwrap_or_default();

    if state
        .gateway_identity
        .as_ref()
        .is_some_and(|identity| !identity.allows_registry_federation())
    {
        return dedupe_and_filter_gateway_base_urls(base_urls, state.gateway_identity.as_ref());
    }

    let mut gateways = Vec::new();
    if let Ok(entries) =
        db::list_gateway_registry_entries(&state.pool, Some("approved"), None, None, Some("query"))
            .await
    {
        gateways.extend(entries);
    }
    for registry_url in &state.bootstrap_registry_urls {
        if let Ok(entries) = state
            .registry_client
            .fetch_public_gateways(registry_url)
            .await
        {
            gateways.extend(entries);
        }
    }
    base_urls.extend(
        gateways
            .into_iter()
            .filter(|gateway| gateway_supports_endpoint(gateway, endpoint))
            .map(|gateway| gateway.base_url),
    );
    dedupe_and_filter_gateway_base_urls(base_urls, state.gateway_identity.as_ref())
}

fn dedupe_and_filter_gateway_base_urls(
    base_urls: Vec<String>,
    identity: Option<&crate::gateway_identity::GatewayIdentity>,
) -> Vec<String> {
    let self_base_url = identity.map(|identity| normalize_gateway_base_url(identity.base_url()));
    let mut seen = std::collections::BTreeSet::new();
    base_urls
        .into_iter()
        .filter_map(|base_url| {
            let base_url = normalize_gateway_base_url(&base_url);
            if !base_url.is_empty()
                && self_base_url.as_deref() != Some(base_url.as_str())
                && seen.insert(base_url.clone())
            {
                Some(base_url)
            } else {
                None
            }
        })
        .collect()
}

fn gateway_supports_endpoint(gateway: &GatewayRegistryEntry, endpoint: &'static str) -> bool {
    gateway.status == "approved"
        && gateway.roles.iter().any(|role| role == "query")
        && gateway
            .supported_endpoints
            .iter()
            .any(|candidate| candidate == endpoint || candidate == "*")
}

fn federated_gateway_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build federated gateway client")
}

fn federated_gateway_url(
    base_url: &str,
    endpoint: &'static str,
    params: &[(&'static str, String)],
) -> Option<String> {
    let base_url = normalize_gateway_base_url(base_url);
    if base_url.is_empty() {
        return None;
    }
    let mut url = reqwest::Url::parse(&format!("{base_url}{endpoint}")).ok()?;
    {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in params {
            if !value.trim().is_empty() {
                pairs.append_pair(key, value);
            }
        }
        pairs.append_pair("federation", FEDERATION_LOCAL);
    }
    Some(url.to_string())
}

fn normalize_gateway_base_url(value: &str) -> String {
    value.trim().trim_end_matches('/').to_string()
}

async fn projection_values(state: &AppState, data_kind: DataKind) -> anyhow::Result<Vec<Value>> {
    let data_kind_string = serde_json::to_string(&data_kind)?
        .trim_matches('"')
        .to_string();
    let rows = db::list_projection_rows(&state.pool, &data_kind_string).await?;
    Ok(rows
        .into_iter()
        .map(|row| attach_source(row.payload.0, row.source_node_id))
        .collect())
}

fn hive_member_counts(subscription_values: Vec<Value>) -> BTreeMap<String, usize> {
    let mut latest_by_subscriber = BTreeMap::<String, (String, bool, u64)>::new();
    for value in subscription_values {
        let Some(route_key) = hive_route_key(&value) else {
            continue;
        };
        let Some(subscriber_node_id) = string_field(&value, "subscriber_node_id") else {
            continue;
        };
        let subscription_key = format!("{route_key}\u{1f}{subscriber_node_id}");
        let active = value
            .get("active")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let updated_at = numeric_timestamp(&value, &["updated_at", "snapshot_generated_at"]);
        let should_replace = latest_by_subscriber
            .get(&subscription_key)
            .is_none_or(|(_, _, existing_updated_at)| updated_at >= *existing_updated_at);
        if should_replace {
            latest_by_subscriber.insert(subscription_key, (route_key, active, updated_at));
        }
    }

    let mut counts = BTreeMap::<String, usize>::new();
    for (_, (route_key, active, _)) in latest_by_subscriber {
        if active {
            *counts.entry(route_key).or_default() += 1;
        }
    }
    counts
}

fn attach_hive_member_count(mut value: Value, member_counts: &BTreeMap<String, usize>) -> Value {
    let count = hive_route_key(&value).and_then(|route_key| member_counts.get(&route_key).copied());
    if let Some(object) = value.as_object_mut() {
        if let Some(count) = count {
            object.insert(
                "member_count".to_string(),
                Value::Number((count as u64).into()),
            );
        } else {
            object
                .entry("member_count".to_string())
                .or_insert_with(|| Value::Number(0_u64.into()));
        }
    }
    value
}

fn hive_route_key(value: &Value) -> Option<String> {
    let feed_key = string_field(value, "feed_key")?;
    let scope_hint = string_field(value, "scope_hint")?;
    let network_id = string_field(value, "network_id").unwrap_or_default();
    Some(format!("{network_id}\u{1f}{feed_key}\u{1f}{scope_hint}"))
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn numeric_timestamp(value: &Value, keys: &[&str]) -> u64 {
    keys.iter()
        .find_map(|key| {
            value.get(*key).and_then(|value| {
                value
                    .as_u64()
                    .or_else(|| value.as_i64().map(|raw| raw.max(0) as u64))
            })
        })
        .unwrap_or_default()
}

fn attach_source(mut value: Value, source_node_id: String) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.insert("source_node_id".to_string(), Value::String(source_node_id));
    }
    value
}

fn attach_snapshot_generated_at(mut value: Value, generated_at: i64) -> Value {
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

fn matches_hive_filters(value: &Value, query: &TopicQuery) -> bool {
    matches_optional_string_filter(
        value,
        &["network_id", "networkId"],
        query.network_id.as_deref(),
    ) && matches_optional_string_filter(
        value,
        &["hive_id", "topic_id", "id"],
        query.hive_id.as_deref(),
    ) && matches_optional_string_filter(
        value,
        &["topic_id", "hive_id", "id"],
        query.topic_id.as_deref(),
    ) && matches_optional_string_filter(
        value,
        &["organization_id", "organizationId"],
        query.organization_id.as_deref(),
    )
}

fn normalize_hive_value(mut value: Value) -> Value {
    let hive_id = value
        .get("hive_id")
        .or_else(|| value.get("topic_id"))
        .or_else(|| value.get("id"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let Some(object) = value.as_object_mut() else {
        return value;
    };
    if let Some(hive_id) = hive_id {
        object
            .entry("hive_id".to_string())
            .or_insert_with(|| Value::String(hive_id));
    }
    value
}

fn matches_hive_message_filters(value: &Value, query: &TopicMessageQuery) -> bool {
    matches_optional_string_filter(
        value,
        &["network_id", "networkId"],
        query.network_id.as_deref(),
    ) && matches_optional_string_filter(
        value,
        &["hive_id", "topic_id", "topicId"],
        query.hive_id.as_deref(),
    ) && matches_optional_string_filter(
        value,
        &["topic_id", "topicId", "hive_id"],
        query.topic_id.as_deref(),
    ) && matches_optional_string_filter(
        value,
        &["organization_id", "organizationId"],
        query.organization_id.as_deref(),
    ) && matches_optional_string_filter(
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

fn sort_values_desc_by_timestamp_with_fallback(values: &mut [Value], fallback_keys: &[&str]) {
    values.sort_by_key(|value| std::cmp::Reverse(timestamp_with_fallback(value, fallback_keys)));
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

fn timestamp_with_fallback(value: &Value, fallback_keys: &[&str]) -> i64 {
    let primary = topic_sort_timestamp(value);
    if primary != 0 {
        return primary;
    }
    for key in fallback_keys {
        if let Some(number) = value.get(*key).and_then(value_to_timestamp) {
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
    network_scoped_topic_key(value, &["topic_id", "id"])
}

fn topic_message_identity_key(value: &Value) -> Option<String> {
    topic_key_from_value(value, &["message_id", "id"]).or_else(|| {
        let topic_id = network_scoped_topic_key(value, &["topic_id", "topicId"])?;
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

fn peer_identity_key(value: &Value) -> Option<String> {
    topic_key_from_value(
        value,
        &[
            "node_id",
            "peer_id",
            "id",
            "public_id",
            "agent_did",
            "source_node_id",
        ],
    )
}

fn mission_identity_key(value: &Value) -> Option<String> {
    topic_key_from_value(value, &["mission_id", "task_id", "id"])
}

fn ranking_identity_key(value: &Value) -> Option<String> {
    topic_key_from_value(value, &["agent_did", "public_id", "agent_id", "id"])
}

fn task_activity_task_identity_key(value: &Value) -> Option<String> {
    topic_key_from_value(value, &["task_id", "id"])
}

fn task_activity_run_identity_key(value: &Value) -> Option<String> {
    topic_key_from_value(value, &["run_id", "id"]).or_else(|| {
        let task_id = value
            .get("task_id")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let status = value
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let updated_at = timestamp_with_fallback(value, &["updated_at", "created_at"]);
        Some(format!("{task_id}:{status}:{updated_at}"))
    })
}

fn topic_key_from_value(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::to_string)
}

fn network_scoped_topic_key(value: &Value, keys: &[&str]) -> Option<String> {
    let topic_id = topic_key_from_value(value, keys)?;
    let Some(network_id) = value
        .get("network_id")
        .or_else(|| value.get("networkId"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Some(topic_id);
    };
    Some(format!("{network_id}:{topic_id}"))
}

pub(crate) fn recommended_routes(capabilities: &PeerTransportCapabilities) -> Value {
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

#[cfg(test)]
mod tests {
    use super::has_valid_geo;
    use super::snapshot_geo_nodes;
    use serde_json::json;

    #[test]
    fn network_node_geo_requires_valid_coordinates() {
        assert!(has_valid_geo(
            &json!({"latitude": 37.7749, "longitude": -122.4194})
        ));
        assert!(!has_valid_geo(
            &json!({"latitude": 91.0, "longitude": -122.4194})
        ));
        assert!(!has_valid_geo(&json!({"latitude": 37.7749})));
        assert!(!has_valid_geo(&json!({"longitude": -122.4194})));
    }

    #[test]
    fn snapshot_geo_nodes_includes_operator_and_peers() {
        let payload = json!({
            "operator": {
                "id": "citizen-node",
                "lat": -33.8399,
                "lng": 151.0583,
                "status": "online"
            },
            "peers": [{
                "id": "peer-1",
                "lat": -30.8491,
                "lng": -77.3826,
                "status": "online"
            }]
        });

        let nodes = snapshot_geo_nodes(&payload, "did:key:z6Local", 1777098979);

        assert_eq!(nodes.len(), 2);
        assert!(nodes.iter().all(has_valid_geo));
        assert_eq!(nodes[0]["node_id"].as_str(), Some("did:key:z6Local"));
        assert_eq!(nodes[1]["node_id"].as_str(), Some("peer-1"));
        assert_eq!(nodes[1]["source_node_id"].as_str(), Some("did:key:z6Local"));
    }
}
