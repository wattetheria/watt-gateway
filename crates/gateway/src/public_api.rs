use crate::contracts::DataKind;
use crate::db;
use crate::gateway_network::GatewayNetworkHandle;
use crate::models::{ListQuery, TopicMessageQuery, TopicQuery};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use wattswarm_network_transport_core::{PeerTransportCapabilities, TransferIntent, TransferKind};

pub async fn network_status(State(state): State<AppState>) -> Response {
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
            axum::Json(json!({
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
            .into_response()
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

pub async fn peers(State(state): State<AppState>, Query(query): Query<ListQuery>) -> Response {
    aggregate_snapshot_array_endpoint(
        &state,
        query.limit.unwrap_or(200),
        "peers",
        |source_id, value| attach_source(value, source_id),
    )
    .await
}

pub async fn network_nodes(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Response {
    let mut values = match projection_values(&state, DataKind::NetworkProjection).await {
        Ok(values) => values,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": error.to_string()})),
            )
                .into_response();
        }
    };
    let rows = match db::list_visible_snapshots(&state.pool).await {
        Ok(rows) => rows,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": error.to_string()})),
            )
                .into_response();
        }
    };
    for row in rows {
        values.extend(snapshot_geo_nodes(
            &row.payload.0,
            &row.node_id,
            row.generated_at.timestamp(),
        ));
    }
    sort_values_desc_by_timestamp_with_fallback(&mut values, &["snapshot_generated_at"]);
    values.retain(has_valid_geo);
    dedupe_nodes_by_id(&mut values);
    if let Some(limit) = query.limit {
        values.truncate(limit);
    }
    axum::Json(values).into_response()
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

pub async fn public_hive_messages(
    State(state): State<AppState>,
    Path(hive_id): Path<String>,
    Query(mut query): Query<TopicMessageQuery>,
) -> Response {
    query.hive_id = Some(hive_id);
    aggregate_public_hive_messages_endpoint(&state, query).await
}

pub async fn tasks(State(state): State<AppState>, Query(query): Query<ListQuery>) -> Response {
    aggregate_projection_endpoint(&state, query.limit.unwrap_or(200), DataKind::TaskSummary).await
}

pub async fn task_activity(
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
    aggregate_projection_endpoint(
        &state,
        query.limit.unwrap_or(200),
        DataKind::RankingProjection,
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
            values.retain(|value| matches_hive_filters(value, &query));
            sort_values_desc_by_timestamp(&mut values);
            dedupe_values_by_key(&mut values, topic_identity_key);
            values.truncate(query.limit.unwrap_or(200));
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

async fn aggregate_snapshot_array_endpoint<F>(
    state: &AppState,
    limit: usize,
    key: &str,
    transform: F,
) -> Response
where
    F: Fn(String, Value) -> Value,
{
    match db::list_visible_snapshots(&state.pool).await {
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
            axum::Json(values).into_response()
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
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
