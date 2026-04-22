use crate::contracts::DataKind;
use crate::db;
use crate::gateway_network::GatewayNetworkHandle;
use crate::models::{DmMessageQuery, ListQuery, TopicMessageQuery, TopicQuery};
use crate::state::AppState;
use axum::extract::{Query, State};
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
            let total_friend_relationships = snapshots
                .iter()
                .map(|payload| {
                    payload["friend_relationships"]
                        .as_array()
                        .map_or(0, Vec::len)
                })
                .sum::<usize>();
            let total_pending_friend_requests = snapshots
                .iter()
                .map(|payload| {
                    payload["pending_friend_requests"]
                        .as_array()
                        .map_or(0, Vec::len)
                })
                .sum::<usize>();
            let total_public_blocks = snapshots
                .iter()
                .map(|payload| payload["public_blocks"].as_array().map_or(0, Vec::len))
                .sum::<usize>();
            let total_dm_threads = snapshots
                .iter()
                .map(|payload| payload["dm_threads"].as_array().map_or(0, Vec::len))
                .sum::<usize>();
            let total_dm_messages = snapshots
                .iter()
                .map(|payload| payload["dm_messages"].as_array().map_or(0, Vec::len))
                .sum::<usize>();
            axum::Json(json!({
                "status": "ok",
                "nodes": total_nodes,
                "peers": total_peers,
                "tasks": total_tasks,
                "organizations": total_organizations,
                "topics": total_topics,
                "topic_messages": total_topic_messages,
                "friend_relationships": total_friend_relationships,
                "pending_friend_requests": total_pending_friend_requests,
                "public_blocks": total_public_blocks,
                "dm_threads": total_dm_threads,
                "dm_messages": total_dm_messages,
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

pub async fn public_topics(
    State(state): State<AppState>,
    Query(query): Query<TopicQuery>,
) -> Response {
    aggregate_public_topics_endpoint(&state, query).await
}

pub async fn public_topic_messages(
    State(state): State<AppState>,
    Query(query): Query<TopicMessageQuery>,
) -> Response {
    aggregate_public_topic_messages_endpoint(&state, query).await
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
                    .unwrap_or(row.generated_at);
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

pub async fn friend_relationships(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Response {
    aggregate_projection_endpoint(
        &state,
        query.limit.unwrap_or(200),
        DataKind::FriendRelationship,
    )
    .await
}

pub async fn pending_friend_requests(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Response {
    aggregate_projection_endpoint(
        &state,
        query.limit.unwrap_or(200),
        DataKind::FriendRequestPending,
    )
    .await
}

pub async fn public_blocks(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Response {
    aggregate_projection_endpoint(&state, query.limit.unwrap_or(200), DataKind::PublicBlock).await
}

pub async fn dm_threads(State(state): State<AppState>, Query(query): Query<ListQuery>) -> Response {
    aggregate_projection_endpoint(&state, query.limit.unwrap_or(200), DataKind::SocialThread).await
}

pub async fn dm_messages(
    State(state): State<AppState>,
    Query(query): Query<DmMessageQuery>,
) -> Response {
    match projection_values(&state, DataKind::DmMessage).await {
        Ok(mut values) => {
            values.retain(|value| matches_dm_message_filters(value, &query));
            sort_values_desc_by_timestamp_with_fallback(&mut values, &["created_at"]);
            dedupe_values_by_key(&mut values, dm_message_identity_key);
            values.truncate(query.limit.unwrap_or(500));
            axum::Json(values).into_response()
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
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

async fn aggregate_public_topics_endpoint(state: &AppState, query: TopicQuery) -> Response {
    match projection_values(state, DataKind::HiveMetadata).await {
        Ok(mut values) => {
            values.retain(|value| matches_topic_filters(value, &query));
            sort_values_desc_by_timestamp(&mut values);
            dedupe_values_by_key(&mut values, topic_identity_key);
            values.truncate(query.limit.unwrap_or(200));
            axum::Json(values).into_response()
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn aggregate_public_topic_messages_endpoint(
    state: &AppState,
    query: TopicMessageQuery,
) -> Response {
    match projection_values(state, DataKind::HiveActivity).await {
        Ok(mut values) => {
            values.retain(|value| matches_topic_message_filters(value, &query));
            sort_values_desc_by_timestamp(&mut values);
            dedupe_values_by_key(&mut values, topic_message_identity_key);
            values.truncate(query.limit.unwrap_or(500));
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

fn matches_dm_message_filters(value: &Value, query: &DmMessageQuery) -> bool {
    matches_optional_string_filter(value, &["thread_id"], query.thread_id.as_deref())
        && matches_optional_string_filter(
            value,
            &["counterpart_public_id"],
            query.counterpart_public_id.as_deref(),
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

fn dm_message_identity_key(value: &Value) -> Option<String> {
    topic_key_from_value(value, &["message_id", "id"]).or_else(|| {
        let thread_id = value.get("thread_id").and_then(Value::as_str)?;
        let created_at = timestamp_with_fallback(value, &["created_at"]);
        let direction = value
            .get("direction")
            .and_then(Value::as_str)
            .unwrap_or_default();
        Some(format!("{thread_id}:{direction}:{created_at}"))
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
