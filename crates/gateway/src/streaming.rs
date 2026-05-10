use crate::contracts::{
    DataKind, EventScope, GatewayUiEvent, SignedNodeEvent, UiStreamQuery, allows_public_stream,
    projection_identity_key, visibility_for_kind,
};
use crate::db;
use crate::http::ingest_signed_snapshot;
use crate::state::AppState;
use crate::verify::verify_signed_node_event;
use anyhow::{Result, bail};
use axum::Json;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use serde_json::{Value, json};
use uuid::Uuid;

pub async fn ingest_node_event(
    State(state): State<AppState>,
    Json(event): Json<SignedNodeEvent>,
) -> Response {
    match persist_signed_node_event(&state, &event, None, None).await {
        Ok(Some(cursor)) => Json(json!({
            "status": "ok",
            "event_id": event.payload.event_id,
            "cursor": cursor,
            "node_id": event.payload.node_id,
            "data_kind": event.payload.data_kind,
        }))
        .into_response(),
        Ok(None) => Json(json!({
            "status": "duplicate",
            "event_id": event.payload.event_id,
        }))
        .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

pub async fn stream(
    State(state): State<AppState>,
    Query(query): Query<UiStreamQuery>,
    ws: WebSocketUpgrade,
) -> Response {
    let allow_protected = query
        .token
        .as_deref()
        .zip(state.registry_admin_token.as_deref())
        .is_some_and(|(token, expected)| token == expected);
    if query
        .data_kind
        .is_some_and(|kind| !allows_public_stream(kind) && !allow_protected)
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "protected stream kinds require an authorized token"})),
        )
            .into_response();
    }
    ws.on_upgrade(move |socket| handle_ws(socket, state, query, allow_protected))
        .into_response()
}

pub async fn persist_signed_node_event(
    state: &AppState,
    event: &SignedNodeEvent,
    source_id: Option<Uuid>,
    expected_signer_agent_did: Option<&str>,
) -> Result<Option<i64>> {
    let resolved_source = if source_id.is_none() && expected_signer_agent_did.is_none() {
        db::find_node_source_for_identity(
            &state.pool,
            &event.payload.node_id,
            &event.payload.signer_agent_did,
        )
        .await?
    } else {
        None
    };
    if resolved_source
        .as_ref()
        .is_some_and(|source| source.source_status != "active")
    {
        bail!("source is not active for event push ingest");
    }
    let source_id = source_id.or_else(|| resolved_source.as_ref().map(|source| source.id));
    let expected_signer_agent_did = expected_signer_agent_did.or_else(|| {
        resolved_source
            .as_ref()
            .and_then(|source| source.expected_signer_agent_did.as_deref())
    });
    verify_signed_node_event(event, expected_signer_agent_did)?;
    if let Some(last_seq) =
        db::max_ui_event_source_seq(&state.pool, &event.payload.node_id, source_id).await?
        && i64::try_from(event.payload.seq)
            .ok()
            .is_some_and(|current_seq| current_seq > last_seq + 1)
    {
        try_backfill_gap(
            state,
            resolved_source.as_ref(),
            &event.payload.node_id,
            expected_signer_agent_did,
            last_seq + 1,
            event.payload.seq.saturating_sub(1),
        )
        .await;
    }
    let data_kind = serde_json::to_string(&event.payload.data_kind)?
        .trim_matches('"')
        .to_string();
    let visibility = serde_json::to_string(&event.payload.visibility)?
        .trim_matches('"')
        .to_string();
    let provisional = !matches!(
        event.payload.provisional_policy,
        crate::contracts::ProvisionalExportPolicy::NeverBeforeConfirmation
    );
    let scope = normalized_event_scope(event);
    if matches!(
        event.payload.provisional_policy,
        crate::contracts::ProvisionalExportPolicy::EphemeralOnly
    ) {
        state.publish_ui_event(GatewayUiEvent {
            cursor: 0,
            event_id: event.payload.event_id.clone(),
            node_id: event.payload.node_id.clone(),
            data_kind: event.payload.data_kind,
            event_kind: event.payload.event_kind.clone(),
            visibility: event.payload.visibility,
            provisional,
            scope,
            generated_at: event.payload.timestamp,
            payload: event.payload.payload.clone(),
        });
        return Ok(None);
    }
    let inserted = db::insert_ui_event(
        &state.pool,
        db::InsertUiEventRecord {
            event_id: &event.payload.event_id,
            source_id,
            node_id: &event.payload.node_id,
            signer_agent_did: &event.payload.signer_agent_did,
            data_kind: &data_kind,
            event_kind: &event.payload.event_kind,
            visibility: &visibility,
            provisional,
            topic_id: scope.topic_id.as_deref(),
            organization_id: scope.organization_id.as_deref(),
            task_id: scope.task_id.as_deref(),
            generated_at: event.payload.timestamp,
            payload: &event.payload.payload,
            ingest_path: "event_push",
            source_cursor_or_seq: i64::try_from(event.payload.seq).ok(),
        },
    )
    .await?;
    let Some(row) = inserted else {
        materialize_mission_lifecycle_projection(state, event, source_id, provisional).await?;
        return Ok(None);
    };
    materialize_mission_lifecycle_projection(state, event, source_id, provisional).await?;
    let ui_event = GatewayUiEvent::try_from(row.clone())?;
    state.publish_ui_event(ui_event);
    let bus_event = json!({
        "event": "gateway.event.ingested",
        "cursor": row.cursor,
        "event_id": row.event_id,
        "node_id": row.node_id,
        "data_kind": row.data_kind,
        "timestamp": Utc::now().to_rfc3339(),
    });
    let _ = state
        .publish_event("gateway.event.ingested", &bus_event)
        .await;
    Ok(Some(row.cursor))
}

async fn materialize_mission_lifecycle_projection(
    state: &AppState,
    event: &SignedNodeEvent,
    source_id: Option<Uuid>,
    provisional: bool,
) -> Result<()> {
    if event.payload.data_kind != DataKind::MissionLifecycle {
        return Ok(());
    }
    let mut payload = event.payload.payload.clone();
    let mission_id = mission_identity(&payload);
    let Some(object) = payload.as_object_mut() else {
        return Ok(());
    };
    object
        .entry("task_type".to_string())
        .or_insert_with(|| Value::String("wattetheria.mission".to_string()));
    object
        .entry("source_node_id".to_string())
        .or_insert_with(|| Value::String(event.payload.node_id.clone()));
    object
        .entry("publisher_wattswarm_node_id".to_string())
        .or_insert_with(|| Value::String(event.payload.node_id.clone()));
    object
        .entry("mission_scope_hint".to_string())
        .or_insert_with(|| Value::String(format!("node:{}", event.payload.node_id)));
    object
        .entry("mission_feed_key".to_string())
        .or_insert_with(|| Value::String("wattetheria.missions".to_string()));
    object
        .entry("status".to_string())
        .and_modify(|status| normalize_mission_event_status(status, &event.payload.event_kind))
        .or_insert_with(|| {
            Value::String(status_from_mission_event_kind(&event.payload.event_kind))
        });
    if let Some(mission_id) = mission_id {
        object
            .entry("mission_id".to_string())
            .or_insert_with(|| Value::String(mission_id.clone()));
        object
            .entry("task_id".to_string())
            .or_insert_with(|| Value::String(mission_id.clone()));
        object
            .entry("id".to_string())
            .or_insert_with(|| Value::String(mission_id));
    }

    let data_kind = serde_json::to_string(&DataKind::TaskSummary)?
        .trim_matches('"')
        .to_string();
    let visibility = serde_json::to_string(&visibility_for_kind(DataKind::TaskSummary))?
        .trim_matches('"')
        .to_string();
    let identity_key =
        projection_identity_key(DataKind::TaskSummary, &payload, &event.payload.node_id);
    let provenance = json!({
        "source_node_id": event.payload.node_id,
        "source_cursor_or_seq": event.payload.seq,
        "ingest_path": "event_push",
        "last_confirmed_at": if provisional { Value::Null } else { Value::Number(event.payload.timestamp.into()) },
        "last_provisional_at": if provisional { Value::Number(event.payload.timestamp.into()) } else { Value::Null },
    });
    db::upsert_projection_row(
        &state.pool,
        db::UpsertProjectionRecord {
            data_kind: &data_kind,
            identity_key: &identity_key,
            source_node_id: &event.payload.node_id,
            source_id,
            generated_at: event.payload.timestamp,
            visibility: &visibility,
            payload: &payload,
            provenance: &provenance,
        },
    )
    .await
}

fn mission_identity(payload: &Value) -> Option<String> {
    payload
        .get("mission_id")
        .or_else(|| payload.get("task_id"))
        .or_else(|| payload.get("id"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
}

fn normalize_mission_event_status(status: &mut Value, event_kind: &str) {
    if status.as_str().is_none_or(|value| value == "open") {
        *status = Value::String(status_from_mission_event_kind(event_kind));
    }
}

fn status_from_mission_event_kind(event_kind: &str) -> String {
    match event_kind {
        "mission.claimed" => "claimed",
        "mission.completed" => "completed",
        "mission.settled" => "settled",
        _ => "published",
    }
    .to_string()
}

fn normalized_event_scope(event: &SignedNodeEvent) -> EventScope {
    let mut scope = event.payload.scope.clone();
    if event.payload.data_kind == DataKind::MissionLifecycle
        && scope.organization_id.as_deref()
            == event
                .payload
                .payload
                .get("publisher")
                .and_then(|value| value.as_str())
        && event
            .payload
            .payload
            .get("publisher_kind")
            .and_then(|value| value.as_str())
            .is_some_and(|kind| kind != "organization")
    {
        scope.organization_id = None;
    }
    scope
}

async fn try_backfill_gap(
    state: &AppState,
    source: Option<&crate::models::NodeSourceRow>,
    node_id: &str,
    expected_signer_agent_did: Option<&str>,
    missing_from_seq: i64,
    missing_to_seq: u64,
) {
    let Some(source) = source else {
        return;
    };
    let snapshot_url = source
        .wattetheria_snapshot_export_url
        .as_deref()
        .unwrap_or(&source.export_url);
    let outcome = async {
        let snapshot = state
            .node_client
            .fetch_signed_snapshot(snapshot_url)
            .await?;
        ingest_signed_snapshot(state, &snapshot, Some(source.id), expected_signer_agent_did).await
    }
    .await;
    let subject = match outcome.as_ref() {
        Ok(true) => "gateway.event.gap_snapshot_refresh_applied",
        Ok(false) => "gateway.event.gap_snapshot_refresh_skipped",
        Err(_) => "gateway.event.gap_snapshot_refresh_failed",
    };
    let payload = json!({
        "event": subject,
        "source_id": source.id,
        "node_id": node_id,
        "missing_from_seq": missing_from_seq,
        "missing_to_seq": missing_to_seq,
        "snapshot_url": snapshot_url,
        "timestamp": Utc::now().to_rfc3339(),
        "error": outcome.as_ref().err().map(|error| error.to_string()),
    });
    let audit_payload = json!({
        "node_id": node_id,
        "missing_from_seq": missing_from_seq,
        "missing_to_seq": missing_to_seq,
        "snapshot_url": snapshot_url,
    });
    let _ = db::insert_audit_record(
        &state.pool,
        db::InsertAuditRecord {
            record_kind: subject,
            data_kind: None,
            identity_key: Some(node_id),
            source_id: Some(source.id),
            source_node_id: Some(node_id),
            generated_at: None,
            ingest_path: "gap_snapshot_refresh",
            payload: &audit_payload,
            provenance: &payload,
        },
    )
    .await;
    let _ = state.publish_event(subject, &payload).await;
    let _ = db::update_source_sync_status(
        &state.pool,
        source.id,
        match outcome.as_ref() {
            Ok(true) => "gap_snapshot_refresh",
            Ok(false) => "gap_snapshot_refresh_skipped",
            Err(_) => "gap_snapshot_refresh_error",
        },
        payload["error"].as_str(),
    )
    .await;
}

async fn handle_ws(
    mut socket: WebSocket,
    state: AppState,
    query: UiStreamQuery,
    allow_protected: bool,
) {
    let mut receiver = state.ui_stream_tx.subscribe();
    let earliest_available_cursor = db::earliest_ui_event_cursor(&state.pool)
        .await
        .ok()
        .flatten();
    let resume_rejection_reason = resume_rejection_reason(query.cursor, earliest_available_cursor);
    let hello = json!({
        "kind": "hello",
        "timestamp": Utc::now().timestamp(),
        "cursor": query.cursor.unwrap_or_default(),
        "earliest_available_cursor": earliest_available_cursor,
        "replay_supported": true,
        "requires_client_cursor": true,
        "resume_cursor_owner": "client",
        "replay_persisted_across_restart": true,
        "bootstrap_contract": "rest_snapshot_then_ws_then_cursor_resume",
        "retry_backoff_ms": {
            "min": 500,
            "max": 10000,
        },
        "rebootstrap_required_when": "cursor_missing_or_server_rejects_resume",
        "auth_mode": if allow_protected { "authorized" } else { "public_only" },
    });
    if socket
        .send(Message::Text(hello.to_string().into()))
        .await
        .is_err()
    {
        return;
    }

    if let Some(reason) = resume_rejection_reason {
        let rejection = json!({
            "kind": "resume_rejected",
            "reason": reason,
            "requested_cursor": query.cursor,
            "earliest_available_cursor": earliest_available_cursor,
            "rebootstrap_required": true,
        });
        let _ = socket
            .send(Message::Text(rejection.to_string().into()))
            .await;
        return;
    }

    if let Ok(rows) = db::list_ui_events_after(
        &state.pool,
        db::ListUiEventsQuery {
            cursor: query.cursor.unwrap_or_default(),
            data_kind: query
                .data_kind
                .as_ref()
                .map(|kind| serde_json::to_string(kind).unwrap_or_default())
                .as_deref()
                .map(|value| value.trim_matches('"'))
                .filter(|value| !value.is_empty()),
            node_id: query.node_id.as_deref(),
            topic_id: query.topic_id.as_deref(),
            organization_id: query.organization_id.as_deref(),
            task_id: query.task_id.as_deref(),
            limit: query.limit.unwrap_or(200) as i64,
        },
    )
    .await
    {
        for row in rows {
            let Ok(event) = GatewayUiEvent::try_from(row) else {
                continue;
            };
            if event_matches_query(&event, &query, allow_protected)
                && socket
                    .send(Message::Text(
                        serde_json::to_string(&event).unwrap_or_default().into(),
                    ))
                    .await
                    .is_err()
            {
                return;
            }
        }
    }

    while let Ok(event) = receiver.recv().await {
        if !event_matches_query(&event, &query, allow_protected) {
            continue;
        }
        let Ok(payload) = serde_json::to_string(&event) else {
            continue;
        };
        if socket.send(Message::Text(payload.into())).await.is_err() {
            break;
        }
    }
}

fn event_matches_query(
    event: &GatewayUiEvent,
    query: &UiStreamQuery,
    allow_protected: bool,
) -> bool {
    if !allow_protected && !allows_public_stream(event.data_kind) {
        return false;
    }
    if query.data_kind.is_some_and(|kind| kind != event.data_kind) {
        return false;
    }
    if query
        .node_id
        .as_deref()
        .is_some_and(|expected| event.node_id != expected)
    {
        return false;
    }
    if query
        .topic_id
        .as_deref()
        .is_some_and(|expected| event.scope.topic_id.as_deref() != Some(expected))
    {
        return false;
    }
    if query
        .organization_id
        .as_deref()
        .is_some_and(|expected| event.scope.organization_id.as_deref() != Some(expected))
    {
        return false;
    }
    if query
        .task_id
        .as_deref()
        .is_some_and(|expected| event.scope.task_id.as_deref() != Some(expected))
    {
        return false;
    }
    true
}

fn resume_rejection_reason(
    requested_cursor: Option<i64>,
    earliest_available_cursor: Option<i64>,
) -> Option<&'static str> {
    match (requested_cursor, earliest_available_cursor) {
        (Some(requested), Some(earliest)) if requested > 0 && requested < earliest => {
            Some("cursor_aged_out")
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::{
        DataKind, EventScope, NodeEventPayload, ProvisionalExportPolicy, UiStreamQuery, Visibility,
    };

    fn sample_event(data_kind: DataKind) -> GatewayUiEvent {
        GatewayUiEvent {
            cursor: 1,
            event_id: "evt-1".to_string(),
            node_id: "node-a".to_string(),
            data_kind,
            event_kind: "topic.message.posted".to_string(),
            visibility: Visibility::Public,
            provisional: true,
            scope: EventScope {
                node_id: Some("node-a".to_string()),
                topic_id: Some("topic-1".to_string()),
                organization_id: None,
                task_id: None,
            },
            generated_at: 1,
            payload: json!({"topic_id":"topic-1"}),
        }
    }

    #[test]
    fn protected_kinds_are_filtered_without_token() {
        let query = UiStreamQuery {
            token: None,
            cursor: None,
            limit: None,
            data_kind: None,
            node_id: None,
            topic_id: None,
            organization_id: None,
            task_id: None,
        };
        assert!(!event_matches_query(
            &sample_event(DataKind::DmSummary),
            &query,
            false
        ));
    }

    #[test]
    fn query_filters_by_topic_id() {
        let query = UiStreamQuery {
            token: None,
            cursor: None,
            limit: None,
            data_kind: Some(DataKind::HiveActivity),
            node_id: None,
            topic_id: Some("topic-1".to_string()),
            organization_id: None,
            task_id: None,
        };
        assert!(event_matches_query(
            &sample_event(DataKind::HiveActivity),
            &query,
            false
        ));
    }

    #[test]
    fn resume_is_rejected_when_requested_cursor_aged_out() {
        assert_eq!(
            resume_rejection_reason(Some(4), Some(10)),
            Some("cursor_aged_out")
        );
        assert_eq!(resume_rejection_reason(Some(10), Some(10)), None);
        assert_eq!(resume_rejection_reason(Some(12), Some(10)), None);
        assert_eq!(resume_rejection_reason(None, Some(10)), None);
    }

    #[test]
    fn mission_scope_drops_player_publisher_from_organization_id() {
        let event = SignedNodeEvent {
            payload: NodeEventPayload {
                event_id: "event-1".to_string(),
                node_id: "node-1".to_string(),
                public_key: "public-key".to_string(),
                signer_agent_did: "did:key:agent".to_string(),
                seq: 1,
                timestamp: 1_710_000_000,
                data_kind: DataKind::MissionLifecycle,
                event_kind: "mission.published".to_string(),
                visibility: Visibility::Public,
                provisional_policy: ProvisionalExportPolicy::NeverBeforeConfirmation,
                scope: EventScope {
                    node_id: None,
                    topic_id: None,
                    organization_id: Some("Citizen-citizen-b2HM".to_string()),
                    task_id: Some("mission-1".to_string()),
                },
                identity_key: Some("mission-1".to_string()),
                payload: json!({
                    "mission_id": "mission-1",
                    "publisher": "Citizen-citizen-b2HM",
                    "publisher_kind": "player",
                }),
            },
            signature: "signature".to_string(),
        };

        let scope = normalized_event_scope(&event);
        assert_eq!(scope.organization_id, None);
        assert_eq!(scope.task_id.as_deref(), Some("mission-1"));
    }

    #[test]
    fn mission_scope_keeps_organization_publisher() {
        let event = SignedNodeEvent {
            payload: NodeEventPayload {
                event_id: "event-1".to_string(),
                node_id: "node-1".to_string(),
                public_key: "public-key".to_string(),
                signer_agent_did: "did:key:agent".to_string(),
                seq: 1,
                timestamp: 1_710_000_000,
                data_kind: DataKind::MissionLifecycle,
                event_kind: "mission.published".to_string(),
                visibility: Visibility::Public,
                provisional_policy: ProvisionalExportPolicy::NeverBeforeConfirmation,
                scope: EventScope {
                    node_id: None,
                    topic_id: None,
                    organization_id: Some("aurora-consortium".to_string()),
                    task_id: Some("mission-1".to_string()),
                },
                identity_key: Some("mission-1".to_string()),
                payload: json!({
                    "mission_id": "mission-1",
                    "publisher": "aurora-consortium",
                    "publisher_kind": "organization",
                }),
            },
            signature: "signature".to_string(),
        };

        let scope = normalized_event_scope(&event);
        assert_eq!(scope.organization_id.as_deref(), Some("aurora-consortium"));
        assert_eq!(scope.task_id.as_deref(), Some("mission-1"));
    }
}
