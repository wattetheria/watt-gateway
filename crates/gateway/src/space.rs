use crate::contracts::{DataKind, ProvisionalExportPolicy, SignedNodeEvent, Visibility};
use crate::db;
use crate::models::UiEventRow;
use crate::state::AppState;
use crate::verify::{verify_canonical_signature, verify_signed_space_presence};
use anyhow::{Context, Result, bail};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::PgPool;
use std::collections::BTreeMap;
use uuid::Uuid;
use wattetheria_gateway_contract::space::NodePresence;
use wattetheria_gateway_contract::{SignedSpacePresence, WorldEvent};
use wattswarm_protocol::types::EventAnnouncementPayload;

#[derive(Deserialize)]
pub struct SpaceQuery {
    pub network_id: String,
    pub space_id: Option<String>,
    pub place_id: Option<String>,
}

#[derive(Deserialize)]
pub struct SpaceObservationQuery {
    pub network_id: Option<String>,
    pub space_id: Option<String>,
    pub place_id: Option<String>,
}

struct SnapshotSource<'a> {
    source_id: Option<Uuid>,
    node_id: &'a str,
    signer_agent_did: &'a str,
}

pub(crate) fn validate_presence(presence: &SignedSpacePresence) -> Result<()> {
    verify_signed_space_presence(presence)?;
    let record = &presence.record;
    if record.seq == 0 {
        bail!("presence sequence must be positive");
    }
    wattetheria_gateway_contract::space::validate_activity(&record.activity)
        .map_err(anyhow::Error::msg)?;
    if record.network_id.trim().is_empty()
        || record.space_id.trim().is_empty()
        || record.space_version.trim().is_empty()
        || record.destination_place_id.trim().is_empty()
    {
        bail!("presence network, space, version and destination identifiers are required");
    }
    if !record
        .path
        .bytes()
        .all(|step| matches!(step, b'U' | b'R' | b'D' | b'L'))
    {
        bail!("presence path must contain only U/R/D/L");
    }
    Ok(())
}

pub fn validate_event(event: &SignedNodeEvent) -> Result<()> {
    match event.payload.data_kind {
        DataKind::Presence if event.payload.event_kind == "node.presence.heartbeat" => {
            if event.payload.visibility != Visibility::Public
                || event.payload.provisional_policy != ProvisionalExportPolicy::EphemeralOnly
            {
                bail!("node heartbeat must be public ephemeral data");
            }
            let presence: NodePresence = serde_json::from_value(event.payload.payload.clone())?;
            validate_node_presence(
                &presence,
                &event.payload.node_id,
                &event.payload.signer_agent_did,
            )
        }
        DataKind::SpacePresence => {
            if event.payload.visibility != Visibility::Public
                || event.payload.provisional_policy
                    != ProvisionalExportPolicy::NeverBeforeConfirmation
            {
                bail!("space presence must be confirmed public data");
            }
            validate_presence(&serde_json::from_value(event.payload.payload.clone())?)
        }
        DataKind::WorldEvent => {
            if event.payload.visibility != Visibility::Public
                || event.payload.provisional_policy
                    != ProvisionalExportPolicy::NeverBeforeConfirmation
            {
                bail!("world events must be confirmed public data");
            }
            validate_world_event(&event.payload.payload)
        }
        _ => Ok(()),
    }
}

pub fn is_space_event(event: &SignedNodeEvent) -> bool {
    matches!(
        event.payload.data_kind,
        DataKind::SpacePresence | DataKind::WorldEvent
    )
}

pub(crate) fn validate_node_presence(
    presence: &NodePresence,
    node_id: &str,
    agent_did: &str,
) -> Result<()> {
    if presence.node_id != node_id || presence.agent_did != agent_did {
        bail!("node heartbeat identity does not match its authenticated source");
    }
    if !(1..=300).contains(&presence.heartbeat_interval_sec) {
        bail!("node heartbeat interval must be between 1 and 300 seconds");
    }
    Ok(())
}

pub async fn init_schema(pool: &PgPool) -> Result<()> {
    sqlx::query(
        "create table if not exists gateway_space_presence (\
         network_id text not null default '', space_id text not null, agent_did text not null, seq numeric(20,0) not null,\
         source_node_id text not null, source_id uuid null, payload jsonb not null,\
         primary key(network_id, space_id, agent_did))",
    )
    .execute(pool)
    .await?;
    sqlx::query("alter table gateway_space_presence add column if not exists network_id text not null default ''")
        .execute(pool).await?;
    sqlx::query(
        "do $$ begin if exists (select 1 from pg_constraint where conrelid='gateway_space_presence'::regclass \
         and contype='p' and pg_get_constraintdef(oid)='PRIMARY KEY (space_id, agent_did)') then \
         alter table gateway_space_presence drop constraint gateway_space_presence_pkey; \
         alter table gateway_space_presence add primary key(network_id,space_id,agent_did); end if; end $$",
    ).execute(pool).await?;
    sqlx::query(
        "create table if not exists gateway_space_events (\
         network_id text not null, announcement_id text not null, space_id text not null,\
         place_id text not null, source_node_id text not null, source_id uuid null,\
         payload jsonb not null, primary key(network_id, announcement_id))",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "create table if not exists gateway_space_node_presence(\
        node_id text not null,agent_did text not null,last_heartbeat_ms bigint not null,\
        source_id uuid null,payload jsonb not null,primary key(node_id,agent_did))",
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn persist_event(
    pool: &PgPool,
    event: &SignedNodeEvent,
    source_id: Option<Uuid>,
    announce_p2p: bool,
) -> Result<Option<UiEventRow>> {
    let mut tx = pool.begin().await?;
    let accepted = match event.payload.data_kind {
        DataKind::SpacePresence => {
            let presence: SignedSpacePresence =
                serde_json::from_value(event.payload.payload.clone())?;
            upsert_presence(&mut tx, &presence, &event.payload.node_id, source_id).await?
        }
        DataKind::WorldEvent => {
            upsert_world_event(
                &mut tx,
                &event.payload.payload,
                &event.payload.node_id,
                source_id,
            )
            .await?
        }
        _ => unreachable!("space persistence only accepts space records"),
    };
    if !accepted {
        tx.rollback().await?;
        return Ok(None);
    }
    let data_kind = serde_json::to_string(&event.payload.data_kind)?;
    let row = insert_ui_record(
        &mut tx,
        db::InsertUiEventRecord {
            event_id: &event.payload.event_id,
            source_id,
            node_id: &event.payload.node_id,
            signer_agent_did: &event.payload.signer_agent_did,
            data_kind: data_kind.trim_matches('"'),
            event_kind: &event.payload.event_kind,
            visibility: "public",
            provisional: false,
            topic_id: event.payload.scope.topic_id.as_deref(),
            organization_id: event.payload.scope.organization_id.as_deref(),
            task_id: event.payload.scope.task_id.as_deref(),
            generated_at: event.payload.timestamp,
            payload: &event.payload.payload,
            ingest_path: "event_push",
            source_cursor_or_seq: i64::try_from(event.payload.seq).ok(),
        },
    )
    .await?;
    if row.is_none() {
        tx.rollback().await?;
        return Ok(None);
    }
    if announce_p2p {
        sqlx::query("insert into gateway_p2p_outbox(dedupe_key,command_kind,payload) values($1,$2,$3) on conflict(dedupe_key) do nothing")
            .bind(format!("event:{}", event.payload.event_id)).bind(db::P2P_OUTBOX_COMMAND_EVENT)
            .bind(sqlx::types::Json(serde_json::to_value(event)?)).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(row)
}

pub async fn persist_node_presence(
    pool: &PgPool,
    presence: &NodePresence,
    source_id: Option<Uuid>,
) -> Result<bool> {
    let mut tx = pool.begin().await?;
    let accepted = upsert_node_presence(&mut tx, presence, source_id).await?;
    tx.commit().await?;
    Ok(accepted)
}

pub async fn persist_snapshot_space(
    pool: &PgPool,
    source_id: Option<Uuid>,
    snapshot: &crate::models::PublicClientSnapshot,
    signer_agent_did: &str,
) -> Result<Vec<UiEventRow>> {
    let mut tx = pool.begin().await?;
    let source = SnapshotSource {
        source_id,
        node_id: &snapshot.node_id,
        signer_agent_did,
    };
    let mut rows = Vec::new();
    for presence in &snapshot.space_presences {
        if let Err(error) = validate_presence(presence) {
            tracing::warn!("snapshot SpacePresence rejected: {error}");
            continue;
        }
        if upsert_presence(&mut tx, presence, &snapshot.node_id, source_id).await? {
            let payload = serde_json::to_value(presence)?;
            let event_id = format!(
                "space-presence:{}:{}:{}:{}",
                presence.record.network_id,
                presence.record.space_id,
                presence.record.agent_did,
                presence.record.seq
            );
            if let Some(row) = insert_snapshot_ui_record(
                &mut tx,
                &source,
                &event_id,
                "space_presence",
                "space.presence.changed",
                presence.record.updated_at / 1000,
                &payload,
            )
            .await?
            {
                rows.push(row);
            }
        }
    }
    if let Some(presence) = &snapshot.node_presence {
        if let Err(error) = validate_node_presence(presence, &snapshot.node_id, signer_agent_did) {
            tracing::warn!("snapshot NodePresence rejected: {error}");
        } else if upsert_node_presence(&mut tx, presence, source_id).await? {
            let payload = serde_json::to_value(presence)?;
            let event_id = format!(
                "node-presence:{}:{}:{}",
                presence.node_id, presence.agent_did, presence.last_heartbeat_ms
            );
            if let Some(row) = insert_snapshot_ui_record(
                &mut tx,
                &source,
                &event_id,
                "presence",
                "node.presence.heartbeat",
                presence.last_heartbeat_ms / 1000,
                &payload,
            )
            .await?
            {
                rows.push(row);
            }
        }
    }
    for payload in &snapshot.world_events {
        if let Err(error) = validate_world_event(payload) {
            tracing::warn!("snapshot WorldEvent rejected: {error}");
            continue;
        }
        if upsert_world_event(&mut tx, payload, &snapshot.node_id, source_id).await? {
            let announcement: EventAnnouncementPayload = serde_json::from_value(payload.clone())?;
            let event_id = format!(
                "world-event:{}:{}",
                announcement.network_id, announcement.announcement_id
            );
            if let Some(row) = insert_snapshot_ui_record(
                &mut tx,
                &source,
                &event_id,
                "world_event",
                "space.world_event.published",
                i64::try_from(announcement.issued_at / 1000)?,
                payload,
            )
            .await?
            {
                rows.push(row);
            }
        }
    }
    tx.commit().await?;
    Ok(rows)
}

async fn insert_snapshot_ui_record(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    source: &SnapshotSource<'_>,
    event_id: &str,
    data_kind: &str,
    event_kind: &str,
    generated_at: i64,
    payload: &Value,
) -> Result<Option<UiEventRow>> {
    insert_ui_record(
        tx,
        db::InsertUiEventRecord {
            event_id,
            source_id: source.source_id,
            node_id: source.node_id,
            signer_agent_did: source.signer_agent_did,
            data_kind,
            event_kind,
            visibility: "public",
            provisional: false,
            topic_id: None,
            organization_id: None,
            task_id: None,
            generated_at,
            payload,
            ingest_path: "snapshot_push",
            source_cursor_or_seq: None,
        },
    )
    .await
}

async fn insert_ui_record(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    record: db::InsertUiEventRecord<'_>,
) -> Result<Option<UiEventRow>> {
    Ok(sqlx::query_as::<_,UiEventRow>(
        "insert into gateway_ui_events(event_id,source_id,node_id,signer_agent_did,data_kind,event_kind,visibility, \
         provisional,topic_id,organization_id,task_id,generated_at,payload,ingest_path,source_cursor_or_seq) \
         values($1,$2,$3,$4,$5,$6,'public',false,$7,$8,$9,to_timestamp($10::double precision),$11,$12,$13) \
         on conflict(event_id) do nothing returning *"
    ).bind(record.event_id).bind(record.source_id).bind(record.node_id).bind(record.signer_agent_did)
        .bind(record.data_kind).bind(record.event_kind).bind(record.topic_id).bind(record.organization_id).bind(record.task_id)
        .bind(record.generated_at as f64).bind(sqlx::types::Json(record.payload)).bind(record.ingest_path).bind(record.source_cursor_or_seq)
        .fetch_optional(&mut **tx).await?)
}

async fn upsert_world_event(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    payload: &Value,
    node_id: &str,
    source_id: Option<Uuid>,
) -> Result<bool> {
    let world: WorldEvent = serde_json::from_value(payload["content"].clone())?;
    Ok(sqlx::query(
        "insert into gateway_space_events(network_id,announcement_id,space_id,place_id,source_node_id,source_id,payload) \
         values($1,$2,$3,$4,$5,$6,$7) on conflict(network_id,announcement_id) do nothing returning announcement_id"
    ).bind(payload["network_id"].as_str()).bind(payload["announcement_id"].as_str()).bind(&world.space_id).bind(&world.place_id)
        .bind(node_id).bind(source_id).bind(sqlx::types::Json(payload)).fetch_optional(&mut **tx).await?.is_some())
}

async fn upsert_node_presence(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    presence: &NodePresence,
    source_id: Option<Uuid>,
) -> Result<bool> {
    Ok(sqlx::query("insert into gateway_space_node_presence(node_id,agent_did,last_heartbeat_ms,source_id,payload) \
        values($1,$2,$3,$4,$5) on conflict(node_id,agent_did) do update \
        set last_heartbeat_ms=excluded.last_heartbeat_ms,source_id=excluded.source_id,payload=excluded.payload \
        where gateway_space_node_presence.last_heartbeat_ms < excluded.last_heartbeat_ms returning node_id")
        .bind(&presence.node_id).bind(&presence.agent_did).bind(presence.last_heartbeat_ms).bind(source_id)
        .bind(sqlx::types::Json(presence)).fetch_optional(&mut **tx).await?.is_some())
}

async fn node_presences(pool: &PgPool) -> Result<Vec<NodePresence>> {
    Ok(sqlx::query_scalar::<_,sqlx::types::Json<NodePresence>>("select p.payload from gateway_space_node_presence p \
        left join node_sources s on s.id=p.source_id where p.source_id is null or s.source_status='active' order by p.node_id,p.agent_did")
        .fetch_all(pool).await?.into_iter().map(|value|value.0).collect())
}

async fn upsert_presence(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    presence: &SignedSpacePresence,
    node_id: &str,
    source_id: Option<Uuid>,
) -> Result<bool> {
    Ok(sqlx::query(
        "insert into gateway_space_presence(network_id,space_id,agent_did,seq,source_node_id,source_id,payload) \
         values($1,$2,$3,$4::text::numeric,$5,$6,$7) on conflict(network_id,space_id,agent_did) do update \
         set seq=excluded.seq,source_node_id=excluded.source_node_id,source_id=excluded.source_id,payload=excluded.payload \
         where gateway_space_presence.seq < excluded.seq returning agent_did"
    ).bind(&presence.record.network_id).bind(&presence.record.space_id).bind(&presence.record.agent_did).bind(presence.record.seq.to_string())
        .bind(node_id).bind(source_id).bind(sqlx::types::Json(presence)).fetch_optional(&mut **tx).await?.is_some())
}

pub async fn presences(
    State(state): State<AppState>,
    Query(query): Query<SpaceObservationQuery>,
) -> Response {
    if let Err(error) = validate_observation_query(&query) {
        return error_response(StatusCode::BAD_REQUEST, error);
    }
    if query.place_id.is_some() {
        return error_response(
            StatusCode::BAD_REQUEST,
            anyhow::anyhow!("presence place_id filtering requires geometry owned by Main/Client"),
        );
    }
    match presence_values(
        &state.pool,
        query.network_id.as_deref(),
        query.space_id.as_deref(),
    )
    .await
    {
        Ok(values) => {
            let node_presences = match node_presences(&state.pool).await {
                Ok(values) => values,
                Err(error) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, error),
            };
            let now = Utc::now().timestamp_millis();
            let values = values
                .into_iter()
                .filter(|(presence, node)| {
                    presence.record.entered
                        && node_presences.iter().any(|heartbeat| {
                            heartbeat.node_id == *node
                                && heartbeat.agent_did == presence.record.agent_did
                                && heartbeat_is_current(heartbeat, now)
                        })
                })
                .collect::<Vec<_>>();
            let names = sqlx::query_as::<_, (String, String, String)>(
                "select p.network_id,n.signer_agent_did,n.payload->'operator'->>'display_name' \
                 from node_snapshots n \
                 join unnest($1::text[],$2::text[],$3::text[]) p(network_id,agent_did,node_id) \
                   on n.node_id=p.node_id and n.signer_agent_did=p.agent_did \
                 left join node_sources s on s.id=n.source_id \
                 where n.payload->'network_status'->>'network_id'=p.network_id \
                   and (n.source_id is null or s.source_status='active') \
                   and jsonb_typeof(n.payload->'operator'->'display_name')='string' \
                   and btrim(n.payload->'operator'->>'display_name')<>''",
            )
            .bind(
                values
                    .iter()
                    .map(|(p, _)| &p.record.network_id)
                    .collect::<Vec<_>>(),
            )
            .bind(
                values
                    .iter()
                    .map(|(p, _)| &p.record.agent_did)
                    .collect::<Vec<_>>(),
            )
            .bind(values.iter().map(|(_, node)| node).collect::<Vec<_>>())
            .fetch_all(&state.pool)
            .await;
            let display_names = match names {
                Ok(names) => names
                    .into_iter()
                    .map(|(network, did, name)| ((network, did), name))
                    .collect::<BTreeMap<_, _>>(),
                Err(error) => {
                    return error_response(StatusCode::INTERNAL_SERVER_ERROR, error.into());
                }
            };
            let identities = values
                .iter()
                .map(|(presence, node)| {
                    let record = &presence.record;
                    let name = display_names.get(&(record.network_id.clone(), record.agent_did.clone()));
                    json!({"network_id":record.network_id,"agent_did":record.agent_did,"node_id":node,"display_name":name})
                })
                .collect::<Vec<_>>();
            let presences = values
                .into_iter()
                .map(|(presence, _)| presence)
                .collect::<Vec<_>>();
            axum::Json(json!({"network_id":query.network_id,"space_id":query.space_id,"server_time_ms":now,"presences":presences,"identities":identities,"node_presences":node_presences})).into_response()
        }
        Err(error) => error_response(StatusCode::INTERNAL_SERVER_ERROR, error),
    }
}

fn heartbeat_is_current(heartbeat: &NodePresence, now: i64) -> bool {
    now <= heartbeat
        .last_heartbeat_ms
        .saturating_add(3 * heartbeat.heartbeat_interval_sec * 1000)
}

pub async fn agent_presence_record(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Query(query): Query<SpaceQuery>,
) -> Response {
    if query.place_id.is_some() {
        return error_response(
            StatusCode::BAD_REQUEST,
            anyhow::anyhow!("presence place_id filtering requires geometry owned by Main/Client"),
        );
    }
    if query
        .space_id
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return error_response(
            StatusCode::BAD_REQUEST,
            anyhow::anyhow!("space_id must not be empty"),
        );
    }
    match sqlx::query_scalar::<_, sqlx::types::Json<Value>>(
        "select payload from gateway_space_presence where network_id=$1 and agent_did=$2 \
         and ($3::text is null or space_id=$3) order by seq desc,space_id limit 1",
    )
    .bind(&query.network_id)
    .bind(&agent_id)
    .bind(&query.space_id)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(Some(presence)) => axum::Json(presence.0).into_response(),
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            anyhow::anyhow!("agent presence not found"),
        ),
        Err(error) => error_response(StatusCode::INTERNAL_SERVER_ERROR, error.into()),
    }
}

fn validate_presence_query(query: &SpaceQuery) -> Result<()> {
    validate_network_query(query)?;
    if query.place_id.is_some() {
        bail!("presence place_id filtering requires geometry owned by Main/Client");
    }
    Ok(())
}

fn validate_network_query(query: &SpaceQuery) -> Result<()> {
    if query.network_id.trim().is_empty() {
        bail!("network_id must not be empty");
    }
    if query
        .space_id
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        bail!("space_id must not be empty");
    }
    Ok(())
}

fn validate_observation_query(query: &SpaceObservationQuery) -> Result<()> {
    if query
        .network_id
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        bail!("network_id must not be empty");
    }
    if query
        .space_id
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        bail!("space_id must not be empty");
    }
    Ok(())
}

async fn presence_values(
    pool: &PgPool,
    network_id: Option<&str>,
    space_id: Option<&str>,
) -> Result<Vec<(SignedSpacePresence, String)>> {
    let values = sqlx::query_as::<_, (sqlx::types::Json<SignedSpacePresence>, String)>(
        "select p.payload,p.source_node_id from \
         (select distinct on (network_id,agent_did) * from gateway_space_presence \
          where ($1::text is null or network_id=$1) and network_id<>'' \
          order by network_id,agent_did,seq desc,space_id) p left join node_sources s on s.id=p.source_id \
         where ($2::text is null or p.space_id=$2) \
         and (p.source_id is null or s.source_status='active') order by p.network_id,p.agent_did",
    )
    .bind(network_id)
    .bind(space_id)
    .fetch_all(pool)
    .await?;
    Ok(values
        .into_iter()
        .map(|(presence, node)| (presence.0, node))
        .collect())
}

pub async fn agent_presence(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Query(query): Query<SpaceQuery>,
) -> Response {
    if let Err(error) = validate_presence_query(&query) {
        return error_response(StatusCode::BAD_REQUEST, error);
    }
    let now = Utc::now().timestamp_millis();
    match presence_values(
        &state.pool,
        Some(&query.network_id),
        query.space_id.as_deref(),
    )
    .await
    {
        Ok(values) => match values
            .into_iter()
            .find(|(presence, _)| presence.record.agent_did == agent_id && presence.record.entered)
        {
            Some((presence, node)) => {
                let node_presences = match node_presences(&state.pool).await {
                    Ok(values) => values,
                    Err(error) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, error),
                };
                let source_node_ids = BTreeMap::from([(presence.record.agent_did.clone(), node)]);
                axum::Json(json!({"network_id":query.network_id,"space_id":presence.record.space_id,"server_time_ms":now,"presence":presence,"source_node_ids":source_node_ids,"node_presences":node_presences})).into_response()
            }
            None => (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"error":"agent presence not found"})),
            )
                .into_response(),
        },
        Err(error) => error_response(StatusCode::INTERNAL_SERVER_ERROR, error),
    }
}

pub async fn events(
    State(state): State<AppState>,
    Query(query): Query<SpaceObservationQuery>,
) -> Response {
    if let Err(error) = validate_observation_query(&query) {
        return error_response(StatusCode::BAD_REQUEST, error);
    }
    match sqlx::query_scalar::<_, sqlx::types::Json<Value>>(
        "select e.payload from gateway_space_events e left join node_sources s on s.id=e.source_id \
         where ($1::text is null or e.network_id=$1) and ($2::text is null or e.space_id=$2) and ($3::text is null or e.place_id=$3) \
         and (e.source_id is null or s.source_status='active') order by e.network_id,e.announcement_id"
    ).bind(&query.network_id).bind(&query.space_id).bind(&query.place_id).fetch_all(&state.pool).await {
        Ok(values) => axum::Json(json!({"network_id":query.network_id,"space_id":query.space_id,"server_time_ms":Utc::now().timestamp_millis(),"events":values.into_iter().map(|value|value.0).collect::<Vec<_>>()})).into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR,axum::Json(json!({"error":error.to_string()}))).into_response(),
    }
}

fn error_response(status: StatusCode, error: anyhow::Error) -> Response {
    (status, axum::Json(json!({"error":error.to_string()}))).into_response()
}

fn validate_world_event(payload: &Value) -> Result<()> {
    let path = std::env::var("WATTETHERIA_GATEWAY_TRUSTED_NETWORK_GENESIS_FILE")
        .context("WorldEvent requires configured trusted network authorities")?;
    let authorities: BTreeMap<String, String> =
        serde_json::from_slice(&std::fs::read(path).context("read trusted network authorities")?)
            .context("parse trusted network authorities")?;
    validate_world_event_with_authorities(payload, &authorities)
}

pub fn validate_world_event_with_authorities(
    payload: &Value,
    authorities: &BTreeMap<String, String>,
) -> Result<()> {
    let announcement: EventAnnouncementPayload = serde_json::from_value(payload.clone())?;
    let authority = authorities
        .get(&announcement.network_id)
        .context("unknown trusted network")?;
    if &announcement.authority_node_id != authority {
        bail!("announcement signer is not the trusted Network Authority");
    }
    let public = base64::engine::general_purpose::STANDARD.encode(hex::decode(authority)?);
    let signature = base64::engine::general_purpose::STANDARD
        .encode(hex::decode(&announcement.authority_signature)?);
    verify_canonical_signature(
        &announcement.unsigned_payload(),
        &signature,
        &public,
        "Network Authority announcement signature",
    )?;
    let world: WorldEvent = serde_json::from_value(announcement.content)?;
    if world.event_id.trim().is_empty() || world.event_id != announcement.announcement_id {
        bail!("world event_id must match announcement_id");
    }
    if world.space_id.trim().is_empty() || world.place_id.trim().is_empty() {
        bail!("world event space and place identifiers are required");
    }
    if world.title.trim().is_empty() {
        bail!("world event title is required");
    }
    if world.ends_at <= world.starts_at {
        bail!("world event end must follow start");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_deadline_is_inclusive() {
        let heartbeat = NodePresence {
            node_id: "node-a".to_owned(),
            agent_did: "did:key:agent-a".to_owned(),
            last_heartbeat_ms: 10_000,
            heartbeat_interval_sec: 20,
        };
        assert!(heartbeat_is_current(&heartbeat, 70_000));
        assert!(!heartbeat_is_current(&heartbeat, 70_001));
    }
}
