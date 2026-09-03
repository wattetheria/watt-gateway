use crate::contracts::{DataKind, Visibility, projection_identity_key, visibility_for_kind};
use crate::db;
use crate::models::PublicClientSnapshot;
use anyhow::Result;
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ProjectionSeed {
    pub data_kind: DataKind,
    pub identity_key: String,
    pub source_node_id: String,
    pub source_id: Option<Uuid>,
    pub generated_at: i64,
    pub visibility: Visibility,
    pub payload: Value,
    pub provenance: Value,
}

pub async fn persist_snapshot_read_models(
    pool: &sqlx::PgPool,
    source_id: Option<Uuid>,
    snapshot: &PublicClientSnapshot,
) -> Result<()> {
    for seed in snapshot_projection_seeds(source_id, snapshot) {
        let data_kind = serde_json::to_string(&seed.data_kind)?
            .trim_matches('"')
            .to_string();
        let visibility = serde_json::to_string(&seed.visibility)?
            .trim_matches('"')
            .to_string();
        db::upsert_projection_row(
            pool,
            db::UpsertProjectionRecord {
                data_kind: &data_kind,
                identity_key: &seed.identity_key,
                source_node_id: &seed.source_node_id,
                source_id: seed.source_id,
                generated_at: seed.generated_at,
                visibility: &visibility,
                payload: &seed.payload,
                provenance: &seed.provenance,
            },
        )
        .await?;
    }
    Ok(())
}

pub async fn list_projection_payloads(
    pool: &sqlx::PgPool,
    data_kind: DataKind,
) -> Result<Vec<Value>> {
    let data_kind_string = serde_json::to_string(&data_kind)?
        .trim_matches('"')
        .to_string();
    let rows = db::list_projection_rows(pool, &data_kind_string).await?;
    Ok(rows.into_iter().map(|row| row.payload.0).collect())
}

pub fn snapshot_projection_seeds(
    source_id: Option<Uuid>,
    snapshot: &PublicClientSnapshot,
) -> Vec<ProjectionSeed> {
    let mut seeds = Vec::new();
    let source_node_id = snapshot.node_id.clone();
    let generated_at = snapshot.generated_at;

    seeds.push(singleton_seed(
        source_id,
        &source_node_id,
        generated_at,
        DataKind::NetworkProjection,
        json!({
            "node_id": snapshot.node_id,
            "network_name": snapshot.network_name,
            "network_org_name": snapshot.network_org_name,
            "network_status": snapshot.network_status,
            "peers": snapshot.peers,
        }),
    ));

    seeds.push(singleton_seed(
        source_id,
        &source_node_id,
        generated_at,
        DataKind::OperatorProfile,
        attach_generated_at(snapshot.operator.clone(), generated_at),
    ));

    fanout_array(
        &mut seeds,
        source_id,
        &source_node_id,
        generated_at,
        DataKind::PublicBlock,
        &snapshot.public_blocks,
    );
    fanout_array(
        &mut seeds,
        source_id,
        &source_node_id,
        generated_at,
        DataKind::HiveMetadata,
        &snapshot.public_topics,
    );
    fanout_array(
        &mut seeds,
        source_id,
        &source_node_id,
        generated_at,
        DataKind::HiveActivity,
        &snapshot.public_topic_messages,
    );
    fanout_array(
        &mut seeds,
        source_id,
        &source_node_id,
        generated_at,
        DataKind::BoardActivity,
        &snapshot.public_board_messages,
    );
    fanout_array(
        &mut seeds,
        source_id,
        &source_node_id,
        generated_at,
        DataKind::TaskSummary,
        &snapshot.tasks,
    );
    fanout_array(
        &mut seeds,
        source_id,
        &source_node_id,
        generated_at,
        DataKind::OrganizationSummary,
        &snapshot.organizations,
    );
    fanout_array(
        &mut seeds,
        source_id,
        &source_node_id,
        generated_at,
        DataKind::RankingProjection,
        &snapshot.leaderboard,
    );

    seeds
}

fn fanout_array(
    seeds: &mut Vec<ProjectionSeed>,
    source_id: Option<Uuid>,
    source_node_id: &str,
    generated_at: i64,
    data_kind: DataKind,
    values: &[Value],
) {
    seeds.extend(values.iter().cloned().map(|value| ProjectionSeed {
        identity_key: projection_identity_key(data_kind, &value, source_node_id),
        source_node_id: source_node_id.to_owned(),
        source_id,
        generated_at,
        visibility: visibility_for_kind(data_kind),
        payload: attach_generated_at(value, generated_at),
        provenance: default_provenance(source_node_id, generated_at, "snapshot_push"),
        data_kind,
    }));
}

fn singleton_seed(
    source_id: Option<Uuid>,
    source_node_id: &str,
    generated_at: i64,
    data_kind: DataKind,
    value: Value,
) -> ProjectionSeed {
    ProjectionSeed {
        identity_key: projection_identity_key(data_kind, &value, source_node_id),
        source_node_id: source_node_id.to_owned(),
        source_id,
        generated_at,
        visibility: visibility_for_kind(data_kind),
        payload: value,
        provenance: default_provenance(source_node_id, generated_at, "snapshot_push"),
        data_kind,
    }
}

fn attach_generated_at(mut value: Value, generated_at: i64) -> Value {
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

fn default_provenance(source_node_id: &str, generated_at: i64, ingest_path: &str) -> Value {
    json!({
        "source_node_id": source_node_id,
        "source_cursor_or_seq": generated_at,
        "ingest_path": ingest_path,
        "last_confirmed_at": generated_at,
        "last_provisional_at": Value::Null,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_snapshot() -> PublicClientSnapshot {
        PublicClientSnapshot {
            generated_at: 1_710_000_000,
            node_id: "node-a".to_string(),
            public_key: "pk".to_string(),
            network_name: Some("testnet".to_string()),
            network_org_name: Some("org".to_string()),
            network_status: json!({"total_nodes": 1}),
            peers: vec![json!({"id":"peer-1"})],
            operator: json!({"id":"operator-1"}),
            rpc_logs: vec![],
            public_blocks: vec![json!({"counterpart_public_id":"blocked-1"})],
            public_topics: vec![json!({"topic_id":"topic-1"})],
            public_topic_messages: vec![json!({"message_id":"topic-msg-1","topic_id":"topic-1"})],
            public_board_messages: vec![json!({
                "message_id": "board-msg-1",
                "source": "network",
                "category": "general",
                "content": {"text": "board"},
            })],
            swarm_task_activity: json!({}),
            tasks: vec![json!({"id":"task-1"})],
            organizations: vec![json!({"organization_id":"org-1"})],
            leaderboard: vec![json!({"agent_did":"agent-1"})],
        }
    }

    #[test]
    fn snapshot_fanout_includes_public_block_and_task_rows() {
        let seeds = snapshot_projection_seeds(None, &sample_snapshot());
        assert!(
            seeds
                .iter()
                .any(|seed| seed.data_kind == DataKind::PublicBlock)
        );
        assert!(
            seeds
                .iter()
                .any(|seed| seed.data_kind == DataKind::TaskSummary)
        );
        assert!(
            seeds
                .iter()
                .any(|seed| seed.data_kind == DataKind::BoardActivity)
        );
    }

    #[test]
    fn snapshot_fanout_attaches_snapshot_timestamp() {
        let seeds = snapshot_projection_seeds(None, &sample_snapshot());
        let message = seeds
            .into_iter()
            .find(|seed| seed.data_kind == DataKind::TaskSummary)
            .expect("task summary seed");
        assert_eq!(
            message.payload["snapshot_generated_at"].as_i64(),
            Some(1_710_000_000)
        );
        assert_eq!(
            message.provenance["source_cursor_or_seq"].as_i64(),
            Some(1_710_000_000)
        );
    }
}
