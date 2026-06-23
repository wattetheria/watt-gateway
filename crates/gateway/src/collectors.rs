use crate::contracts::{DataKind, projection_identity_key};
use crate::db;
use crate::models::NodeSourceRow;
use crate::state::AppState;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WattswarmNetworkProjectionSnapshot {
    pub generated_at: u64,
    pub node_id: String,
    pub display_name: String,
    pub org_id: String,
    pub network_id: String,
    pub running: bool,
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
    pub peer_protocol_distribution: std::collections::BTreeMap<String, u64>,
    pub peers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WattswarmTopicMessageView {
    pub message_id: String,
    pub network_id: String,
    pub feed_key: String,
    pub scope_hint: String,
    pub author_node_id: String,
    pub content: Value,
    pub reply_to_message_id: Option<String>,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WattswarmTopicActivitySnapshot {
    pub generated_at: u64,
    pub subscriber_node_id: String,
    pub feed_key: String,
    pub scope_hint: String,
    pub messages: Vec<WattswarmTopicMessageView>,
    pub cursor: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WattswarmTopicSubscriptionRow {
    pub network_id: String,
    pub subscriber_node_id: String,
    pub feed_key: String,
    pub scope_hint: String,
    pub active: bool,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WattswarmTopicSubscriptionSnapshot {
    pub generated_at: u64,
    pub network_id: String,
    pub subscriptions: Vec<WattswarmTopicSubscriptionRow>,
}

pub async fn collect_wattswarm_read_models(state: &AppState, source: &NodeSourceRow) -> Result<()> {
    let Some(base_url) = source
        .wattswarm_ui_base_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(());
    };

    let network: WattswarmNetworkProjectionSnapshot = state
        .node_client
        .fetch_json(
            &format!("{base_url}/api/wattetheria/network/snapshot"),
            None,
        )
        .await?;
    persist_network_projection(state, source, &network).await?;

    if let Err(error) =
        collect_topic_subscription_read_models(state, source, base_url, &network.network_id).await
    {
        eprintln!("wattswarm topic subscription projection collection skipped: {error:#}");
    }
    collect_topic_activity_read_models(state, source, base_url).await?;
    Ok(())
}

async fn persist_network_projection(
    state: &AppState,
    source: &NodeSourceRow,
    snapshot: &WattswarmNetworkProjectionSnapshot,
) -> Result<()> {
    let payload = json!({
        "node_id": snapshot.node_id,
        "display_name": snapshot.display_name,
        "org_id": snapshot.org_id,
        "network_id": snapshot.network_id,
        "running": snapshot.running,
        "mode": snapshot.mode,
        "latitude": snapshot.latitude,
        "longitude": snapshot.longitude,
        "peer_protocol_distribution": snapshot.peer_protocol_distribution,
        "peers": snapshot.peers,
        "snapshot_generated_at": snapshot.generated_at,
    });
    persist_projection(
        state,
        DataKind::NetworkProjection,
        projection_identity_key(DataKind::NetworkProjection, &payload, &snapshot.node_id),
        &snapshot.node_id,
        source.id,
        i64::try_from(snapshot.generated_at).unwrap_or(i64::MAX),
        payload,
    )
    .await
}

async fn collect_topic_activity_read_models(
    state: &AppState,
    source: &NodeSourceRow,
    base_url: &str,
) -> Result<()> {
    let rows = db::list_projection_rows(&state.pool, "hive_metadata").await?;
    for row in rows
        .into_iter()
        .filter(|row| row.source_id == Some(source.id))
    {
        let Some(feed_key) = row.payload.0.get("feed_key").and_then(Value::as_str) else {
            continue;
        };
        let Some(scope_hint) = row.payload.0.get("scope_hint").and_then(Value::as_str) else {
            continue;
        };
        let network_id = row.payload.0.get("network_id").and_then(Value::as_str);
        let mut query = vec![
            ("feed_key", feed_key.to_string()),
            ("scope_hint", scope_hint.to_string()),
            ("limit", "50".to_string()),
        ];
        if let Some(network_id) = network_id.map(str::trim).filter(|value| !value.is_empty()) {
            query.push(("network_id", network_id.to_string()));
        }
        let activity: WattswarmTopicActivitySnapshot = state
            .node_client
            .fetch_json(
                &format!("{base_url}/api/wattetheria/topic/activity"),
                Some(&query),
            )
            .await?;
        let generated_at = i64::try_from(activity.generated_at).unwrap_or(i64::MAX);
        for message in activity.messages {
            let payload = json!({
                "message_id": message.message_id,
                "network_id": message.network_id,
                "feed_key": message.feed_key,
                "scope_hint": message.scope_hint,
                "author_node_id": message.author_node_id,
                "content": message.content,
                "reply_to_message_id": message.reply_to_message_id,
                "created_at": message.created_at,
                "topic_id": row.payload.0.get("topic_id").cloned().unwrap_or(Value::Null),
                "organization_id": row.payload.0.get("organization_id").cloned().unwrap_or(Value::Null),
                "snapshot_generated_at": activity.generated_at,
            });
            let source_node_id = source
                .expected_wattswarm_node_id
                .as_deref()
                .filter(|value| !value.is_empty())
                .unwrap_or(&row.source_node_id);
            persist_projection(
                state,
                DataKind::HiveActivity,
                projection_identity_key(DataKind::HiveActivity, &payload, source_node_id),
                source_node_id,
                source.id,
                generated_at,
                payload,
            )
            .await?;
        }
    }
    Ok(())
}

async fn collect_topic_subscription_read_models(
    state: &AppState,
    source: &NodeSourceRow,
    base_url: &str,
    network_id: &str,
) -> Result<()> {
    let query = [("network_id", network_id.to_string())];
    let snapshot: WattswarmTopicSubscriptionSnapshot = state
        .node_client
        .fetch_json(
            &format!("{base_url}/api/wattetheria/topic/subscriptions"),
            Some(&query),
        )
        .await?;
    for subscription in snapshot.subscriptions {
        let subscription_id = topic_subscription_identity(&subscription);
        let payload = json!({
            "subscription_id": subscription_id,
            "network_id": subscription.network_id,
            "subscriber_node_id": subscription.subscriber_node_id,
            "feed_key": subscription.feed_key,
            "scope_hint": subscription.scope_hint,
            "active": subscription.active,
            "updated_at": subscription.updated_at,
            "snapshot_generated_at": snapshot.generated_at,
        });
        let source_node_id = payload["subscriber_node_id"]
            .as_str()
            .filter(|value| !value.is_empty())
            .unwrap_or(&source.name)
            .to_owned();
        persist_projection(
            state,
            DataKind::HiveSubscription,
            projection_identity_key(DataKind::HiveSubscription, &payload, &source_node_id),
            &source_node_id,
            source.id,
            i64::try_from(subscription.updated_at).unwrap_or(i64::MAX),
            payload,
        )
        .await?;
    }
    Ok(())
}

fn topic_subscription_identity(subscription: &WattswarmTopicSubscriptionRow) -> String {
    format!(
        "{}\u{1f}{}\u{1f}{}\u{1f}{}",
        subscription.network_id,
        subscription.feed_key,
        subscription.scope_hint,
        subscription.subscriber_node_id
    )
}

async fn persist_projection(
    state: &AppState,
    data_kind: DataKind,
    identity_key: String,
    source_node_id: &str,
    source_id: uuid::Uuid,
    generated_at: i64,
    payload: Value,
) -> Result<()> {
    let data_kind_string = serde_json::to_string(&data_kind)?
        .trim_matches('"')
        .to_string();
    let provenance = json!({
        "source_node_id": source_node_id,
        "source_cursor_or_seq": Value::Null,
        "ingest_path": "wattswarm_pull",
        "last_confirmed_at": generated_at,
        "last_provisional_at": Value::Null,
    });
    db::upsert_projection_row(
        &state.pool,
        db::UpsertProjectionRecord {
            data_kind: &data_kind_string,
            identity_key: &identity_key,
            source_node_id,
            source_id: Some(source_id),
            generated_at,
            visibility: "public",
            payload: &payload,
            provenance: &provenance,
        },
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_projection_payload_carries_snapshot_timestamp() {
        let payload = json!({
            "node_id": "node-a",
            "display_name": "Captain Aurora",
            "latitude": 37.7749,
            "longitude": -122.4194,
            "snapshot_generated_at": 12_u64,
        });
        assert_eq!(payload["snapshot_generated_at"].as_u64(), Some(12));
        assert_eq!(payload["display_name"].as_str(), Some("Captain Aurora"));
        assert_eq!(payload["latitude"].as_f64(), Some(37.7749));
        assert_eq!(payload["longitude"].as_f64(), Some(-122.4194));
    }
}
