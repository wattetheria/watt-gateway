use crate::contracts::SignedNodeEvent;
use crate::db;
use crate::gateway_network::{self, GatewayNetworkRuntime};
use crate::models::SignedPublicClientSnapshot;
use crate::state::AppState;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant, timeout};
use tracing::{debug, warn};
use wattswarm_network_transport_core::TransportContactMaterial;

const SYNC_POLL_INTERVAL: Duration = Duration::from_millis(100);
const SNAPSHOT_REANNOUNCE_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub enum GatewayP2pSyncCommand {
    SnapshotApplied {
        node_id: String,
        signer_agent_did: String,
        generated_at: i64,
    },
    EventApplied {
        event: Box<SignedNodeEvent>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum GatewayP2pSyncMessage {
    SnapshotAnnounceV1 {
        gateway_peer_id: String,
        node_id: String,
        signer_agent_did: String,
        generated_at: i64,
        transport_contact_material: Box<TransportContactMaterial>,
    },
    EventV1 {
        gateway_peer_id: String,
        event: Box<SignedNodeEvent>,
    },
}

pub async fn run_gateway_p2p_sync(
    mut runtime: GatewayNetworkRuntime,
    state: AppState,
    mut commands: mpsc::Receiver<GatewayP2pSyncCommand>,
) {
    let mut next_snapshot_reannounce = Instant::now() + SNAPSHOT_REANNOUNCE_INTERVAL;
    loop {
        while let Ok(command) = commands.try_recv() {
            if let Err(error) = handle_command(&mut runtime, command) {
                warn!("gateway p2p sync publish failed: {error:#}");
            }
        }

        if Instant::now() >= next_snapshot_reannounce {
            if let Err(error) = reannounce_local_snapshots(&mut runtime, &state).await {
                warn!("gateway p2p sync snapshot reannounce failed: {error:#}");
            }
            next_snapshot_reannounce = Instant::now() + SNAPSHOT_REANNOUNCE_INTERVAL;
        }

        match timeout(SYNC_POLL_INTERVAL, runtime.next_sync_summary()).await {
            Ok(Ok(gossip)) => {
                if let Err(error) = handle_gossip(&state, gossip.payload).await {
                    warn!("gateway p2p sync ingest failed: {error:#}");
                }
            }
            Ok(Err(error)) => warn!("gateway p2p sync receive failed: {error:#}"),
            Err(_) => {}
        }
    }
}

fn handle_command(
    runtime: &mut GatewayNetworkRuntime,
    command: GatewayP2pSyncCommand,
) -> Result<()> {
    match command {
        GatewayP2pSyncCommand::SnapshotApplied {
            node_id,
            signer_agent_did,
            generated_at,
        } => {
            let contact = runtime
                .export_transport_contact_material(chrono::Utc::now().timestamp().max(0) as u64)?;
            let message = GatewayP2pSyncMessage::SnapshotAnnounceV1 {
                gateway_peer_id: runtime.local_peer_id().to_string(),
                node_id,
                signer_agent_did,
                generated_at,
                transport_contact_material: Box::new(contact),
            };
            runtime.publish_sync_summary(&serde_json::to_vec(&message)?)?;
        }
        GatewayP2pSyncCommand::EventApplied { event } => {
            let message = GatewayP2pSyncMessage::EventV1 {
                gateway_peer_id: runtime.local_peer_id().to_string(),
                event,
            };
            runtime.publish_sync_summary(&serde_json::to_vec(&message)?)?;
        }
    }
    Ok(())
}

async fn reannounce_local_snapshots(
    runtime: &mut GatewayNetworkRuntime,
    state: &AppState,
) -> Result<()> {
    for snapshot in db::list_visible_snapshots(&state.pool).await? {
        handle_command(
            runtime,
            GatewayP2pSyncCommand::SnapshotApplied {
                node_id: snapshot.node_id,
                signer_agent_did: snapshot.signer_agent_did,
                generated_at: snapshot_payload_generated_at(&snapshot.payload.0)
                    .unwrap_or_else(|| snapshot.generated_at.timestamp()),
            },
        )?;
    }
    Ok(())
}

fn snapshot_payload_generated_at(payload: &serde_json::Value) -> Option<i64> {
    payload
        .get("generated_at")
        .and_then(serde_json::Value::as_i64)
}

async fn handle_gossip(state: &AppState, payload: Vec<u8>) -> Result<()> {
    let message = match serde_json::from_slice::<GatewayP2pSyncMessage>(&payload) {
        Ok(message) => message,
        Err(error) => {
            debug!("ignore non-gateway p2p sync summary: {error}");
            return Ok(());
        }
    };
    match message {
        GatewayP2pSyncMessage::SnapshotAnnounceV1 {
            gateway_peer_id,
            node_id,
            signer_agent_did,
            generated_at,
            transport_contact_material,
        } => {
            if state
                .gateway_network
                .as_ref()
                .is_some_and(|handle| handle.local_peer_id.as_str() == gateway_peer_id)
            {
                return Ok(());
            }
            if snapshot_is_current(state, &node_id, generated_at).await? {
                return Ok(());
            }
            fetch_and_ingest_snapshot(
                state,
                &node_id,
                &signer_agent_did,
                generated_at,
                &transport_contact_material,
            )
            .await?;
        }
        GatewayP2pSyncMessage::EventV1 {
            gateway_peer_id,
            event,
        } => {
            if state
                .gateway_network
                .as_ref()
                .is_some_and(|handle| handle.local_peer_id.as_str() == gateway_peer_id)
            {
                return Ok(());
            }
            crate::streaming::persist_signed_node_event_without_p2p_announce(
                state, &event, None, None,
            )
            .await?;
        }
    }
    Ok(())
}

async fn snapshot_is_current(state: &AppState, node_id: &str, generated_at: i64) -> Result<bool> {
    let Some(snapshot) = db::get_snapshot_by_node_id(&state.pool, node_id).await? else {
        return Ok(false);
    };
    Ok(snapshot.generated_at.timestamp_millis() >= normalize_generated_at_millis(generated_at))
}

async fn fetch_and_ingest_snapshot(
    state: &AppState,
    node_id: &str,
    signer_agent_did: &str,
    generated_at: i64,
    contact: &TransportContactMaterial,
) -> Result<()> {
    let handle = state
        .gateway_network
        .as_ref()
        .context("gateway p2p runtime is not enabled")?;
    let snapshot: SignedPublicClientSnapshot = gateway_network::fetch_signed_snapshot_via_iroh(
        &handle.state_dir,
        &handle.local_peer_id,
        contact,
        node_id,
    )
    .await?;
    if snapshot.payload.node_id != node_id {
        bail!(
            "p2p snapshot node_id mismatch: announced {node_id}, fetched {}",
            snapshot.payload.node_id
        );
    }
    if snapshot.signer_agent_did != signer_agent_did {
        bail!(
            "p2p snapshot signer mismatch: announced {signer_agent_did}, fetched {}",
            snapshot.signer_agent_did
        );
    }
    if snapshot.payload.generated_at != generated_at {
        bail!(
            "p2p snapshot generated_at mismatch: announced {generated_at}, fetched {}",
            snapshot.payload.generated_at
        );
    }
    let source_id = db::find_node_source_for_identity(
        &state.pool,
        &snapshot.payload.node_id,
        &snapshot.signer_agent_did,
    )
    .await?
    .map(|source| source.id);
    crate::http::ingest_signed_snapshot_without_p2p_announce(
        state,
        &snapshot,
        source_id,
        Some(&snapshot.signer_agent_did),
    )
    .await?;
    Ok(())
}

fn normalize_generated_at_millis(generated_at: i64) -> i64 {
    if generated_at.unsigned_abs() >= 100_000_000_000 {
        generated_at
    } else {
        generated_at.saturating_mul(1_000)
    }
}
