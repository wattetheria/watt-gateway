use anyhow::{Result, anyhow};
use serde::{Serialize, de::DeserializeOwned};
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::Duration;
use wattswarm_artifact_store::{ArtifactKind, ArtifactStore};
use wattswarm_network_substrate::{
    GossipKind, NetworkNodeId, NetworkRuntimeObservabilitySnapshot, RawGossipMessage,
    SubstrateConfig, SubstrateNode, SubstrateRuntime, SubstrateRuntimeEvent, SwarmScope,
    TopicNamespace, TrafficGuardPeerHealth,
};
use wattswarm_network_transport_core::{
    DirectDataFetchRequest, DirectDataObjectKind, PeerTransportCapabilities, TransferIntent,
    TransportContactMaterial, TransportRoute, TransportRouter,
};
use wattswarm_network_transport_iroh::{
    export_local_contact_material_for_network_peer_id,
    fetch_direct_data_for_network_peer_id_with_timeout, shutdown_local_iroh_data_plane,
};

const NODE_SEED_FILE: &str = "node_seed.hex";
const STATE_LOCK_FILE: &str = ".wattetheria-gateway-p2p.lock";
pub const PUBLIC_CLIENT_SNAPSHOT_SCOPE: &str = "public-client-snapshot";

#[derive(Debug, Clone)]
pub struct GatewayP2pConfig {
    pub enabled: bool,
    pub state_dir: PathBuf,
    pub namespace: TopicNamespace,
    pub protocol_version: String,
    pub listen_addrs: Vec<String>,
    pub bootstrap_peers: Vec<String>,
    pub max_established_per_peer: u32,
    pub gossip_mesh_d: usize,
    pub gossip_mesh_d_low: usize,
    pub gossip_mesh_d_high: usize,
    pub gossip_mesh_heartbeat_ms: u64,
    pub gossip_mesh_max_transmit_size: usize,
    pub max_backfill_events: usize,
    pub max_backfill_events_hard_limit: usize,
}

impl Default for GatewayP2pConfig {
    fn default() -> Self {
        let mut config = Self::from_substrate(SubstrateConfig::default());
        config.enabled = false;
        config.namespace.network = "wattetheria-gateway".to_owned();
        config.protocol_version = "/wattetheria-gateway/0.1.0".to_owned();
        config
    }
}

impl GatewayP2pConfig {
    fn from_substrate(config: SubstrateConfig) -> Self {
        Self {
            enabled: false,
            state_dir: PathBuf::from(".wattetheria-gateway-p2p-state"),
            namespace: config.namespace,
            protocol_version: config.protocol_version,
            listen_addrs: config.listen_addrs,
            bootstrap_peers: config.bootstrap_peers,
            max_established_per_peer: config.max_established_per_peer,
            gossip_mesh_d: config.gossip_mesh_d,
            gossip_mesh_d_low: config.gossip_mesh_d_low,
            gossip_mesh_d_high: config.gossip_mesh_d_high,
            gossip_mesh_heartbeat_ms: config.gossip_mesh_heartbeat_ms,
            gossip_mesh_max_transmit_size: config.gossip_mesh_max_transmit_size,
            max_backfill_events: config.max_backfill_events,
            max_backfill_events_hard_limit: config.max_backfill_events_hard_limit,
        }
    }

    pub fn as_substrate(&self) -> SubstrateConfig {
        SubstrateConfig {
            namespace: self.namespace.clone(),
            protocol_version: self.protocol_version.clone(),
            listen_addrs: self.listen_addrs.clone(),
            bootstrap_peers: self.bootstrap_peers.clone(),
            max_established_per_peer: self.max_established_per_peer,
            gossip_mesh_d: self.gossip_mesh_d,
            gossip_mesh_d_low: self.gossip_mesh_d_low,
            gossip_mesh_d_high: self.gossip_mesh_d_high,
            gossip_mesh_heartbeat_ms: self.gossip_mesh_heartbeat_ms,
            gossip_mesh_max_transmit_size: self.gossip_mesh_max_transmit_size,
            max_backfill_events: self.max_backfill_events,
            max_backfill_events_hard_limit: self.max_backfill_events_hard_limit,
            control_request_timeout_ms: SubstrateConfig::default().control_request_timeout_ms,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.as_substrate().validate()
    }
}

pub struct GatewayNetworkNode {
    inner: SubstrateNode,
    state_dir: PathBuf,
    lock_path: PathBuf,
    lock_file: File,
}

impl GatewayNetworkNode {
    pub fn generate(config: GatewayP2pConfig) -> Result<Self> {
        initialize_state_dir(&config.state_dir)?;
        let (lock_path, lock_file) = acquire_state_dir_lock(&config.state_dir)?;
        let local_seed = load_or_create_identity_seed(&config.state_dir.join(NODE_SEED_FILE))?;
        Ok(Self {
            inner: SubstrateNode::from_seed_bytes(
                config.as_substrate(),
                config.state_dir.clone(),
                local_seed,
            )?,
            state_dir: config.state_dir,
            lock_path,
            lock_file,
        })
    }
}

pub struct GatewayNetworkRuntime {
    inner: SubstrateRuntime,
    state_dir: PathBuf,
    lock_path: PathBuf,
    lock_file: File,
}

#[derive(Debug, Clone)]
pub struct GatewayNetworkGossip {
    pub propagation_source: NetworkNodeId,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum GatewayNetworkSyncEvent {
    Gossip(GatewayNetworkGossip),
    NeighborUp { peer: NetworkNodeId },
}

#[derive(Debug, Clone)]
pub struct GatewayNetworkHandle {
    pub info: GatewayNetworkInfo,
    pub state_dir: PathBuf,
    pub local_peer_id: NetworkNodeId,
}

#[derive(Debug, Clone, Serialize)]
pub struct GatewayNetworkInfo {
    pub peer_id: String,
    pub listen_addrs: Vec<String>,
    pub transport_capabilities: PeerTransportCapabilities,
    pub transport_contact_material: Option<TransportContactMaterial>,
    pub nat_status: String,
    pub nat_public_address: Option<String>,
    pub nat_confidence: u32,
    pub relay_reservations: Vec<String>,
    pub peer_health: Vec<GatewayPeerHealth>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GatewayPeerHealth {
    pub peer: String,
    pub score: i64,
    pub blacklisted: bool,
    pub reputation_tier: String,
    pub quarantined: bool,
    pub quarantine_remaining_ms: u64,
    pub ban_remaining_ms: u64,
    pub throttle_factor_percent: u32,
}

impl From<TrafficGuardPeerHealth> for GatewayPeerHealth {
    fn from(value: TrafficGuardPeerHealth) -> Self {
        Self {
            peer: value.peer,
            score: value.score,
            blacklisted: value.blacklisted,
            reputation_tier: value.reputation_tier,
            quarantined: value.quarantined,
            quarantine_remaining_ms: value.quarantine_remaining_ms,
            ban_remaining_ms: value.ban_remaining_ms,
            throttle_factor_percent: value.throttle_factor_percent,
        }
    }
}

impl GatewayNetworkRuntime {
    pub fn new(node: GatewayNetworkNode) -> Result<Self> {
        let mut inner = SubstrateRuntime::new(node.inner)?;
        inner.subscribe_scope(&SwarmScope::Global)?;
        Ok(Self {
            inner,
            state_dir: node.state_dir,
            lock_path: node.lock_path,
            lock_file: node.lock_file,
        })
    }

    pub fn local_peer_id(&self) -> NetworkNodeId {
        self.inner.local_peer_id()
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    pub fn listen_addrs(&self) -> Vec<String> {
        self.inner
            .listen_addrs()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    pub fn observability_snapshot(&self) -> NetworkRuntimeObservabilitySnapshot {
        self.inner.observability_snapshot()
    }

    pub fn transport_capabilities(&self) -> PeerTransportCapabilities {
        PeerTransportCapabilities::iroh_direct_default()
    }

    pub fn export_transport_contact_material(
        &self,
        generated_at: u64,
    ) -> Result<TransportContactMaterial> {
        export_local_contact_material_for_network_peer_id(
            &self.state_dir,
            self.local_peer_id().as_str(),
            generated_at,
        )
    }

    pub fn recommended_transfer_route(
        &self,
        remote_capabilities: Option<&PeerTransportCapabilities>,
        intent: &TransferIntent,
    ) -> TransportRoute {
        TransportRouter::select(intent, remote_capabilities)
    }

    pub fn export_info(&self, generated_at: u64) -> Result<GatewayNetworkInfo> {
        let snapshot: NetworkRuntimeObservabilitySnapshot = self.observability_snapshot();
        Ok(GatewayNetworkInfo {
            peer_id: self.local_peer_id().to_string(),
            listen_addrs: self.listen_addrs(),
            transport_capabilities: self.transport_capabilities(),
            transport_contact_material: Some(self.export_transport_contact_material(generated_at)?),
            nat_status: snapshot.nat_status,
            nat_public_address: snapshot.nat_public_address,
            nat_confidence: snapshot.nat_confidence,
            relay_reservations: snapshot.relay_reservations,
            peer_health: snapshot.peer_health.into_iter().map(Into::into).collect(),
        })
    }

    pub fn export_handle(&self, generated_at: u64) -> Result<GatewayNetworkHandle> {
        Ok(GatewayNetworkHandle {
            info: self.export_info(generated_at)?,
            state_dir: self.state_dir.clone(),
            local_peer_id: self.local_peer_id(),
        })
    }

    pub fn publish_sync_summary(&mut self, payload: &[u8]) -> Result<()> {
        self.inner
            .publish(&SwarmScope::Global, GossipKind::Summaries, payload)
    }

    pub async fn next_sync_summary(&mut self) -> Result<GatewayNetworkSyncEvent> {
        loop {
            if let Some(event) = classify_sync_event(self.inner.next_event().await?) {
                return Ok(event);
            }
        }
    }
}

fn classify_sync_event(event: SubstrateRuntimeEvent) -> Option<GatewayNetworkSyncEvent> {
    match event {
        SubstrateRuntimeEvent::Gossip {
            propagation_source,
            message:
                RawGossipMessage {
                    scope: SwarmScope::Global,
                    kind: GossipKind::Summaries,
                    payload,
                },
        } => Some(GatewayNetworkSyncEvent::Gossip(GatewayNetworkGossip {
            propagation_source,
            payload,
        })),
        SubstrateRuntimeEvent::GossipNeighborUp {
            peer,
            scope: SwarmScope::Global,
            kind: GossipKind::Summaries,
        } => Some(GatewayNetworkSyncEvent::NeighborUp { peer }),
        _ => None,
    }
}

impl Drop for GatewayNetworkRuntime {
    fn drop(&mut self) {
        shutdown_local_iroh_data_plane(&self.state_dir);
        let _ = fs::remove_file(&self.lock_path);
        let _ = self.lock_file.sync_all();
    }
}

pub async fn fetch_signed_snapshot_via_iroh<T>(
    state_dir: &Path,
    local_peer_id: &NetworkNodeId,
    remote_contact: &TransportContactMaterial,
    snapshot_id: &str,
) -> Result<T>
where
    T: DeserializeOwned,
{
    let state_dir = state_dir.to_owned();
    let local_peer_id = local_peer_id.clone();
    let remote_contact = remote_contact.clone();
    let snapshot_id = snapshot_id.to_owned();
    let response = tokio::task::spawn_blocking(move || {
        fetch_direct_data_for_network_peer_id_with_timeout(
            &state_dir,
            local_peer_id.as_str(),
            &remote_contact,
            &DirectDataFetchRequest {
                object_kind: DirectDataObjectKind::SnapshotJson,
                object_id: snapshot_id,
                scope: Some(PUBLIC_CLIENT_SNAPSHOT_SCOPE.to_owned()),
                source_uri: None,
                expected_digest: None,
                expected_size: None,
            },
            Duration::from_secs(30),
        )
    })
    .await??;
    Ok(serde_json::from_slice(&response.bytes)?)
}

pub fn persist_snapshot_artifact_bytes(
    state_dir: &Path,
    snapshot_node_id: &str,
    bytes: &[u8],
) -> Result<PathBuf> {
    let artifact_store = open_local_artifact_store(state_dir)?;
    artifact_store.write_validated_bytes(
        ArtifactKind::Snapshot,
        snapshot_node_id,
        Some(PUBLIC_CLIENT_SNAPSHOT_SCOPE),
        bytes,
        None,
        Some(bytes.len() as u64),
    )
}

pub fn persist_json_snapshot_artifact<T>(
    state_dir: &Path,
    snapshot_node_id: &str,
    snapshot: &T,
) -> Result<PathBuf>
where
    T: Serialize,
{
    let bytes = serde_json::to_vec(snapshot)?;
    persist_snapshot_artifact_bytes(state_dir, snapshot_node_id, &bytes)
}

fn initialize_state_dir(state_dir: &Path) -> Result<()> {
    fs::create_dir_all(state_dir)?;
    open_local_artifact_store(state_dir)?;
    Ok(())
}

fn acquire_state_dir_lock(state_dir: &Path) -> Result<(PathBuf, File)> {
    let lock_path = state_dir.join(STATE_LOCK_FILE);
    let lock_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&lock_path)
        .map_err(|err| anyhow!("lock state dir {}: {err}", state_dir.display()))?;
    Ok((lock_path, lock_file))
}

fn load_or_create_identity_seed(seed_file: &Path) -> Result<[u8; 32]> {
    if seed_file.exists() {
        let bytes = hex::decode(fs::read_to_string(seed_file)?.trim())?;
        if bytes.len() != 32 {
            anyhow::bail!("seed must be 32 bytes");
        }
        let mut seed = [0_u8; 32];
        seed.copy_from_slice(&bytes);
        return Ok(seed);
    }

    let seed: [u8; 32] = rand::random();
    if let Some(parent) = seed_file.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(seed_file, hex::encode(seed))?;
    Ok(seed)
}

fn artifact_store_path(state_dir: &Path) -> PathBuf {
    state_dir.join("artifacts")
}

fn open_local_artifact_store(state_dir: &Path) -> Result<ArtifactStore> {
    let store = ArtifactStore::new(artifact_store_path(state_dir));
    store.ensure_layout()?;
    Ok(store)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_event_classification_surfaces_summary_neighbors() {
        let state_dir =
            std::env::temp_dir().join(format!("gateway-p2p-sync-event-{}", rand::random::<u64>()));
        let node = GatewayNetworkNode::generate(GatewayP2pConfig {
            state_dir: state_dir.clone(),
            listen_addrs: vec!["127.0.0.1:0".to_owned()],
            ..Default::default()
        })
        .unwrap();
        let peer = node.inner.local_peer_id();

        let event = classify_sync_event(SubstrateRuntimeEvent::GossipNeighborUp {
            peer: peer.clone(),
            scope: SwarmScope::Global,
            kind: GossipKind::Summaries,
        });
        assert!(matches!(
            event,
            Some(GatewayNetworkSyncEvent::NeighborUp { peer: actual }) if actual == peer
        ));

        let ignored = classify_sync_event(SubstrateRuntimeEvent::GossipNeighborUp {
            peer,
            scope: SwarmScope::Global,
            kind: GossipKind::Events,
        });
        assert!(ignored.is_none());

        drop(node);
        std::fs::remove_dir_all(state_dir).unwrap();
    }
}
