use crate::config::GatewayP2pConfig;
use crate::models::SignedPublicClientSnapshot;
use anyhow::{Result, anyhow};
use serde::Serialize;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use wattswarm_artifact_store::{ArtifactKind, ArtifactStore};
use wattswarm_network_substrate::{
    NetworkRuntimeObservabilitySnapshot, PeerId, SubstrateNode, SubstrateRuntime, SwarmScope,
    TrafficGuardPeerHealth,
};
use wattswarm_network_transport_core::{
    PeerTransportCapabilities, TransferIntent, TransportContactMaterial, TransportRoute,
    TransportRouter,
};
use wattswarm_network_transport_iroh::{
    export_local_contact_material, shutdown_local_iroh_data_plane,
};

const NODE_SEED_FILE: &str = "node_seed.hex";
const STATE_LOCK_FILE: &str = ".wattetheria-gateway-p2p.lock";
pub const PUBLIC_CLIENT_SNAPSHOT_SCOPE: &str = "public-client-snapshot";

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
        let local_key = load_or_create_identity_keypair(&config.state_dir.join(NODE_SEED_FILE))?;
        Ok(Self {
            inner: SubstrateNode::new(config.as_substrate(), local_key)?,
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
pub struct GatewayNetworkHandle {
    pub info: GatewayNetworkInfo,
    pub state_dir: PathBuf,
    pub local_peer_id: PeerId,
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

    pub fn local_peer_id(&self) -> PeerId {
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
        export_local_contact_material(&self.state_dir, &self.local_peer_id(), generated_at)
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
}

impl Drop for GatewayNetworkRuntime {
    fn drop(&mut self) {
        shutdown_local_iroh_data_plane(&self.state_dir);
        let _ = fs::remove_file(&self.lock_path);
        let _ = self.lock_file.sync_all();
    }
}

pub fn persist_snapshot_artifact(
    state_dir: &Path,
    snapshot: &SignedPublicClientSnapshot,
) -> Result<PathBuf> {
    let bytes = serde_json::to_vec(snapshot)?;
    let artifact_store = open_local_artifact_store(state_dir)?;
    artifact_store.write_validated_bytes(
        ArtifactKind::Snapshot,
        &snapshot.payload.node_id,
        Some(PUBLIC_CLIENT_SNAPSHOT_SCOPE),
        &bytes,
        None,
        Some(bytes.len() as u64),
    )
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

fn load_or_create_identity_keypair(seed_file: &Path) -> Result<libp2p_identity::Keypair> {
    if seed_file.exists() {
        let mut bytes = hex::decode(fs::read_to_string(seed_file)?.trim())?;
        if bytes.len() != 32 {
            anyhow::bail!("seed must be 32 bytes");
        }
        return Ok(libp2p_identity::Keypair::ed25519_from_bytes(&mut bytes)?);
    }

    let seed: [u8; 32] = rand::random();
    if let Some(parent) = seed_file.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(seed_file, hex::encode(seed))?;
    Ok(libp2p_identity::Keypair::ed25519_from_bytes(seed.to_vec())?)
}

fn artifact_store_path(state_dir: &Path) -> PathBuf {
    state_dir.join("artifacts")
}

fn open_local_artifact_store(state_dir: &Path) -> Result<ArtifactStore> {
    let store = ArtifactStore::new(artifact_store_path(state_dir));
    store.ensure_layout()?;
    Ok(store)
}
