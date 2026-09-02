use crate::contracts::SignedNodeEvent;
use crate::db;
use crate::gateway_network::{self, GatewayNetworkRuntime, GatewayNetworkSyncEvent};
use crate::models::{SignedPublicClientSnapshot, SnapshotRow};
use crate::state::AppState;
use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, TryAcquireError, mpsc};
use tokio::time::{Duration, Instant, sleep_until};
use tracing::{debug, warn};
use wattswarm_network_transport_core::{TransportContactMaterial, TransportRoute};

const SNAPSHOT_REANNOUNCE_INTERVAL: Duration = Duration::from_secs(30);
const SNAPSHOT_FULL_RECONCILE_INTERVAL: Duration = Duration::from_secs(300);
const SNAPSHOT_REANNOUNCE_BATCH_INTERVAL: Duration = Duration::from_millis(100);
const SNAPSHOT_REANNOUNCE_BATCH_SIZE: i64 = 256;
const P2P_OUTBOX_BATCH_SIZE: i64 = 32;
const P2P_OUTBOX_POLL_INTERVAL: Duration = Duration::from_secs(1);
const SNAPSHOT_WORKER_COUNT: usize = 4;
const EVENT_WORKER_COUNT: usize = 16;
const GOSSIP_WORK_QUEUE_CAPACITY: usize = 128;
const MAX_PENDING_SNAPSHOT_FETCHES_PER_PEER: usize =
    GOSSIP_WORK_QUEUE_CAPACITY / SNAPSHOT_WORKER_COUNT;
const MAX_COMMANDS_PER_TICK: usize = 32;

#[derive(Debug)]
struct IncomingGossip {
    propagation_source: String,
    payload: Vec<u8>,
}

#[derive(Debug, Clone)]
enum SnapshotReannounceCursor {
    Full {
        started_at: DateTime<Utc>,
        node_id: String,
    },
    Incremental {
        ingested_at: DateTime<Utc>,
        node_id: String,
    },
}

#[derive(Debug, Deserialize)]
struct SnapshotOutboxPayload {
    node_id: String,
    signer_agent_did: String,
    generated_at: i64,
}

#[derive(Debug, Clone)]
pub struct GatewayP2pSyncCommand;

struct GossipWorkLimiter {
    snapshot_global: Arc<Semaphore>,
    event_global: Arc<Semaphore>,
    snapshot_peers: Mutex<HashMap<String, SnapshotPeerLimit>>,
    snapshot_global_notify: Arc<Notify>,
    snapshot_queue_drops: AtomicU64,
    event_queue_drops: AtomicU64,
}

struct SnapshotPeerLimit {
    semaphore: Arc<Semaphore>,
    notify: Arc<Notify>,
    pending: usize,
}

struct SnapshotFetchAdmission {
    limiter: Arc<GossipWorkLimiter>,
    peer_id: String,
    peer_semaphore: Arc<Semaphore>,
    peer_notify: Arc<Notify>,
}

struct NotifyingSemaphorePermit {
    permit: Option<OwnedSemaphorePermit>,
    notify: Arc<Notify>,
}

struct SnapshotWorkPermits {
    _peer: NotifyingSemaphorePermit,
    _global: NotifyingSemaphorePermit,
}

impl NotifyingSemaphorePermit {
    fn new(permit: OwnedSemaphorePermit, notify: Arc<Notify>) -> Self {
        Self {
            permit: Some(permit),
            notify,
        }
    }
}

impl Drop for NotifyingSemaphorePermit {
    fn drop(&mut self) {
        drop(self.permit.take());
        self.notify.notify_one();
    }
}

impl GossipWorkLimiter {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            snapshot_global: Arc::new(Semaphore::new(SNAPSHOT_WORKER_COUNT)),
            event_global: Arc::new(Semaphore::new(EVENT_WORKER_COUNT)),
            snapshot_peers: Mutex::new(HashMap::new()),
            snapshot_global_notify: Arc::new(Notify::new()),
            snapshot_queue_drops: AtomicU64::new(0),
            event_queue_drops: AtomicU64::new(0),
        })
    }

    fn record_queue_drop(&self, lane: GatewayP2pSyncLane) -> u64 {
        let counter = match lane {
            GatewayP2pSyncLane::Snapshot => &self.snapshot_queue_drops,
            GatewayP2pSyncLane::Event => &self.event_queue_drops,
        };
        counter.fetch_add(1, Ordering::Relaxed) + 1
    }

    async fn acquire_event(&self) -> Result<OwnedSemaphorePermit> {
        Arc::clone(&self.event_global)
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("gateway p2p event work limiter closed"))
    }

    fn try_admit_snapshot(self: &Arc<Self>, peer_id: &str) -> Option<SnapshotFetchAdmission> {
        let mut peers = self
            .snapshot_peers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = peers
            .entry(peer_id.to_owned())
            .or_insert_with(|| SnapshotPeerLimit {
                semaphore: Arc::new(Semaphore::new(1)),
                notify: Arc::new(Notify::new()),
                pending: 0,
            });
        if entry.pending >= MAX_PENDING_SNAPSHOT_FETCHES_PER_PEER {
            return None;
        }
        entry.pending += 1;
        Some(SnapshotFetchAdmission {
            limiter: Arc::clone(self),
            peer_id: peer_id.to_owned(),
            peer_semaphore: Arc::clone(&entry.semaphore),
            peer_notify: Arc::clone(&entry.notify),
        })
    }
}

impl SnapshotFetchAdmission {
    #[cfg(test)]
    fn try_acquire_permits(&self) -> Result<Option<SnapshotWorkPermits>> {
        let peer = match Arc::clone(&self.peer_semaphore).try_acquire_owned() {
            Ok(permit) => permit,
            Err(TryAcquireError::Closed) => {
                return Err(anyhow!("gateway p2p snapshot peer limiter closed"));
            }
            Err(TryAcquireError::NoPermits) => return Ok(None),
        };
        match Arc::clone(&self.limiter.snapshot_global).try_acquire_owned() {
            Ok(global) => Ok(Some(SnapshotWorkPermits {
                _peer: NotifyingSemaphorePermit::new(peer, Arc::clone(&self.peer_notify)),
                _global: NotifyingSemaphorePermit::new(
                    global,
                    Arc::clone(&self.limiter.snapshot_global_notify),
                ),
            })),
            Err(TryAcquireError::Closed) => {
                drop(peer);
                self.peer_notify.notify_one();
                Err(anyhow!("gateway p2p snapshot limiter closed"))
            }
            Err(TryAcquireError::NoPermits) => {
                drop(peer);
                self.peer_notify.notify_one();
                Ok(None)
            }
        }
    }

    async fn acquire(&self) -> Result<SnapshotWorkPermits> {
        let mut woke_from_global = false;
        loop {
            let peer_notified = self.peer_notify.notified();
            let peer = match Arc::clone(&self.peer_semaphore).try_acquire_owned() {
                Ok(permit) => permit,
                Err(TryAcquireError::Closed) => {
                    return Err(anyhow!("gateway p2p snapshot peer limiter closed"));
                }
                Err(TryAcquireError::NoPermits) => {
                    if woke_from_global {
                        // A global wake is not useful while this peer is still busy.
                        // Pass it to a waiter for another peer instead.
                        self.limiter.snapshot_global_notify.notify_one();
                        woke_from_global = false;
                    }
                    peer_notified.await;
                    continue;
                }
            };

            let global_notified = self.limiter.snapshot_global_notify.notified();
            match Arc::clone(&self.limiter.snapshot_global).try_acquire_owned() {
                Ok(global) => {
                    return Ok(SnapshotWorkPermits {
                        _peer: NotifyingSemaphorePermit::new(peer, Arc::clone(&self.peer_notify)),
                        _global: NotifyingSemaphorePermit::new(
                            global,
                            Arc::clone(&self.limiter.snapshot_global_notify),
                        ),
                    });
                }
                Err(TryAcquireError::Closed) => {
                    drop(peer);
                    self.peer_notify.notify_one();
                    return Err(anyhow!("gateway p2p snapshot limiter closed"));
                }
                Err(TryAcquireError::NoPermits) => {
                    drop(peer);
                    self.peer_notify.notify_one();
                    global_notified.await;
                    woke_from_global = true;
                }
            }
        }
    }
}

impl Drop for SnapshotFetchAdmission {
    fn drop(&mut self) {
        let mut peers = self
            .limiter
            .snapshot_peers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let remove = if let Some(entry) = peers.get_mut(&self.peer_id) {
            entry.pending = entry.pending.saturating_sub(1);
            entry.pending == 0
        } else {
            false
        };
        if remove {
            peers.remove(&self.peer_id);
        }
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GatewayP2pSyncLane {
    Snapshot,
    Event,
}

#[derive(Debug, Deserialize)]
struct GatewayP2pSyncHeader {
    #[serde(rename = "type")]
    message_type: GatewayP2pSyncMessageType,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum GatewayP2pSyncMessageType {
    SnapshotAnnounceV1,
    EventV1,
}

fn classify_gossip_payload(payload: &[u8]) -> Result<GatewayP2pSyncLane> {
    let mut index = skip_json_whitespace(payload, 0);
    if payload.get(index) != Some(&b'{') {
        bail!("gateway p2p sync payload is not a JSON object");
    }
    index = skip_json_whitespace(payload, index + 1);
    let key_end = json_string_end(payload, index)?;
    let key: String = serde_json::from_slice(&payload[index..key_end])?;
    if key != "type" {
        let header = serde_json::from_slice::<GatewayP2pSyncHeader>(payload)?;
        return Ok(gateway_p2p_sync_lane(header.message_type));
    }
    index = skip_json_whitespace(payload, key_end);
    if payload.get(index) != Some(&b':') {
        bail!("gateway p2p sync payload type field is missing a colon");
    }
    index = skip_json_whitespace(payload, index + 1);
    let value_end = json_string_end(payload, index)?;
    let message_type =
        serde_json::from_slice::<GatewayP2pSyncMessageType>(&payload[index..value_end])?;
    Ok(gateway_p2p_sync_lane(message_type))
}

fn gateway_p2p_sync_lane(message_type: GatewayP2pSyncMessageType) -> GatewayP2pSyncLane {
    match message_type {
        GatewayP2pSyncMessageType::SnapshotAnnounceV1 => GatewayP2pSyncLane::Snapshot,
        GatewayP2pSyncMessageType::EventV1 => GatewayP2pSyncLane::Event,
    }
}

fn skip_json_whitespace(payload: &[u8], mut index: usize) -> usize {
    while payload
        .get(index)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        index += 1;
    }
    index
}

fn json_string_end(payload: &[u8], start: usize) -> Result<usize> {
    if payload.get(start) != Some(&b'"') {
        bail!("gateway p2p sync payload expected a JSON string");
    }
    let mut escaped = false;
    for (index, byte) in payload.iter().enumerate().skip(start + 1) {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' => escaped = true,
            b'"' => return Ok(index + 1),
            _ => {}
        }
    }
    bail!("gateway p2p sync payload contains an unterminated JSON string")
}

fn spawn_gossip_dispatcher(
    mut queue: mpsc::Receiver<IncomingGossip>,
    state: AppState,
    work_limiter: Arc<GossipWorkLimiter>,
    work_queue_slots: Arc<Semaphore>,
    lane: GatewayP2pSyncLane,
) {
    tokio::spawn(async move {
        while let Some(gossip) = queue.recv().await {
            let slot = match Arc::clone(&work_queue_slots).acquire_owned().await {
                Ok(slot) => slot,
                Err(_) => {
                    warn!(lane = ?lane, "gateway p2p gossip work queue closed");
                    break;
                }
            };
            let worker_state = state.clone();
            let worker_limiter = Arc::clone(&work_limiter);
            tokio::spawn(async move {
                let _slot = slot;
                let IncomingGossip {
                    propagation_source,
                    payload,
                } = gossip;
                if let Err(error) =
                    handle_gossip(&worker_state, &worker_limiter, &propagation_source, payload)
                        .await
                {
                    warn!(lane = ?lane, "gateway p2p sync ingest failed: {error:#}");
                }
            });
        }
    });
}

fn enqueue_gossip(
    sender: &mpsc::Sender<IncomingGossip>,
    gossip: IncomingGossip,
    limiter: &GossipWorkLimiter,
    lane: GatewayP2pSyncLane,
) {
    match sender.try_send(gossip) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            let dropped = limiter.record_queue_drop(lane);
            warn!(
                lane = ?lane,
                dropped_count = dropped,
                queue_capacity = GOSSIP_WORK_QUEUE_CAPACITY,
                "dropping gateway p2p gossip because the lane queue is full"
            );
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            warn!(lane = ?lane, "gateway p2p gossip lane is closed");
        }
    }
}

pub async fn run_gateway_p2p_sync(
    mut runtime: GatewayNetworkRuntime,
    state: AppState,
    mut commands: mpsc::Receiver<GatewayP2pSyncCommand>,
) {
    let work_limiter = GossipWorkLimiter::new();
    let (event_tx, event_rx) = mpsc::channel(GOSSIP_WORK_QUEUE_CAPACITY);
    let (snapshot_tx, snapshot_rx) = mpsc::channel(GOSSIP_WORK_QUEUE_CAPACITY);
    spawn_gossip_dispatcher(
        event_rx,
        state.clone(),
        Arc::clone(&work_limiter),
        Arc::new(Semaphore::new(GOSSIP_WORK_QUEUE_CAPACITY)),
        GatewayP2pSyncLane::Event,
    );
    spawn_gossip_dispatcher(
        snapshot_rx,
        state.clone(),
        Arc::clone(&work_limiter),
        Arc::new(Semaphore::new(GOSSIP_WORK_QUEUE_CAPACITY)),
        GatewayP2pSyncLane::Snapshot,
    );

    let mut next_snapshot_reannounce = Instant::now();
    let mut next_full_reconcile = Instant::now();
    let mut next_outbox_poll = Instant::now();
    let mut snapshot_cursor = None;
    let mut commands_open = true;
    let mut gossip_retry_at = None;
    loop {
        if let Err(error) = run_periodic_sync_work(
            &mut runtime,
            &state,
            &mut snapshot_cursor,
            &mut next_snapshot_reannounce,
            &mut next_full_reconcile,
            &mut next_outbox_poll,
        )
        .await
        {
            warn!("gateway p2p sync periodic work failed: {error:#}");
        }
        if gossip_retry_at.is_some_and(|deadline| Instant::now() >= deadline) {
            gossip_retry_at = None;
        }

        let next_deadline = gossip_retry_at
            .map(|deadline| next_snapshot_reannounce.min(next_outbox_poll).min(deadline))
            .unwrap_or_else(|| next_snapshot_reannounce.min(next_outbox_poll));
        tokio::select! {
            command = commands.recv(), if commands_open => {
                match command {
                    Some(_) => {
                        let _ = drain_command_batch(&mut commands);
                        if let Err(error) = drain_p2p_outbox(&mut runtime, &state).await {
                            warn!("gateway p2p outbox drain failed: {error:#}");
                        }
                    }
                    None => commands_open = false,
                    }
            }
            gossip = runtime.next_sync_summary(), if gossip_retry_at.is_none() => {
                match gossip {
                    Ok(GatewayNetworkSyncEvent::Gossip(gossip)) => {
                        match classify_gossip_payload(&gossip.payload) {
                            Ok(lane) => {
                                let incoming = IncomingGossip {
                                    propagation_source: gossip.propagation_source.to_string(),
                                    payload: gossip.payload,
                                };
                                match lane {
                                    GatewayP2pSyncLane::Event => {
                                        enqueue_gossip(&event_tx, incoming, &work_limiter, lane);
                                    }
                                    GatewayP2pSyncLane::Snapshot => {
                                        enqueue_gossip(
                                            &snapshot_tx,
                                            incoming,
                                            &work_limiter,
                                            lane,
                                        );
                                    }
                                }
                            }
                            Err(error) => {
                                debug!("ignore non-gateway p2p sync summary: {error}");
                            }
                        }
                    }
                    Ok(GatewayNetworkSyncEvent::NeighborUp { peer }) => {
                        schedule_full_reconcile(
                            Instant::now(),
                            &mut next_snapshot_reannounce,
                            &mut next_full_reconcile,
                        );
                        debug!(peer = %peer, "gateway p2p neighbor joined; scheduling snapshot reconcile");
                    }
                    Err(error) => {
                        gossip_retry_at = Some(Instant::now() + Duration::from_secs(1));
                        warn!("gateway p2p sync receive failed; retrying in 1s: {error:#}");
                    }
                }
            }
            _ = sleep_until(next_deadline) => {}
        }
    }
}

fn schedule_full_reconcile(
    now: Instant,
    next_snapshot_reannounce: &mut Instant,
    next_full_reconcile: &mut Instant,
) {
    *next_snapshot_reannounce = (*next_snapshot_reannounce).min(now);
    *next_full_reconcile = (*next_full_reconcile).min(now);
}

async fn run_periodic_sync_work(
    runtime: &mut GatewayNetworkRuntime,
    state: &AppState,
    snapshot_cursor: &mut Option<SnapshotReannounceCursor>,
    next_snapshot_reannounce: &mut Instant,
    next_full_reconcile: &mut Instant,
    next_outbox_poll: &mut Instant,
) -> Result<()> {
    let now = Instant::now();
    if now >= *next_outbox_poll {
        *next_outbox_poll = now + P2P_OUTBOX_POLL_INTERVAL;
        drain_p2p_outbox(runtime, state).await?;
    }
    if now < *next_snapshot_reannounce {
        return Ok(());
    }

    let full_reconcile = now >= *next_full_reconcile;
    match reannounce_local_snapshots(runtime, state, snapshot_cursor, full_reconcile).await {
        Ok(has_more) => {
            if full_reconcile && !has_more {
                *next_full_reconcile = Instant::now() + SNAPSHOT_FULL_RECONCILE_INTERVAL;
            }
            *next_snapshot_reannounce = next_snapshot_reannounce_deadline(Instant::now(), has_more);
            Ok(())
        }
        Err(error) => {
            *next_snapshot_reannounce = Instant::now() + Duration::from_secs(5);
            Err(error)
        }
    }
}

fn next_snapshot_reannounce_deadline(now: Instant, has_more: bool) -> Instant {
    now + if has_more {
        SNAPSHOT_REANNOUNCE_BATCH_INTERVAL
    } else {
        SNAPSHOT_REANNOUNCE_INTERVAL
    }
}

fn drain_command_batch(commands: &mut mpsc::Receiver<GatewayP2pSyncCommand>) -> usize {
    let mut drained = 0;
    while drained < MAX_COMMANDS_PER_TICK {
        match commands.try_recv() {
            Ok(_) => drained += 1,
            Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                break;
            }
        }
    }
    drained
}

async fn drain_p2p_outbox(runtime: &mut GatewayNetworkRuntime, state: &AppState) -> Result<()> {
    let rows = db::claim_p2p_outbox(&state.pool, P2P_OUTBOX_BATCH_SIZE).await?;
    let contact = if rows
        .iter()
        .any(|row| row.command_kind == db::P2P_OUTBOX_COMMAND_SNAPSHOT)
    {
        Some(
            runtime
                .export_transport_contact_material(Utc::now().timestamp_millis().max(0) as u64)?,
        )
    } else {
        None
    };
    for row in rows {
        let message = match outbox_message(runtime.local_peer_id().as_str(), contact.as_ref(), &row)
        {
            Ok(message) => message,
            Err(error) => {
                db::ack_p2p_outbox(&state.pool, row.id).await?;
                warn!(
                    outbox_id = row.id,
                    dedupe_key = %row.dedupe_key,
                    attempts = row.attempts,
                    "discarding malformed gateway p2p outbox payload: {error:#}"
                );
                continue;
            }
        };
        match runtime.publish_sync_summary(&message) {
            Ok(()) => db::ack_p2p_outbox(&state.pool, row.id).await?,
            Err(error) => {
                let exhausted = db::release_p2p_outbox(&state.pool, row.id).await?;
                if exhausted {
                    warn!(
                        outbox_id = row.id,
                        dedupe_key = %row.dedupe_key,
                        attempts = row.attempts,
                        "discarding gateway p2p outbox row after retry limit: {error:#}"
                    );
                } else {
                    warn!(
                        outbox_id = row.id,
                        dedupe_key = %row.dedupe_key,
                        attempts = row.attempts,
                        "gateway p2p outbox publish failed: {error:#}"
                    );
                }
            }
        }
    }
    Ok(())
}

fn outbox_message(
    local_peer_id: &str,
    contact: Option<&TransportContactMaterial>,
    row: &db::P2pOutboxRow,
) -> Result<Vec<u8>> {
    let message = match row.command_kind.as_str() {
        db::P2P_OUTBOX_COMMAND_SNAPSHOT => {
            let payload: SnapshotOutboxPayload = serde_json::from_value(row.payload.0.clone())?;
            GatewayP2pSyncMessage::SnapshotAnnounceV1 {
                gateway_peer_id: local_peer_id.to_owned(),
                node_id: payload.node_id,
                signer_agent_did: payload.signer_agent_did,
                generated_at: payload.generated_at,
                transport_contact_material: Box::new(
                    contact
                        .context("snapshot outbox contact material was not exported")?
                        .clone(),
                ),
            }
        }
        db::P2P_OUTBOX_COMMAND_EVENT => GatewayP2pSyncMessage::EventV1 {
            gateway_peer_id: local_peer_id.to_owned(),
            event: Box::new(serde_json::from_value(row.payload.0.clone())?),
        },
        command_kind => bail!("unknown gateway p2p outbox command kind {command_kind}"),
    };
    Ok(serde_json::to_vec(&message)?)
}

fn publish_snapshot_announcements(
    runtime: &mut GatewayNetworkRuntime,
    snapshots: &[SnapshotRow],
) -> Result<()> {
    if snapshots.is_empty() {
        return Ok(());
    }
    let contact =
        runtime.export_transport_contact_material(Utc::now().timestamp_millis().max(0) as u64)?;
    let gateway_peer_id = runtime.local_peer_id().to_string();
    for snapshot in snapshots {
        let message = GatewayP2pSyncMessage::SnapshotAnnounceV1 {
            gateway_peer_id: gateway_peer_id.clone(),
            node_id: snapshot.node_id.clone(),
            signer_agent_did: snapshot.signer_agent_did.clone(),
            generated_at: snapshot_payload_generated_at(&snapshot.payload.0)
                .unwrap_or_else(|| snapshot.generated_at.timestamp()),
            transport_contact_material: Box::new(contact.clone()),
        };
        runtime.publish_sync_summary(&serde_json::to_vec(&message)?)?;
    }
    Ok(())
}

async fn reannounce_local_snapshots(
    runtime: &mut GatewayNetworkRuntime,
    state: &AppState,
    cursor: &mut Option<SnapshotReannounceCursor>,
    full_reconcile: bool,
) -> Result<bool> {
    let start_full_reconcile =
        full_reconcile && !matches!(cursor.as_ref(), Some(SnapshotReannounceCursor::Full { .. }));
    if start_full_reconcile {
        *cursor = Some(SnapshotReannounceCursor::Full {
            started_at: Utc::now(),
            node_id: String::new(),
        });
    }

    if let Some(SnapshotReannounceCursor::Full {
        started_at,
        node_id,
    }) = cursor.as_ref()
    {
        let started_at = *started_at;
        let node_id = node_id.clone();
        let snapshots = db::list_visible_snapshots_after_node_id(
            &state.pool,
            &node_id,
            SNAPSHOT_REANNOUNCE_BATCH_SIZE,
        )
        .await?;
        let has_more = snapshots.len() as i64 >= SNAPSHOT_REANNOUNCE_BATCH_SIZE;
        publish_snapshot_announcements(runtime, &snapshots)?;
        *cursor = Some(next_full_reconcile_cursor(
            started_at,
            snapshots.last().map(|snapshot| snapshot.node_id.as_str()),
            has_more,
        ));
        return Ok(has_more);
    }

    let Some(SnapshotReannounceCursor::Incremental {
        ingested_at,
        node_id,
    }) = cursor.as_ref()
    else {
        return Ok(true);
    };
    let ingested_at = *ingested_at;
    let node_id = node_id.clone();
    let snapshots = db::list_visible_snapshots_updated_after(
        &state.pool,
        ingested_at,
        Some(&node_id),
        SNAPSHOT_REANNOUNCE_BATCH_SIZE,
    )
    .await?;
    let has_more = snapshots.len() as i64 >= SNAPSHOT_REANNOUNCE_BATCH_SIZE;
    if let Some(last) = snapshots.last() {
        publish_snapshot_announcements(runtime, &snapshots)?;
        *cursor = Some(SnapshotReannounceCursor::Incremental {
            ingested_at: last.ingested_at,
            node_id: last.node_id.clone(),
        });
    }
    Ok(has_more)
}

fn next_full_reconcile_cursor(
    started_at: DateTime<Utc>,
    last_node_id: Option<&str>,
    has_more: bool,
) -> SnapshotReannounceCursor {
    if has_more {
        SnapshotReannounceCursor::Full {
            started_at,
            node_id: last_node_id.unwrap_or_default().to_owned(),
        }
    } else {
        SnapshotReannounceCursor::Incremental {
            ingested_at: started_at,
            node_id: String::new(),
        }
    }
}

fn snapshot_payload_generated_at(payload: &serde_json::Value) -> Option<i64> {
    payload
        .get("generated_at")
        .and_then(serde_json::Value::as_i64)
}

async fn handle_gossip(
    state: &AppState,
    work_limiter: &Arc<GossipWorkLimiter>,
    propagation_source: &str,
    payload: Vec<u8>,
) -> Result<()> {
    let message = match serde_json::from_slice::<GatewayP2pSyncMessage>(&payload) {
        Ok(message) => message,
        Err(error) => {
            debug!("ignore malformed gateway p2p sync summary: {error}");
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
            validate_snapshot_announcement(
                propagation_source,
                &gateway_peer_id,
                &transport_contact_material,
            )?;
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
            let Some(fetch_admission) = work_limiter.try_admit_snapshot(&gateway_peer_id) else {
                warn!(
                    gateway_peer_id,
                    node_id,
                    "dropping gateway p2p snapshot announcement because the peer queue is full"
                );
                return Ok(());
            };
            let _work_permits = fetch_admission.acquire().await?;
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
            let _work_permit = work_limiter.acquire_event().await?;
            crate::streaming::persist_signed_node_event_without_p2p_announce(
                state, &event, None, None,
            )
            .await?;
        }
    }
    Ok(())
}

fn validate_snapshot_announcement(
    propagation_source: &str,
    gateway_peer_id: &str,
    contact: &TransportContactMaterial,
) -> Result<()> {
    if propagation_source.trim().is_empty() {
        bail!("gateway p2p gossip propagation source is empty");
    }
    if gateway_peer_id.trim().is_empty() {
        bail!("gateway p2p snapshot announcement peer id is empty");
    }
    // Gossip reports the immediate forwarding hop, not necessarily the original announcer.
    if contact.transport != TransportRoute::IrohDirect.as_str()
        || contact.metadata.route != TransportRoute::IrohDirect
    {
        bail!("gateway p2p snapshot announcement must use iroh_direct");
    }
    if contact.peer_id != gateway_peer_id {
        bail!(
            "gateway p2p snapshot contact peer mismatch: announced {gateway_peer_id}, contact {}",
            contact.peer_id
        );
    }
    let metadata_endpoint = contact.metadata.endpoint_id.as_deref();
    let extra_endpoint = contact
        .extra
        .get("endpoint_id")
        .and_then(serde_json::Value::as_str);
    let endpoint_id = extra_endpoint.or(metadata_endpoint).unwrap_or_default();
    if endpoint_id.is_empty() {
        bail!("gateway p2p snapshot contact endpoint id is empty");
    }
    if metadata_endpoint.is_some_and(|value| value != endpoint_id) || endpoint_id != gateway_peer_id
    {
        bail!("gateway p2p snapshot contact endpoint does not match gateway peer");
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wattswarm_network_transport_core::{PeerTransportCapabilities, TransportMetadata};

    #[test]
    fn command_drain_is_bounded_to_one_tick() {
        let (sender, mut receiver) = mpsc::channel(MAX_COMMANDS_PER_TICK + 1);
        for _ in 0..=MAX_COMMANDS_PER_TICK {
            sender
                .try_send(GatewayP2pSyncCommand)
                .expect("command should fit in test queue");
        }

        let drained = drain_command_batch(&mut receiver);

        assert_eq!(drained, MAX_COMMANDS_PER_TICK);
        assert!(receiver.try_recv().is_ok());
    }

    #[test]
    fn snapshot_reannounce_pages_are_paced() {
        let now = Instant::now();
        assert_eq!(
            next_snapshot_reannounce_deadline(now, true),
            now + SNAPSHOT_REANNOUNCE_BATCH_INTERVAL
        );
        assert_eq!(
            next_snapshot_reannounce_deadline(now, false),
            now + SNAPSHOT_REANNOUNCE_INTERVAL
        );
    }

    #[test]
    fn neighbor_join_schedules_immediate_full_reconcile() {
        let now = Instant::now();
        let mut next_snapshot = now + Duration::from_secs(30);
        let mut next_full = now + Duration::from_secs(300);

        schedule_full_reconcile(now, &mut next_snapshot, &mut next_full);

        assert_eq!(next_snapshot, now);
        assert_eq!(next_full, now);
    }

    #[test]
    fn gossip_header_classification_avoids_materializing_message_body() {
        assert_eq!(
            classify_gossip_payload(br#"{"type":"event_v1","event":{}}"#).unwrap(),
            GatewayP2pSyncLane::Event
        );
        assert_eq!(
            classify_gossip_payload(br#"{"type":"event_v1","event":"unterminated"#).unwrap(),
            GatewayP2pSyncLane::Event
        );
        assert_eq!(
            classify_gossip_payload(br#"{"type":"snapshot_announce_v1","node_id":"node-a"}"#)
                .unwrap(),
            GatewayP2pSyncLane::Snapshot
        );
        assert_eq!(
            classify_gossip_payload(br#"{"event":{},"type":"event_v1"}"#).unwrap(),
            GatewayP2pSyncLane::Event
        );
    }

    #[test]
    fn final_full_reconcile_page_immediately_enters_incremental_mode() {
        let started_at = Utc::now();

        let final_cursor = next_full_reconcile_cursor(started_at, Some("node-z"), false);
        assert!(matches!(
            final_cursor,
            SnapshotReannounceCursor::Incremental { ingested_at, ref node_id }
                if ingested_at == started_at && node_id.is_empty()
        ));

        let paged_cursor = next_full_reconcile_cursor(started_at, Some("node-z"), true);
        assert!(matches!(
            paged_cursor,
            SnapshotReannounceCursor::Full { started_at: actual, ref node_id }
                if actual == started_at && node_id == "node-z"
        ));
    }

    #[tokio::test]
    async fn snapshot_fetch_limiter_serializes_each_peer_without_blocking_others() {
        let limiter = GossipWorkLimiter::new();
        let first = limiter.try_admit_snapshot("peer-a").unwrap();
        let second = limiter.try_admit_snapshot("peer-a").unwrap();
        let other = limiter.try_admit_snapshot("peer-b").unwrap();
        let first_permits = first.acquire().await.unwrap();

        assert_eq!(second.peer_semaphore.available_permits(), 0);
        assert_eq!(
            limiter.snapshot_global.available_permits(),
            SNAPSHOT_WORKER_COUNT - 1
        );
        let other_permits = other.acquire().await.unwrap();

        drop(other_permits);
        drop(first_permits);
        let second_permits = second.acquire().await.unwrap();
        drop(second_permits);
    }

    #[tokio::test]
    async fn snapshot_admission_wakes_when_a_snapshot_permit_is_released() {
        let limiter = GossipWorkLimiter::new();
        let admissions = (0..SNAPSHOT_WORKER_COUNT)
            .map(|index| {
                limiter
                    .try_admit_snapshot(&format!("peer-{index}"))
                    .expect("peer admission should fit")
            })
            .collect::<Vec<_>>();
        let mut held_permits = Vec::new();
        for admission in &admissions {
            held_permits.push(admission.acquire().await.unwrap());
        }

        let waiting_admission = limiter.try_admit_snapshot("peer-waiting").unwrap();
        let waiting_task = tokio::spawn(async move { waiting_admission.acquire().await });
        tokio::task::yield_now().await;
        assert!(!waiting_task.is_finished());

        drop(
            held_permits
                .pop()
                .expect("a snapshot permit should be held"),
        );
        let waiting_permit = tokio::time::timeout(Duration::from_secs(1), waiting_task)
            .await
            .expect("snapshot admission should be notified")
            .expect("snapshot admission task should finish")
            .expect("snapshot admission should acquire permits");
        drop(waiting_permit);
        drop(held_permits);
        drop(admissions);
    }

    #[tokio::test]
    async fn snapshot_admission_does_not_steal_global_wakeup_from_another_peer() {
        let limiter = GossipWorkLimiter::new();
        let held_global = (0..SNAPSHOT_WORKER_COUNT)
            .map(|_| {
                Arc::clone(&limiter.snapshot_global)
                    .try_acquire_owned()
                    .expect("snapshot permit should be available")
            })
            .collect::<Vec<_>>();

        let blocked_admission = limiter.try_admit_snapshot("peer-a").unwrap();
        let blocked_peer_permit = Arc::clone(&blocked_admission.peer_semaphore)
            .try_acquire_owned()
            .expect("peer-a should have one peer permit");
        let blocked_task = tokio::spawn(async move { blocked_admission.acquire().await });
        tokio::task::yield_now().await;

        let other_admission = limiter.try_admit_snapshot("peer-b").unwrap();
        let other_task = tokio::spawn(async move { other_admission.acquire().await });
        tokio::task::yield_now().await;
        assert!(!other_task.is_finished());

        let mut held_global = held_global;
        let released_global = held_global.pop().expect("a snapshot permit should be held");
        drop(NotifyingSemaphorePermit::new(
            released_global,
            Arc::clone(&limiter.snapshot_global_notify),
        ));

        let other_permits = tokio::time::timeout(Duration::from_secs(1), other_task)
            .await
            .expect("another peer should receive the global wakeup")
            .expect("another peer admission task should finish")
            .expect("another peer should acquire snapshot permits");
        drop(other_permits);

        blocked_task.abort();
        let _ = blocked_task.await;
        drop(blocked_peer_permit);
        drop(held_global);
    }

    #[tokio::test]
    async fn event_work_limit_is_independent_of_snapshot_fetch_limit() {
        let limiter = GossipWorkLimiter::new();
        let snapshot_permits = (0..SNAPSHOT_WORKER_COUNT)
            .map(|_| {
                Arc::clone(&limiter.snapshot_global)
                    .try_acquire_owned()
                    .expect("snapshot permit should be available")
            })
            .collect::<Vec<_>>();

        assert_eq!(limiter.snapshot_global.available_permits(), 0);
        assert_eq!(limiter.event_global.available_permits(), EVENT_WORKER_COUNT);

        let event_permit = limiter.acquire_event().await.unwrap();
        assert_eq!(
            limiter.event_global.available_permits(),
            EVENT_WORKER_COUNT - 1
        );

        drop(event_permit);
        drop(snapshot_permits);
    }

    #[test]
    fn snapshot_admission_releases_peer_permit_when_snapshot_slots_are_full() {
        let limiter = GossipWorkLimiter::new();
        let snapshot_permits = (0..SNAPSHOT_WORKER_COUNT)
            .map(|_| {
                Arc::clone(&limiter.snapshot_global)
                    .try_acquire_owned()
                    .expect("snapshot permit should be available")
            })
            .collect::<Vec<_>>();
        let admission = limiter.try_admit_snapshot("peer-a").unwrap();

        assert!(admission.try_acquire_permits().unwrap().is_none());
        assert_eq!(admission.peer_semaphore.available_permits(), 1);

        drop(snapshot_permits);
        let permits = admission
            .try_acquire_permits()
            .unwrap()
            .expect("snapshot permits should be available after release");
        drop(permits);
    }

    #[test]
    fn snapshot_fetch_limiter_bounds_each_peer_queue() {
        let limiter = GossipWorkLimiter::new();
        let admissions = (0..MAX_PENDING_SNAPSHOT_FETCHES_PER_PEER)
            .map(|_| limiter.try_admit_snapshot("peer-a").unwrap())
            .collect::<Vec<_>>();

        assert!(limiter.try_admit_snapshot("peer-a").is_none());
        assert!(limiter.try_admit_snapshot("peer-b").is_some());

        drop(admissions);
        assert!(limiter.try_admit_snapshot("peer-a").is_some());
    }

    #[test]
    fn snapshot_queue_drops_are_counted_without_affecting_event_queue() {
        let limiter = GossipWorkLimiter::new();
        let (sender, mut receiver) = mpsc::channel(1);
        let gossip = || IncomingGossip {
            propagation_source: "peer-a".to_owned(),
            payload: Vec::new(),
        };

        enqueue_gossip(&sender, gossip(), &limiter, GatewayP2pSyncLane::Snapshot);
        enqueue_gossip(&sender, gossip(), &limiter, GatewayP2pSyncLane::Snapshot);

        assert_eq!(limiter.snapshot_queue_drops.load(Ordering::Relaxed), 1);
        assert_eq!(limiter.event_queue_drops.load(Ordering::Relaxed), 0);
        assert!(receiver.try_recv().is_ok());
    }

    fn contact(peer_id: &str) -> TransportContactMaterial {
        TransportContactMaterial {
            transport: TransportRoute::IrohDirect.as_str().to_owned(),
            peer_id: peer_id.to_owned(),
            metadata: TransportMetadata {
                route: TransportRoute::IrohDirect,
                generated_at: 1,
                endpoint_id: Some(peer_id.to_owned()),
                alpn: None,
                listen_addrs: Vec::new(),
                capabilities: PeerTransportCapabilities::iroh_direct_default(),
            },
            extra: json!({"endpoint_id": peer_id}),
        }
    }

    #[test]
    fn snapshot_announcement_requires_contact_identity_binding() {
        let valid = contact("peer-a");
        assert!(validate_snapshot_announcement("peer-b", "peer-a", &valid).is_ok());

        let mut mismatched = valid.clone();
        mismatched.peer_id = "peer-b".to_owned();
        assert!(validate_snapshot_announcement("peer-b", "peer-a", &mismatched).is_err());

        mismatched = valid;
        mismatched.extra = json!({"endpoint_id": "peer-b"});
        assert!(validate_snapshot_announcement("peer-b", "peer-a", &mismatched).is_err());
    }
}
