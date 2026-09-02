use crate::contracts::{DataKind, GatewayUiEvent};
use crate::gateway_identity::GatewayIdentity;
use crate::gateway_network::GatewayNetworkHandle;
use crate::gateway_sync::GatewayP2pSyncCommand;
use crate::node_client::NodeClient;
use crate::registry_client::RegistryClient;
use anyhow::Result;
use async_nats::Client as NatsClient;
use serde_json::Value;
use sqlx::PgPool;
use std::collections::{HashMap, VecDeque};
use std::ops::Deref;
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::{broadcast, mpsc};

const FILTERED_UI_STREAM_CAPACITY: usize = 512;
const PUBLISHED_EVENT_CACHE_CAPACITY: usize = 8_192;

#[derive(Debug, Clone)]
pub struct UiStreamEvent {
    pub event: GatewayUiEvent,
    pub payload: Arc<str>,
}

impl UiStreamEvent {
    fn from_event(event: GatewayUiEvent) -> Option<Self> {
        let payload = serde_json::to_string(&event).ok()?;
        Some(Self {
            event,
            payload: Arc::from(payload),
        })
    }
}

impl Deref for UiStreamEvent {
    type Target = GatewayUiEvent;

    fn deref(&self) -> &Self::Target {
        &self.event
    }
}

#[derive(Debug, Default)]
struct PublishedEventCache {
    event_ids: std::collections::HashSet<Arc<str>>,
    order: VecDeque<Arc<str>>,
}

impl PublishedEventCache {
    fn remember(&mut self, event_id: &str) -> bool {
        if self.event_ids.contains(event_id) {
            return false;
        }
        let event_id = Arc::<str>::from(event_id);
        self.event_ids.insert(Arc::clone(&event_id));
        self.order.push_back(event_id);
        if self.order.len() > PUBLISHED_EVENT_CACHE_CAPACITY
            && let Some(expired) = self.order.pop_front()
        {
            self.event_ids.remove(&expired);
        }
        true
    }
}

#[derive(Clone)]
pub struct UiStreamHub {
    all: broadcast::Sender<UiStreamEvent>,
    filtered: Arc<RwLock<HashMap<DataKind, broadcast::Sender<UiStreamEvent>>>>,
    published: Arc<Mutex<PublishedEventCache>>,
}

impl UiStreamHub {
    pub fn new(all: broadcast::Sender<UiStreamEvent>) -> Self {
        Self {
            all,
            filtered: Arc::new(RwLock::new(HashMap::new())),
            published: Arc::new(Mutex::new(PublishedEventCache::default())),
        }
    }

    pub fn subscribe(&self, data_kind: Option<DataKind>) -> broadcast::Receiver<UiStreamEvent> {
        match data_kind {
            Some(data_kind) => {
                let mut filtered = self
                    .filtered
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                filtered
                    .entry(data_kind)
                    .or_insert_with(|| broadcast::channel(FILTERED_UI_STREAM_CAPACITY).0)
                    .subscribe()
            }
            None => self.all.subscribe(),
        }
    }

    fn publish(&self, event: GatewayUiEvent) {
        let Some(stream_event) = UiStreamEvent::from_event(event) else {
            return;
        };
        let should_publish = stream_event.cursor == 0
            || self
                .published
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remember(&stream_event.event_id);
        if !should_publish {
            return;
        }

        let data_kind = stream_event.data_kind;
        let _ = self.all.send(stream_event.clone());
        if let Some(sender) = self
            .filtered
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&data_kind)
        {
            let _ = sender.send(stream_event);
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub node_client: NodeClient,
    pub registry_client: RegistryClient,
    pub nats: Option<NatsClient>,
    pub registry_admin_token: Option<String>,
    pub bootstrap_registry_urls: Vec<String>,
    pub gateway_identity: Option<GatewayIdentity>,
    pub gateway_network: Option<GatewayNetworkHandle>,
    pub gateway_sync_tx: Option<mpsc::Sender<GatewayP2pSyncCommand>>,
    pub ui_stream_tx: UiStreamHub,
}

impl AppState {
    pub async fn publish_event(&self, subject: &str, payload: &Value) -> Result<()> {
        if let Some(client) = &self.nats {
            client
                .publish(subject.to_string(), serde_json::to_vec(payload)?.into())
                .await?;
        }
        Ok(())
    }

    pub fn publish_ui_event(&self, event: GatewayUiEvent) {
        self.ui_stream_tx.publish(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::{EventScope, Visibility};
    use serde_json::json;
    use std::time::Duration;
    use tokio::sync::broadcast;

    fn event(event_id: &str, data_kind: DataKind) -> GatewayUiEvent {
        GatewayUiEvent {
            cursor: 1,
            event_id: event_id.to_owned(),
            node_id: "node-test".to_owned(),
            data_kind,
            event_kind: "test.event".to_owned(),
            visibility: Visibility::Public,
            provisional: false,
            scope: EventScope::default(),
            generated_at: 1,
            payload: json!({"event_id": event_id}),
        }
    }

    #[tokio::test]
    async fn ui_stream_hub_reuses_payload_and_prefilters_filtered_subscribers() {
        let (sender, _) = broadcast::channel(8);
        let hub = UiStreamHub::new(sender);
        let mut all_receiver = hub.subscribe(None);
        let mut presence_receiver = hub.subscribe(Some(DataKind::Presence));

        hub.publish(event("event-1", DataKind::Presence));
        let all_event = all_receiver.recv().await.unwrap();
        let presence_event = presence_receiver.recv().await.unwrap();
        assert_eq!(all_event.event_id, "event-1");
        assert!(Arc::ptr_eq(&all_event.payload, &presence_event.payload));

        hub.publish(event("event-1", DataKind::Presence));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), all_receiver.recv())
                .await
                .is_err()
        );

        hub.publish(event("event-2", DataKind::Identity));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), presence_receiver.recv())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn ui_stream_hub_preserves_repeated_ephemeral_events() {
        let (sender, _) = broadcast::channel(8);
        let hub = UiStreamHub::new(sender);
        let mut receiver = hub.subscribe(None);
        let mut ephemeral = event("presence-heartbeat", DataKind::Presence);
        ephemeral.cursor = 0;

        hub.publish(ephemeral.clone());
        hub.publish(ephemeral);

        assert_eq!(
            receiver.recv().await.unwrap().event_id,
            "presence-heartbeat"
        );
        assert_eq!(
            receiver.recv().await.unwrap().event_id,
            "presence-heartbeat"
        );
    }
}
