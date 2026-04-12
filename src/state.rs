use crate::contracts::GatewayUiEvent;
use crate::gateway_identity::GatewayIdentity;
use crate::gateway_network::GatewayNetworkHandle;
use crate::node_client::NodeClient;
use crate::registry_client::RegistryClient;
use anyhow::Result;
use async_nats::Client as NatsClient;
use serde_json::Value;
use sqlx::PgPool;
use tokio::sync::broadcast;

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
    pub ui_stream_tx: broadcast::Sender<GatewayUiEvent>,
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
        let _ = self.ui_stream_tx.send(event);
    }
}
