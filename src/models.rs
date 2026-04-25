use crate::contracts::{DataKind, EventScope, GatewayUiEvent, SourceStatus, Visibility};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use uuid::Uuid;
use wattswarm_network_transport_core::{PeerTransportCapabilities, TransportContactMaterial};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPublicClientSnapshot {
    pub payload: PublicClientSnapshot,
    pub signature: String,
    #[serde(alias = "signer_agent_id")]
    pub signer_agent_did: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicClientSnapshot {
    pub generated_at: i64,
    pub node_id: String,
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_org_name: Option<String>,
    pub network_status: Value,
    pub peers: Vec<Value>,
    pub operator: Value,
    pub rpc_logs: Vec<Value>,
    #[serde(default)]
    pub friend_relationships: Vec<Value>,
    #[serde(default)]
    pub pending_friend_requests: Vec<Value>,
    #[serde(default)]
    pub public_blocks: Vec<Value>,
    #[serde(default)]
    pub dm_threads: Vec<Value>,
    #[serde(default)]
    pub dm_messages: Vec<Value>,
    #[serde(default)]
    pub public_topics: Vec<Value>,
    #[serde(default)]
    pub public_topic_messages: Vec<Value>,
    #[serde(default)]
    pub swarm_task_activity: Value,
    pub tasks: Vec<Value>,
    pub organizations: Vec<Value>,
    pub leaderboard: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayManifest {
    pub generated_at: i64,
    pub gateway_id: String,
    pub display_name: String,
    pub base_url: String,
    pub public_key: String,
    pub region: Option<String>,
    #[serde(alias = "operator_id")]
    pub operator_did: Option<String>,
    pub roles: Vec<String>,
    pub supported_endpoints: Vec<String>,
    pub federation_peers: Vec<String>,
    pub allows_public_ingest: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedGatewayManifest {
    pub payload: GatewayManifest,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct NodeSourceRow {
    pub id: Uuid,
    pub name: String,
    pub export_url: String,
    pub wattetheria_snapshot_export_url: Option<String>,
    pub wattetheria_events_export_url: Option<String>,
    pub wattswarm_ui_base_url: Option<String>,
    pub wattswarm_sync_grpc_endpoint: Option<String>,
    pub region: Option<String>,
    pub expected_signer_agent_did: Option<String>,
    pub expected_wattswarm_node_id: Option<String>,
    pub source_status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub last_sync_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_sync_status: Option<String>,
    pub last_error: Option<String>,
    pub transport_capabilities: Option<sqlx::types::Json<PeerTransportCapabilities>>,
    pub transport_contact_material: Option<sqlx::types::Json<TransportContactMaterial>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SnapshotRow {
    pub source_id: Option<Uuid>,
    pub node_id: String,
    pub signer_agent_did: String,
    pub public_key: String,
    pub generated_at: i64,
    pub ingested_at: chrono::DateTime<chrono::Utc>,
    pub payload: sqlx::types::Json<Value>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ProjectionRow {
    pub data_kind: String,
    pub identity_key: String,
    pub source_node_id: String,
    pub source_id: Option<Uuid>,
    pub generated_at: i64,
    pub ingested_at: chrono::DateTime<chrono::Utc>,
    pub visibility: String,
    pub payload: sqlx::types::Json<Value>,
    pub provenance: sqlx::types::Json<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UiEventRow {
    pub cursor: i64,
    pub event_id: String,
    pub source_id: Option<Uuid>,
    pub node_id: String,
    pub signer_agent_did: String,
    pub data_kind: String,
    pub event_kind: String,
    pub visibility: String,
    pub provisional: bool,
    pub topic_id: Option<String>,
    pub organization_id: Option<String>,
    pub task_id: Option<String>,
    pub generated_at: i64,
    pub ingested_at: chrono::DateTime<chrono::Utc>,
    pub payload: sqlx::types::Json<Value>,
    pub ingest_path: String,
    pub source_cursor_or_seq: Option<i64>,
}

impl TryFrom<UiEventRow> for GatewayUiEvent {
    type Error = anyhow::Error;

    fn try_from(value: UiEventRow) -> Result<Self, Self::Error> {
        Ok(Self {
            cursor: value.cursor,
            event_id: value.event_id,
            node_id: value.node_id,
            data_kind: serde_json::from_value::<DataKind>(Value::String(value.data_kind))?,
            event_kind: value.event_kind,
            visibility: serde_json::from_value::<Visibility>(Value::String(value.visibility))?,
            provisional: value.provisional,
            scope: EventScope {
                node_id: None,
                topic_id: value.topic_id,
                organization_id: value.organization_id,
                task_id: value.task_id,
            },
            generated_at: value.generated_at,
            payload: value.payload.0,
        })
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct GatewayRegistryDbRow {
    pub gateway_id: String,
    pub display_name: String,
    pub base_url: String,
    pub public_key: String,
    pub region: Option<String>,
    pub operator_did: Option<String>,
    pub roles: sqlx::types::Json<Vec<String>>,
    pub supported_endpoints: sqlx::types::Json<Vec<String>>,
    pub federation_peers: sqlx::types::Json<Vec<String>>,
    pub allows_public_ingest: bool,
    pub manifest_payload: sqlx::types::Json<GatewayManifest>,
    pub manifest_signature: String,
    pub status: String,
    pub discovery_tier: String,
    pub review_reason: Option<String>,
    pub reviewed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub reviewed_by: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayRegistryEntry {
    pub gateway_id: String,
    pub display_name: String,
    pub base_url: String,
    pub public_key: String,
    pub region: Option<String>,
    pub operator_did: Option<String>,
    pub roles: Vec<String>,
    pub supported_endpoints: Vec<String>,
    pub federation_peers: Vec<String>,
    pub allows_public_ingest: bool,
    pub manifest: GatewayManifest,
    pub manifest_signature: String,
    pub status: String,
    pub discovery_tier: String,
    pub review_reason: Option<String>,
    pub reviewed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub reviewed_by: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<GatewayRegistryDbRow> for GatewayRegistryEntry {
    fn from(value: GatewayRegistryDbRow) -> Self {
        Self {
            gateway_id: value.gateway_id,
            display_name: value.display_name,
            base_url: value.base_url,
            public_key: value.public_key,
            region: value.region,
            operator_did: value.operator_did,
            roles: value.roles.0,
            supported_endpoints: value.supported_endpoints.0,
            federation_peers: value.federation_peers.0,
            allows_public_ingest: value.allows_public_ingest,
            manifest: value.manifest_payload.0,
            manifest_signature: value.manifest_signature,
            status: value.status,
            discovery_tier: value.discovery_tier,
            review_reason: value.review_reason,
            reviewed_at: value.reviewed_at,
            reviewed_by: value.reviewed_by,
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegisterNodeRequest {
    pub name: String,
    #[serde(default)]
    pub export_url: Option<String>,
    #[serde(default)]
    pub wattetheria_snapshot_export_url: Option<String>,
    #[serde(default)]
    pub wattetheria_events_export_url: Option<String>,
    #[serde(default)]
    pub wattswarm_ui_base_url: Option<String>,
    #[serde(default)]
    pub wattswarm_sync_grpc_endpoint: Option<String>,
    pub region: Option<String>,
    #[serde(alias = "expected_signer_agent_id")]
    pub expected_signer_agent_did: Option<String>,
    #[serde(default)]
    pub expected_wattswarm_node_id: Option<String>,
    #[serde(default)]
    pub source_status: Option<SourceStatus>,
    #[serde(default)]
    pub transport_capabilities: Option<PeerTransportCapabilities>,
    #[serde(default)]
    pub transport_contact_material: Option<TransportContactMaterial>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegisterNodeResponse {
    pub source_id: Uuid,
    pub name: String,
    pub export_url: String,
    pub source_status: SourceStatus,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SyncRequest {
    pub source_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncResult {
    pub source_id: Option<Uuid>,
    pub node_id: String,
    pub signer_agent_did: String,
    pub generated_at: i64,
    pub sync_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wattswarm_collect_error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListQuery {
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TopicQuery {
    pub limit: Option<usize>,
    pub topic_id: Option<String>,
    pub organization_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TopicMessageQuery {
    pub limit: Option<usize>,
    pub topic_id: Option<String>,
    pub organization_id: Option<String>,
    pub author_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DmMessageQuery {
    pub limit: Option<usize>,
    pub thread_id: Option<String>,
    pub counterpart_public_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterGatewayRequest {
    pub manifest: SignedGatewayManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterGatewayResponse {
    pub gateway_id: String,
    pub status: String,
    pub discovery_tier: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SelfRegisterGatewayRequest {
    pub registry_url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SelfRegisterGatewayResponse {
    pub registry_url: String,
    pub gateway_id: String,
    pub status: String,
    pub discovery_tier: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SelfRegisterGatewayBatchResponse {
    pub results: Vec<SelfRegisterGatewayResponse>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BootstrapRegistryEntry {
    pub registry_url: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredGatewayEntry {
    pub source_registry_url: String,
    pub gateway: GatewayRegistryEntry,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayRegistryQuery {
    pub region: Option<String>,
    pub tier: Option<String>,
    pub role: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReviewGatewayRequest {
    pub status: String,
    pub discovery_tier: Option<String>,
    pub reason: Option<String>,
    pub reviewed_by: Option<String>,
}
