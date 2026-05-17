use serde::{Deserialize, Serialize};
use serde_json::Value;
pub use wattetheria_gateway_contract::{
    ALL_DATA_KINDS, DataKind, EventScope, NodeEventPayload, ProvisionalExportPolicy,
    SignedNodeEvent, Visibility,
};

const DEFAULT_PROVENANCE_FIELDS: &[&str] = &[
    "identity_key",
    "source_kind",
    "source_cursor_or_seq",
    "ingest_path",
    "last_confirmed_at",
    "last_provisional_at",
];

const ALWAYS_PUBLIC_SLA: SlaTargets = SlaTargets {
    hot_path_target_ms: None,
    max_staleness_sec: 300,
};
const LIVE_MECHANISM_SLA: SlaTargets = SlaTargets {
    hot_path_target_ms: Some(350),
    max_staleness_sec: 15,
};
const WARM_PRODUCT_SLA: SlaTargets = SlaTargets {
    hot_path_target_ms: None,
    max_staleness_sec: 60,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayIngestMode {
    SnapshotPush,
    EventPush,
    GossipSubscribe,
    IrohDirectFetch,
    PullOnly,
    DerivedProjection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UiDeliveryMode {
    WsStream,
    RestPoll,
    RestSnapshotBootstrap,
    RestOnDemand,
    DebugOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HybridSubtype {
    Overlay,
    Merge,
    SemanticWrap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SourceStatus {
    #[default]
    Active,
    Suspended,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionPolicy {
    Forever,
    RollingNDays,
    OverwriteLatest,
    DropAfterConclusion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticDomain {
    Product,
    Mechanism,
    Social,
    Governance,
    Network,
    World,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataStage {
    Input,
    MechanismProcess,
    MechanismConclusion,
    ProductProjection,
    AggregatedSummary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LatencyClass {
    Hot,
    Warm,
    Cold,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsistencyClass {
    LocalCommit,
    EventualMechanism,
    ConfirmedMechanism,
    ProjectionAfterConfirmation,
    SnapshotLatest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceSystem {
    Wattetheria,
    Wattswarm,
    Hybrid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlaTargets {
    pub hot_path_target_ms: Option<u32>,
    pub max_staleness_sec: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataKindMetadata {
    pub kind: DataKind,
    pub domain: SemanticDomain,
    pub stage: DataStage,
    pub visibility: Visibility,
    pub signing_authority: &'static str,
    pub semantic_authority: &'static str,
    pub latency_class: LatencyClass,
    pub consistency_class: ConsistencyClass,
    pub storage_shape: &'static str,
    pub identity_fields: &'static [&'static str],
    pub payload_version: u16,
    pub provisional_export_policy: ProvisionalExportPolicy,
    pub retention_policy: RetentionPolicy,
    pub provenance_fields: &'static [&'static str],
    pub sla_targets: SlaTargets,
    pub primary_source: SourceSystem,
    pub fallback_source: Option<SourceSystem>,
    pub ingest_mode: GatewayIngestMode,
    pub ui_delivery_mode: UiDeliveryMode,
    pub hybrid_subtype: Option<HybridSubtype>,
    pub game_client_stable: bool,
    pub pull_only_fallback_data: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GatewayUiEvent {
    pub cursor: i64,
    pub event_id: String,
    pub node_id: String,
    pub data_kind: DataKind,
    pub event_kind: String,
    pub visibility: Visibility,
    pub provisional: bool,
    pub scope: EventScope,
    pub generated_at: i64,
    pub payload: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct UiStreamQuery {
    pub token: Option<String>,
    pub cursor: Option<i64>,
    pub limit: Option<usize>,
    pub data_kind: Option<DataKind>,
    pub node_id: Option<String>,
    pub topic_id: Option<String>,
    pub organization_id: Option<String>,
    pub task_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataKindPolicy {
    pub ingest_mode: GatewayIngestMode,
    pub ui_delivery_mode: UiDeliveryMode,
    pub hybrid_subtype: Option<HybridSubtype>,
    pub visibility: Visibility,
}

#[must_use]
pub fn data_kind_metadata(kind: DataKind) -> DataKindMetadata {
    match kind {
        DataKind::Presence => DataKindMetadata {
            kind,
            domain: SemanticDomain::Social,
            stage: DataStage::AggregatedSummary,
            visibility: Visibility::Public,
            signing_authority: "wattetheria node key",
            semantic_authority: "wattetheria social projection",
            latency_class: LatencyClass::Warm,
            consistency_class: ConsistencyClass::SnapshotLatest,
            storage_shape: "node_public_state",
            identity_fields: &["node_id", "public_id", "id"],
            payload_version: 1,
            provisional_export_policy: ProvisionalExportPolicy::NeverBeforeConfirmation,
            retention_policy: RetentionPolicy::OverwriteLatest,
            provenance_fields: DEFAULT_PROVENANCE_FIELDS,
            sla_targets: WARM_PRODUCT_SLA,
            primary_source: SourceSystem::Hybrid,
            fallback_source: Some(SourceSystem::Wattetheria),
            ingest_mode: GatewayIngestMode::DerivedProjection,
            ui_delivery_mode: UiDeliveryMode::RestPoll,
            hybrid_subtype: Some(HybridSubtype::Overlay),
            game_client_stable: true,
            pull_only_fallback_data: false,
        },
        DataKind::Identity | DataKind::OperatorProfile | DataKind::OrganizationSummary => {
            DataKindMetadata {
                kind,
                domain: SemanticDomain::Product,
                stage: DataStage::ProductProjection,
                visibility: Visibility::Public,
                signing_authority: "wattetheria node key",
                semantic_authority: "wattetheria product rules",
                latency_class: LatencyClass::Warm,
                consistency_class: ConsistencyClass::LocalCommit,
                storage_shape: "identity_projection",
                identity_fields: match kind {
                    DataKind::OrganizationSummary => &["organization_id", "id"],
                    _ => &["agent_did", "public_id", "id"],
                },
                payload_version: 1,
                provisional_export_policy: ProvisionalExportPolicy::NeverBeforeConfirmation,
                retention_policy: RetentionPolicy::OverwriteLatest,
                provenance_fields: DEFAULT_PROVENANCE_FIELDS,
                sla_targets: WARM_PRODUCT_SLA,
                primary_source: SourceSystem::Wattetheria,
                fallback_source: None,
                ingest_mode: GatewayIngestMode::SnapshotPush,
                ui_delivery_mode: UiDeliveryMode::RestSnapshotBootstrap,
                hybrid_subtype: None,
                game_client_stable: true,
                pull_only_fallback_data: false,
            }
        }
        DataKind::MissionLifecycle => DataKindMetadata {
            kind,
            domain: SemanticDomain::Product,
            stage: DataStage::ProductProjection,
            visibility: Visibility::Public,
            signing_authority: "wattetheria node key",
            semantic_authority: "wattetheria mission board",
            latency_class: LatencyClass::Warm,
            consistency_class: ConsistencyClass::ProjectionAfterConfirmation,
            storage_shape: "task_conclusion_projection",
            identity_fields: &["mission_id", "task_id", "id"],
            payload_version: 1,
            provisional_export_policy: ProvisionalExportPolicy::NeverBeforeConfirmation,
            retention_policy: RetentionPolicy::Forever,
            provenance_fields: DEFAULT_PROVENANCE_FIELDS,
            sla_targets: WARM_PRODUCT_SLA,
            primary_source: SourceSystem::Wattetheria,
            fallback_source: None,
            ingest_mode: GatewayIngestMode::SnapshotPush,
            ui_delivery_mode: UiDeliveryMode::RestSnapshotBootstrap,
            hybrid_subtype: Some(HybridSubtype::SemanticWrap),
            game_client_stable: true,
            pull_only_fallback_data: false,
        },
        DataKind::TaskSummary => DataKindMetadata {
            kind,
            domain: SemanticDomain::Product,
            stage: DataStage::ProductProjection,
            visibility: Visibility::Public,
            signing_authority: "wattetheria node key",
            semantic_authority: "wattetheria mission/task projection",
            latency_class: LatencyClass::Warm,
            consistency_class: ConsistencyClass::ProjectionAfterConfirmation,
            storage_shape: "task_conclusion_projection",
            identity_fields: &["task_id", "mission_id", "id"],
            payload_version: 1,
            provisional_export_policy: ProvisionalExportPolicy::NeverBeforeConfirmation,
            retention_policy: RetentionPolicy::OverwriteLatest,
            provenance_fields: DEFAULT_PROVENANCE_FIELDS,
            sla_targets: WARM_PRODUCT_SLA,
            primary_source: SourceSystem::Wattetheria,
            fallback_source: None,
            ingest_mode: GatewayIngestMode::SnapshotPush,
            ui_delivery_mode: UiDeliveryMode::RestSnapshotBootstrap,
            hybrid_subtype: Some(HybridSubtype::SemanticWrap),
            game_client_stable: true,
            pull_only_fallback_data: false,
        },
        DataKind::TaskVoteSignal | DataKind::TaskRoundUpdate => DataKindMetadata {
            kind,
            domain: SemanticDomain::Mechanism,
            stage: if matches!(kind, DataKind::TaskVoteSignal) {
                DataStage::Input
            } else {
                DataStage::MechanismProcess
            },
            visibility: Visibility::Public,
            signing_authority: "agent or node key on each signed event",
            semantic_authority: "wattswarm decision process",
            latency_class: LatencyClass::Hot,
            consistency_class: ConsistencyClass::EventualMechanism,
            storage_shape: "task_process_projection",
            identity_fields: &["task_id", "vote_id", "round_id", "id"],
            payload_version: 1,
            provisional_export_policy: if matches!(kind, DataKind::TaskVoteSignal) {
                ProvisionalExportPolicy::EphemeralOnly
            } else {
                ProvisionalExportPolicy::ProvisionalWithDowngrade
            },
            retention_policy: RetentionPolicy::RollingNDays,
            provenance_fields: DEFAULT_PROVENANCE_FIELDS,
            sla_targets: LIVE_MECHANISM_SLA,
            primary_source: SourceSystem::Wattswarm,
            fallback_source: Some(SourceSystem::Wattetheria),
            ingest_mode: GatewayIngestMode::EventPush,
            ui_delivery_mode: UiDeliveryMode::WsStream,
            hybrid_subtype: None,
            game_client_stable: true,
            pull_only_fallback_data: false,
        },
        DataKind::TaskDecisionFinalized => DataKindMetadata {
            kind,
            domain: SemanticDomain::Mechanism,
            stage: DataStage::MechanismConclusion,
            visibility: Visibility::Public,
            signing_authority: "mechanism finality proof or node-exported signed conclusion",
            semantic_authority: "wattswarm mechanism consensus",
            latency_class: LatencyClass::Hot,
            consistency_class: ConsistencyClass::ConfirmedMechanism,
            storage_shape: "task_conclusion_projection",
            identity_fields: &["task_id", "decision_id", "id"],
            payload_version: 1,
            provisional_export_policy: ProvisionalExportPolicy::NeverBeforeConfirmation,
            retention_policy: RetentionPolicy::Forever,
            provenance_fields: DEFAULT_PROVENANCE_FIELDS,
            sla_targets: LIVE_MECHANISM_SLA,
            primary_source: SourceSystem::Wattswarm,
            fallback_source: Some(SourceSystem::Wattetheria),
            ingest_mode: GatewayIngestMode::EventPush,
            ui_delivery_mode: UiDeliveryMode::WsStream,
            hybrid_subtype: None,
            game_client_stable: true,
            pull_only_fallback_data: false,
        },
        DataKind::GovernanceProposal | DataKind::GovernanceVote | DataKind::GovernanceDecision => {
            DataKindMetadata {
                kind,
                domain: SemanticDomain::Governance,
                stage: match kind {
                    DataKind::GovernanceProposal => DataStage::Input,
                    DataKind::GovernanceVote => DataStage::MechanismProcess,
                    _ => DataStage::MechanismConclusion,
                },
                visibility: Visibility::Public,
                signing_authority: "wattetheria node key",
                semantic_authority: "wattetheria governance engine",
                latency_class: if matches!(kind, DataKind::GovernanceDecision) {
                    LatencyClass::Warm
                } else {
                    LatencyClass::Hot
                },
                consistency_class: if matches!(kind, DataKind::GovernanceDecision) {
                    ConsistencyClass::ConfirmedMechanism
                } else {
                    ConsistencyClass::LocalCommit
                },
                storage_shape: "task_conclusion_projection",
                identity_fields: &["proposal_id", "vote_id", "id"],
                payload_version: 1,
                provisional_export_policy: if matches!(kind, DataKind::GovernanceVote) {
                    ProvisionalExportPolicy::ProvisionalWithDowngrade
                } else {
                    ProvisionalExportPolicy::NeverBeforeConfirmation
                },
                retention_policy: RetentionPolicy::Forever,
                provenance_fields: DEFAULT_PROVENANCE_FIELDS,
                sla_targets: WARM_PRODUCT_SLA,
                primary_source: SourceSystem::Wattetheria,
                fallback_source: None,
                ingest_mode: if matches!(kind, DataKind::GovernanceDecision) {
                    GatewayIngestMode::SnapshotPush
                } else {
                    GatewayIngestMode::EventPush
                },
                ui_delivery_mode: if matches!(kind, DataKind::GovernanceDecision) {
                    UiDeliveryMode::RestSnapshotBootstrap
                } else {
                    UiDeliveryMode::WsStream
                },
                hybrid_subtype: None,
                game_client_stable: true,
                pull_only_fallback_data: false,
            }
        }
        DataKind::OracleFeedUpdate => DataKindMetadata {
            kind,
            domain: SemanticDomain::Mechanism,
            stage: DataStage::MechanismConclusion,
            visibility: Visibility::Public,
            signing_authority: "oracle signer",
            semantic_authority: "oracle feed attestor",
            latency_class: LatencyClass::Warm,
            consistency_class: ConsistencyClass::ConfirmedMechanism,
            storage_shape: "network_projection",
            identity_fields: &["feed_id", "id"],
            payload_version: 1,
            provisional_export_policy: ProvisionalExportPolicy::NeverBeforeConfirmation,
            retention_policy: RetentionPolicy::RollingNDays,
            provenance_fields: DEFAULT_PROVENANCE_FIELDS,
            sla_targets: WARM_PRODUCT_SLA,
            primary_source: SourceSystem::Wattswarm,
            fallback_source: Some(SourceSystem::Wattetheria),
            ingest_mode: GatewayIngestMode::PullOnly,
            ui_delivery_mode: UiDeliveryMode::RestPoll,
            hybrid_subtype: None,
            game_client_stable: true,
            pull_only_fallback_data: false,
        },
        DataKind::SettlementEvent | DataKind::ReputationUpdate => DataKindMetadata {
            kind,
            domain: SemanticDomain::Mechanism,
            stage: DataStage::MechanismConclusion,
            visibility: Visibility::Public,
            signing_authority: "mechanism conclusion signer",
            semantic_authority: "wattswarm settlement and reputation engine",
            latency_class: LatencyClass::Warm,
            consistency_class: ConsistencyClass::ConfirmedMechanism,
            storage_shape: "ranking_projection",
            identity_fields: &["settlement_id", "agent_did", "id"],
            payload_version: 1,
            provisional_export_policy: ProvisionalExportPolicy::NeverBeforeConfirmation,
            retention_policy: RetentionPolicy::RollingNDays,
            provenance_fields: DEFAULT_PROVENANCE_FIELDS,
            sla_targets: WARM_PRODUCT_SLA,
            primary_source: SourceSystem::Wattswarm,
            fallback_source: Some(SourceSystem::Wattetheria),
            ingest_mode: GatewayIngestMode::PullOnly,
            ui_delivery_mode: UiDeliveryMode::RestPoll,
            hybrid_subtype: None,
            game_client_stable: true,
            pull_only_fallback_data: false,
        },
        DataKind::RankingProjection => DataKindMetadata {
            kind,
            domain: SemanticDomain::Product,
            stage: DataStage::AggregatedSummary,
            visibility: Visibility::Public,
            signing_authority: "wattetheria node key",
            semantic_authority: "wattetheria ranking projection",
            latency_class: LatencyClass::Warm,
            consistency_class: ConsistencyClass::ProjectionAfterConfirmation,
            storage_shape: "ranking_projection",
            identity_fields: &["agent_did", "public_id", "id"],
            payload_version: 1,
            provisional_export_policy: ProvisionalExportPolicy::NeverBeforeConfirmation,
            retention_policy: RetentionPolicy::OverwriteLatest,
            provenance_fields: DEFAULT_PROVENANCE_FIELDS,
            sla_targets: WARM_PRODUCT_SLA,
            primary_source: SourceSystem::Wattetheria,
            fallback_source: Some(SourceSystem::Wattswarm),
            ingest_mode: GatewayIngestMode::SnapshotPush,
            ui_delivery_mode: UiDeliveryMode::RestSnapshotBootstrap,
            hybrid_subtype: None,
            game_client_stable: true,
            pull_only_fallback_data: false,
        },
        DataKind::HiveMetadata => DataKindMetadata {
            kind,
            domain: SemanticDomain::Social,
            stage: DataStage::ProductProjection,
            visibility: Visibility::Public,
            signing_authority: "wattetheria node key",
            semantic_authority: "wattetheria wraps wattswarm topic facts",
            latency_class: LatencyClass::Warm,
            consistency_class: ConsistencyClass::ProjectionAfterConfirmation,
            storage_shape: "topic_activity_projection",
            identity_fields: &["topic_id", "id"],
            payload_version: 1,
            provisional_export_policy: ProvisionalExportPolicy::NeverBeforeConfirmation,
            retention_policy: RetentionPolicy::OverwriteLatest,
            provenance_fields: DEFAULT_PROVENANCE_FIELDS,
            sla_targets: WARM_PRODUCT_SLA,
            primary_source: SourceSystem::Hybrid,
            fallback_source: Some(SourceSystem::Wattetheria),
            ingest_mode: GatewayIngestMode::DerivedProjection,
            ui_delivery_mode: UiDeliveryMode::RestSnapshotBootstrap,
            hybrid_subtype: Some(HybridSubtype::SemanticWrap),
            game_client_stable: true,
            pull_only_fallback_data: false,
        },
        DataKind::HiveMessagePosted => DataKindMetadata {
            kind,
            domain: SemanticDomain::Social,
            stage: DataStage::Input,
            visibility: Visibility::Public,
            signing_authority: "agent envelope signer",
            semantic_authority: "wattswarm topic mechanism",
            latency_class: LatencyClass::Hot,
            consistency_class: ConsistencyClass::EventualMechanism,
            storage_shape: "topic_activity_projection",
            identity_fields: &["message_id", "topic_id", "id"],
            payload_version: 1,
            provisional_export_policy: ProvisionalExportPolicy::EphemeralOnly,
            retention_policy: RetentionPolicy::DropAfterConclusion,
            provenance_fields: DEFAULT_PROVENANCE_FIELDS,
            sla_targets: LIVE_MECHANISM_SLA,
            primary_source: SourceSystem::Wattswarm,
            fallback_source: Some(SourceSystem::Wattetheria),
            ingest_mode: GatewayIngestMode::EventPush,
            ui_delivery_mode: UiDeliveryMode::WsStream,
            hybrid_subtype: None,
            game_client_stable: true,
            pull_only_fallback_data: false,
        },
        DataKind::HiveActivity => DataKindMetadata {
            kind,
            domain: SemanticDomain::Social,
            stage: DataStage::MechanismConclusion,
            visibility: Visibility::Public,
            signing_authority: "wattswarm message projection signer",
            semantic_authority: "wattswarm topic history",
            latency_class: LatencyClass::Hot,
            consistency_class: ConsistencyClass::ConfirmedMechanism,
            storage_shape: "topic_activity_projection",
            identity_fields: &["message_id", "topic_id", "id"],
            payload_version: 1,
            provisional_export_policy: ProvisionalExportPolicy::NeverBeforeConfirmation,
            retention_policy: RetentionPolicy::RollingNDays,
            provenance_fields: DEFAULT_PROVENANCE_FIELDS,
            sla_targets: LIVE_MECHANISM_SLA,
            primary_source: SourceSystem::Wattswarm,
            fallback_source: Some(SourceSystem::Wattetheria),
            ingest_mode: GatewayIngestMode::PullOnly,
            ui_delivery_mode: UiDeliveryMode::WsStream,
            hybrid_subtype: None,
            game_client_stable: true,
            pull_only_fallback_data: false,
        },
        DataKind::FriendRelationship | DataKind::FriendRequestPending | DataKind::PublicBlock => {
            DataKindMetadata {
                kind,
                domain: SemanticDomain::Social,
                stage: DataStage::AggregatedSummary,
                visibility: Visibility::Public,
                signing_authority: "wattetheria node key",
                semantic_authority: "relationship state machine",
                latency_class: LatencyClass::Warm,
                consistency_class: ConsistencyClass::LocalCommit,
                storage_shape: "node_public_state",
                identity_fields: &["counterpart_public_id", "public_id", "id"],
                payload_version: 1,
                provisional_export_policy: ProvisionalExportPolicy::NeverBeforeConfirmation,
                retention_policy: RetentionPolicy::OverwriteLatest,
                provenance_fields: DEFAULT_PROVENANCE_FIELDS,
                sla_targets: WARM_PRODUCT_SLA,
                primary_source: SourceSystem::Hybrid,
                fallback_source: Some(SourceSystem::Wattetheria),
                ingest_mode: GatewayIngestMode::SnapshotPush,
                ui_delivery_mode: UiDeliveryMode::RestPoll,
                hybrid_subtype: Some(HybridSubtype::Overlay),
                game_client_stable: true,
                pull_only_fallback_data: false,
            }
        }
        DataKind::SocialThread | DataKind::DmSummary => DataKindMetadata {
            kind,
            domain: SemanticDomain::Social,
            stage: DataStage::AggregatedSummary,
            visibility: Visibility::Protected,
            signing_authority: "wattetheria node key",
            semantic_authority: "conversation projection",
            latency_class: LatencyClass::Warm,
            consistency_class: ConsistencyClass::SnapshotLatest,
            storage_shape: "node_public_state",
            identity_fields: &["thread_id", "id"],
            payload_version: 1,
            provisional_export_policy: ProvisionalExportPolicy::NeverBeforeConfirmation,
            retention_policy: RetentionPolicy::OverwriteLatest,
            provenance_fields: DEFAULT_PROVENANCE_FIELDS,
            sla_targets: WARM_PRODUCT_SLA,
            primary_source: SourceSystem::Hybrid,
            fallback_source: Some(SourceSystem::Wattetheria),
            ingest_mode: GatewayIngestMode::SnapshotPush,
            ui_delivery_mode: UiDeliveryMode::RestOnDemand,
            hybrid_subtype: Some(HybridSubtype::Overlay),
            game_client_stable: true,
            pull_only_fallback_data: false,
        },
        DataKind::DmMessage => DataKindMetadata {
            kind,
            domain: SemanticDomain::Social,
            stage: DataStage::AggregatedSummary,
            visibility: Visibility::Protected,
            signing_authority: "wattetheria node key",
            semantic_authority: "conversation projection",
            latency_class: LatencyClass::Warm,
            consistency_class: ConsistencyClass::SnapshotLatest,
            storage_shape: "node_public_state",
            identity_fields: &["message_id", "id"],
            payload_version: 1,
            provisional_export_policy: ProvisionalExportPolicy::NeverBeforeConfirmation,
            retention_policy: RetentionPolicy::RollingNDays,
            provenance_fields: DEFAULT_PROVENANCE_FIELDS,
            sla_targets: WARM_PRODUCT_SLA,
            primary_source: SourceSystem::Hybrid,
            fallback_source: Some(SourceSystem::Wattetheria),
            ingest_mode: GatewayIngestMode::SnapshotPush,
            ui_delivery_mode: UiDeliveryMode::RestOnDemand,
            hybrid_subtype: Some(HybridSubtype::Overlay),
            game_client_stable: true,
            pull_only_fallback_data: false,
        },
        DataKind::NetworkProjection => DataKindMetadata {
            kind,
            domain: SemanticDomain::Network,
            stage: DataStage::AggregatedSummary,
            visibility: Visibility::Public,
            signing_authority: "wattswarm network snapshot signer",
            semantic_authority: "shared-fact network view",
            latency_class: LatencyClass::Warm,
            consistency_class: ConsistencyClass::ProjectionAfterConfirmation,
            storage_shape: "network_projection",
            identity_fields: &["node_id", "network_id", "id"],
            payload_version: 1,
            provisional_export_policy: ProvisionalExportPolicy::NeverBeforeConfirmation,
            retention_policy: RetentionPolicy::OverwriteLatest,
            provenance_fields: DEFAULT_PROVENANCE_FIELDS,
            sla_targets: WARM_PRODUCT_SLA,
            primary_source: SourceSystem::Wattswarm,
            fallback_source: Some(SourceSystem::Wattetheria),
            ingest_mode: GatewayIngestMode::PullOnly,
            ui_delivery_mode: UiDeliveryMode::RestPoll,
            hybrid_subtype: None,
            game_client_stable: true,
            pull_only_fallback_data: false,
        },
        DataKind::TravelState => DataKindMetadata {
            kind,
            domain: SemanticDomain::World,
            stage: DataStage::ProductProjection,
            visibility: Visibility::Public,
            signing_authority: "wattetheria node key",
            semantic_authority: "travel state registry",
            latency_class: LatencyClass::Warm,
            consistency_class: ConsistencyClass::LocalCommit,
            storage_shape: "node_public_state",
            identity_fields: &["route_id", "public_id", "id"],
            payload_version: 1,
            provisional_export_policy: ProvisionalExportPolicy::NeverBeforeConfirmation,
            retention_policy: RetentionPolicy::OverwriteLatest,
            provenance_fields: DEFAULT_PROVENANCE_FIELDS,
            sla_targets: WARM_PRODUCT_SLA,
            primary_source: SourceSystem::Wattetheria,
            fallback_source: None,
            ingest_mode: GatewayIngestMode::SnapshotPush,
            ui_delivery_mode: UiDeliveryMode::RestSnapshotBootstrap,
            hybrid_subtype: None,
            game_client_stable: true,
            pull_only_fallback_data: false,
        },
        DataKind::GalaxyEvent | DataKind::WorldEvent => DataKindMetadata {
            kind,
            domain: SemanticDomain::World,
            stage: DataStage::ProductProjection,
            visibility: Visibility::Public,
            signing_authority: "wattetheria node key",
            semantic_authority: "world rule engine",
            latency_class: if matches!(kind, DataKind::GalaxyEvent) {
                LatencyClass::Hot
            } else {
                LatencyClass::Warm
            },
            consistency_class: ConsistencyClass::LocalCommit,
            storage_shape: "task_conclusion_projection",
            identity_fields: &["event_id", "id"],
            payload_version: 1,
            provisional_export_policy: ProvisionalExportPolicy::NeverBeforeConfirmation,
            retention_policy: if matches!(kind, DataKind::GalaxyEvent) {
                RetentionPolicy::RollingNDays
            } else {
                RetentionPolicy::Forever
            },
            provenance_fields: DEFAULT_PROVENANCE_FIELDS,
            sla_targets: if matches!(kind, DataKind::GalaxyEvent) {
                LIVE_MECHANISM_SLA
            } else {
                ALWAYS_PUBLIC_SLA
            },
            primary_source: SourceSystem::Wattetheria,
            fallback_source: None,
            ingest_mode: if matches!(kind, DataKind::GalaxyEvent) {
                GatewayIngestMode::EventPush
            } else {
                GatewayIngestMode::SnapshotPush
            },
            ui_delivery_mode: if matches!(kind, DataKind::GalaxyEvent) {
                UiDeliveryMode::WsStream
            } else {
                UiDeliveryMode::RestSnapshotBootstrap
            },
            hybrid_subtype: None,
            game_client_stable: true,
            pull_only_fallback_data: false,
        },
    }
}

#[must_use]
pub fn data_kind_policy(kind: DataKind) -> DataKindPolicy {
    let metadata = data_kind_metadata(kind);
    DataKindPolicy {
        ingest_mode: metadata.ingest_mode,
        ui_delivery_mode: metadata.ui_delivery_mode,
        hybrid_subtype: metadata.hybrid_subtype,
        visibility: metadata.visibility,
    }
}

#[must_use]
pub fn allows_public_stream(kind: DataKind) -> bool {
    let metadata = data_kind_metadata(kind);
    metadata.visibility == Visibility::Public
        && metadata.ui_delivery_mode == UiDeliveryMode::WsStream
}

#[must_use]
pub fn visibility_for_kind(kind: DataKind) -> Visibility {
    data_kind_metadata(kind).visibility
}

#[must_use]
pub fn projection_identity_key(
    kind: DataKind,
    value: &Value,
    fallback_source_node_id: &str,
) -> String {
    data_kind_metadata(kind)
        .identity_fields
        .iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .filter(|candidate| !candidate.trim().is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| fallback_source_node_id.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeSet;

    #[test]
    fn data_kind_catalog_has_unique_rows_for_every_known_kind() {
        let rows = ALL_DATA_KINDS.iter().map(|kind| data_kind_metadata(*kind));
        let unique = rows
            .map(|row| serde_json::to_string(&row.kind).unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(unique.len(), ALL_DATA_KINDS.len());
    }

    #[test]
    fn dm_kinds_are_protected() {
        assert_eq!(
            visibility_for_kind(DataKind::DmSummary),
            Visibility::Protected
        );
        assert_eq!(
            visibility_for_kind(DataKind::DmMessage),
            Visibility::Protected
        );
        assert!(!allows_public_stream(DataKind::DmSummary));
    }

    #[test]
    fn task_round_updates_are_live_public_stream_data() {
        let policy = data_kind_policy(DataKind::TaskRoundUpdate);
        assert_eq!(policy.ingest_mode, GatewayIngestMode::EventPush);
        assert_eq!(policy.ui_delivery_mode, UiDeliveryMode::WsStream);
        assert_eq!(policy.visibility, Visibility::Public);
        assert_eq!(
            data_kind_metadata(DataKind::TaskRoundUpdate).latency_class,
            LatencyClass::Hot
        );
    }

    #[test]
    fn social_graph_kinds_are_present_in_the_catalog() {
        for kind in [
            DataKind::FriendRelationship,
            DataKind::FriendRequestPending,
            DataKind::PublicBlock,
            DataKind::SocialThread,
            DataKind::DmSummary,
            DataKind::DmMessage,
        ] {
            assert!(ALL_DATA_KINDS.contains(&kind));
        }
    }

    #[test]
    fn projection_identity_key_prefers_known_fields() {
        let payload = json!({"thread_id": "thread-1", "id": "fallback"});
        assert_eq!(
            projection_identity_key(DataKind::SocialThread, &payload, "node-a"),
            "thread-1"
        );
    }

    #[test]
    fn future_game_client_stability_is_marked_for_world_classes() {
        assert!(data_kind_metadata(DataKind::WorldEvent).game_client_stable);
        assert!(data_kind_metadata(DataKind::GalaxyEvent).game_client_stable);
    }

    #[test]
    fn hybrid_primary_rows_always_define_a_hybrid_subtype() {
        for kind in ALL_DATA_KINDS {
            let metadata = data_kind_metadata(kind);
            if metadata.primary_source == SourceSystem::Hybrid {
                assert!(
                    metadata.hybrid_subtype.is_some(),
                    "{kind:?} declared Hybrid primary without hybrid_subtype"
                );
            }
        }
    }
}
