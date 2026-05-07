use crate::contracts::{
    DataKind, GatewayIngestMode, HybridSubtype, SourceSystem, UiDeliveryMode, data_kind_metadata,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourcePolicy {
    pub primary: SourceSystem,
    pub fallback: Option<SourceSystem>,
    pub ingest_mode: GatewayIngestMode,
    pub ui_delivery_mode: UiDeliveryMode,
    pub hybrid_subtype: Option<HybridSubtype>,
    pub pull_only_fallback_data: bool,
}

#[must_use]
pub fn source_policy(kind: DataKind) -> SourcePolicy {
    let metadata = data_kind_metadata(kind);
    SourcePolicy {
        primary: metadata.primary_source,
        fallback: metadata.fallback_source,
        ingest_mode: metadata.ingest_mode,
        ui_delivery_mode: metadata.ui_delivery_mode,
        hybrid_subtype: metadata.hybrid_subtype,
        pull_only_fallback_data: metadata.pull_only_fallback_data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_summary_defaults_to_wattswarm_primary() {
        let policy = source_policy(DataKind::TaskSummary);
        assert_eq!(policy.primary, SourceSystem::Wattswarm);
        assert_eq!(policy.ingest_mode, GatewayIngestMode::SnapshotPush);
    }

    #[test]
    fn hive_metadata_is_hybrid_semantic_wrap() {
        let policy = source_policy(DataKind::HiveMetadata);
        assert_eq!(policy.primary, SourceSystem::Hybrid);
        assert_eq!(policy.hybrid_subtype, Some(HybridSubtype::SemanticWrap));
    }

    #[test]
    fn projection_data_does_not_use_hybrid_as_a_catch_all() {
        let policy = source_policy(DataKind::RankingProjection);
        assert_eq!(policy.primary, SourceSystem::Wattetheria);
        assert_eq!(policy.hybrid_subtype, None);
    }
}
