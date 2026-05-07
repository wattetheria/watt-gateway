pub mod collectors;
pub mod config;
pub mod contracts;
pub mod db;
pub mod gateway_identity;
pub mod http;
pub mod models;
pub mod node_client;
pub mod public_api;
pub mod read_models;
pub mod registry_client;
pub mod source_policy;
pub mod state;
pub mod streaming;
pub mod verify;

pub mod gateway_network {
    pub use wattetheria_gateway_p2p::*;

    use crate::models::SignedPublicClientSnapshot;
    use anyhow::Result;
    use std::path::{Path, PathBuf};

    pub fn persist_snapshot_artifact(
        state_dir: &Path,
        snapshot: &SignedPublicClientSnapshot,
    ) -> Result<PathBuf> {
        wattetheria_gateway_p2p::persist_json_snapshot_artifact(
            state_dir,
            &snapshot.payload.node_id,
            snapshot,
        )
    }
}
