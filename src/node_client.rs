use crate::models::SignedPublicClientSnapshot;
use anyhow::{Context, Result};
use reqwest::Client;
use serde::de::DeserializeOwned;
use std::path::Path;
use std::time::Duration;
use wattswarm_network_substrate::PeerId;
use wattswarm_network_transport_core::{
    DirectDataFetchRequest, DirectDataObjectKind, TransportContactMaterial,
};
use wattswarm_network_transport_iroh::fetch_direct_data;

const PUBLIC_CLIENT_SNAPSHOT_SCOPE: &str = "public-client-snapshot";

#[derive(Debug, Clone)]
pub struct NodeClient {
    client: Client,
}

impl NodeClient {
    pub fn new(timeout_secs: u64) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .context("build reqwest client")?;
        Ok(Self { client })
    }

    pub async fn fetch_signed_snapshot(
        &self,
        export_url: &str,
    ) -> Result<SignedPublicClientSnapshot> {
        self.fetch_json(export_url, None).await
    }

    pub async fn fetch_signed_snapshot_via_iroh(
        &self,
        state_dir: &Path,
        local_peer_id: &PeerId,
        remote_contact: &TransportContactMaterial,
        snapshot_id: &str,
    ) -> Result<SignedPublicClientSnapshot> {
        let response = fetch_direct_data(
            state_dir,
            local_peer_id,
            remote_contact,
            &DirectDataFetchRequest {
                object_kind: DirectDataObjectKind::SnapshotJson,
                object_id: snapshot_id.to_owned(),
                scope: Some(PUBLIC_CLIENT_SNAPSHOT_SCOPE.to_owned()),
                source_uri: None,
                expected_digest: None,
                expected_size: None,
            },
        )?;
        serde_json::from_slice(&response.bytes).context("parse signed snapshot from iroh fetch")
    }

    pub async fn fetch_json<T>(&self, url: &str, query: Option<&[(&str, String)]>) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let mut request = self.client.get(url);
        if let Some(query) = query {
            request = request.query(query);
        }
        request
            .send()
            .await
            .with_context(|| format!("request {url}"))?
            .error_for_status()
            .with_context(|| format!("request {url} returned error status"))?
            .json::<T>()
            .await
            .with_context(|| format!("parse response from {url}"))
    }
}
