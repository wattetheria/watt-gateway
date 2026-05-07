use crate::models::SignedPublicClientSnapshot;
use anyhow::{Context, Result};
use reqwest::Client;
use serde::de::DeserializeOwned;
use std::time::Duration;

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
