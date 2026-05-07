use crate::models::{GatewayRegistryEntry, RegisterGatewayRequest, RegisterGatewayResponse};
use anyhow::{Context, Result};
use reqwest::Client;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct RegistryClient {
    client: Client,
}

impl RegistryClient {
    pub fn new(timeout_secs: u64) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .context("build reqwest client")?;
        Ok(Self { client })
    }

    pub async fn fetch_public_gateways(
        &self,
        registry_url: &str,
    ) -> Result<Vec<GatewayRegistryEntry>> {
        self.client
            .get(normalized_registry_list_url(registry_url))
            .send()
            .await
            .context("request public gateway registry list")?
            .error_for_status()
            .context("public gateway registry returned error status")?
            .json::<Vec<GatewayRegistryEntry>>()
            .await
            .context("parse public gateway registry list")
    }

    pub async fn register_manifest(
        &self,
        registry_url: &str,
        request: &RegisterGatewayRequest,
    ) -> Result<RegisterGatewayResponse> {
        self.client
            .post(normalized_registry_register_url(registry_url))
            .json(request)
            .send()
            .await
            .context("post signed gateway manifest to registry")?
            .error_for_status()
            .context("gateway registry register returned error status")?
            .json::<RegisterGatewayResponse>()
            .await
            .context("parse gateway registry register response")
    }
}

pub fn normalized_registry_list_url(registry_url: &str) -> String {
    let trimmed = registry_url.trim_end_matches('/');
    if trimmed.ends_with("/api/registry/gateways/register") {
        trimmed
            .trim_end_matches("/register")
            .trim_end_matches('/')
            .to_string()
    } else if trimmed.ends_with("/api/registry/gateways") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/api/registry/gateways")
    }
}

pub fn normalized_registry_register_url(registry_url: &str) -> String {
    let trimmed = registry_url.trim_end_matches('/');
    if trimmed.ends_with("/api/registry/gateways/register") {
        trimmed.to_string()
    } else if trimmed.ends_with("/api/registry/gateways") {
        format!("{trimmed}/register")
    } else {
        format!("{trimmed}/api/registry/gateways/register")
    }
}

#[cfg(test)]
mod tests {
    use super::{normalized_registry_list_url, normalized_registry_register_url};

    #[test]
    fn normalizes_base_registry_urls() {
        assert_eq!(
            normalized_registry_list_url("https://registry.example"),
            "https://registry.example/api/registry/gateways"
        );
        assert_eq!(
            normalized_registry_register_url("https://registry.example"),
            "https://registry.example/api/registry/gateways/register"
        );
    }

    #[test]
    fn normalizes_list_registry_urls() {
        assert_eq!(
            normalized_registry_list_url("https://registry.example/api/registry/gateways"),
            "https://registry.example/api/registry/gateways"
        );
        assert_eq!(
            normalized_registry_register_url("https://registry.example/api/registry/gateways"),
            "https://registry.example/api/registry/gateways/register"
        );
    }

    #[test]
    fn normalizes_register_registry_urls() {
        assert_eq!(
            normalized_registry_list_url("https://registry.example/api/registry/gateways/register"),
            "https://registry.example/api/registry/gateways"
        );
        assert_eq!(
            normalized_registry_register_url(
                "https://registry.example/api/registry/gateways/register"
            ),
            "https://registry.example/api/registry/gateways/register"
        );
    }
}
