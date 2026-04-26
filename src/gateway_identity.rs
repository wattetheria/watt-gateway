use crate::models::{GatewayManifest, SignedGatewayManifest};
use crate::verify::canonical_bytes;
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};

#[derive(Debug, Clone)]
pub struct GatewayIdentity {
    gateway_id: String,
    display_name: String,
    base_url: String,
    region: Option<String>,
    operator_did: Option<String>,
    roles: Vec<String>,
    supported_endpoints: Vec<String>,
    federation_peers: Vec<String>,
    allows_public_ingest: bool,
    signing_key: SigningKey,
}

#[derive(Debug, Clone)]
pub struct GatewayIdentityConfig {
    pub gateway_id: Option<String>,
    pub display_name: Option<String>,
    pub base_url: Option<String>,
    pub region: Option<String>,
    pub operator_did: Option<String>,
    pub roles: Vec<String>,
    pub supported_endpoints: Vec<String>,
    pub federation_peers: Vec<String>,
    pub allows_public_ingest: bool,
    pub signing_key_b64: Option<String>,
}

impl GatewayIdentity {
    pub fn from_config(config: GatewayIdentityConfig) -> Result<Option<Self>> {
        let any_present = config.gateway_id.is_some()
            || config.display_name.is_some()
            || config.base_url.is_some()
            || config.signing_key_b64.is_some()
            || config.region.is_some()
            || config.operator_did.is_some();
        if !any_present {
            return Ok(None);
        }

        let gateway_id = config
            .gateway_id
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("WATTETHERIA_GATEWAY_IDENTITY_ID is required"))?;
        let display_name = config
            .display_name
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!("WATTETHERIA_GATEWAY_IDENTITY_DISPLAY_NAME is required")
            })?;
        let base_url = config
            .base_url
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("WATTETHERIA_GATEWAY_IDENTITY_BASE_URL is required"))?;
        let signing_key_b64 = config
            .signing_key_b64
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!("WATTETHERIA_GATEWAY_IDENTITY_SIGNING_KEY is required")
            })?;

        let signing_key = decode_signing_key(&signing_key_b64)?;
        let roles = normalized_list(config.roles, &["ingest", "query", "federation"]);
        let supported_endpoints = normalized_list(
            config.supported_endpoints,
            &[
                "/api/network/status",
                "/api/peers",
                "/api/topics",
                "/api/topic-messages",
                "/api/tasks",
                "/api/organizations",
                "/api/leaderboard",
                "/api/registry/bootstrap",
                "/api/registry/discovery",
                "/api/registry/gateways",
                "/api/registry/self-manifest",
                "/api/registry/self-register",
            ],
        );

        Ok(Some(Self {
            gateway_id,
            display_name,
            base_url: base_url.trim_end_matches('/').to_string(),
            region: config.region,
            operator_did: config.operator_did,
            roles,
            supported_endpoints,
            federation_peers: config.federation_peers,
            allows_public_ingest: config.allows_public_ingest,
            signing_key,
        }))
    }

    pub fn signed_manifest(&self) -> Result<SignedGatewayManifest> {
        let payload = GatewayManifest {
            generated_at: chrono::Utc::now().timestamp(),
            gateway_id: self.gateway_id.clone(),
            display_name: self.display_name.clone(),
            base_url: self.base_url.clone(),
            public_key: STANDARD.encode(self.signing_key.verifying_key().as_bytes()),
            region: self.region.clone(),
            operator_did: self.operator_did.clone(),
            roles: self.roles.clone(),
            supported_endpoints: self.supported_endpoints.clone(),
            federation_peers: self.federation_peers.clone(),
            allows_public_ingest: self.allows_public_ingest,
        };
        let signature = STANDARD.encode(
            self.signing_key
                .sign(&canonical_bytes(&payload)?)
                .to_bytes(),
        );
        Ok(SignedGatewayManifest { payload, signature })
    }
}

fn decode_signing_key(signing_key_b64: &str) -> Result<SigningKey> {
    let bytes = STANDARD
        .decode(signing_key_b64)
        .context("decode gateway signing key base64")?;
    let bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("gateway signing key must decode to 32 bytes"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn normalized_list(values: Vec<String>, defaults: &[&str]) -> Vec<String> {
    let mut entries = values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if entries.is_empty() {
        entries = defaults.iter().map(|value| (*value).to_string()).collect();
    }
    entries.sort();
    entries.dedup();
    entries
}

#[cfg(test)]
mod tests {
    use super::{GatewayIdentity, GatewayIdentityConfig};
    use base64::Engine as _;

    #[test]
    fn gateway_identity_builds_signed_manifest() {
        let identity = GatewayIdentity::from_config(GatewayIdentityConfig {
            gateway_id: Some("gw-ap-1".to_string()),
            display_name: Some("AP Gateway".to_string()),
            base_url: Some("https://gw-ap.example".to_string()),
            region: Some("ap-southeast".to_string()),
            operator_did: Some("did:key:operator-ap".to_string()),
            roles: Vec::new(),
            supported_endpoints: Vec::new(),
            federation_peers: vec!["https://gw-us.example".to_string()],
            allows_public_ingest: true,
            signing_key_b64: Some(base64::engine::general_purpose::STANDARD.encode([7_u8; 32])),
        })
        .unwrap()
        .unwrap();

        let manifest = identity.signed_manifest().unwrap();
        assert_eq!(manifest.payload.gateway_id, "gw-ap-1");
        assert!(
            manifest
                .payload
                .supported_endpoints
                .contains(&"/api/registry/self-manifest".to_string())
        );
    }

    #[test]
    fn empty_identity_config_disables_self_manifest() {
        let identity = GatewayIdentity::from_config(GatewayIdentityConfig {
            gateway_id: None,
            display_name: None,
            base_url: None,
            region: None,
            operator_did: None,
            roles: Vec::new(),
            supported_endpoints: Vec::new(),
            federation_peers: Vec::new(),
            allows_public_ingest: true,
            signing_key_b64: None,
        })
        .unwrap();
        assert!(identity.is_none());
    }

    #[test]
    fn partial_identity_config_is_rejected() {
        let error = GatewayIdentity::from_config(GatewayIdentityConfig {
            gateway_id: Some("gw-ap-1".to_string()),
            display_name: None,
            base_url: Some("https://gw-ap.example".to_string()),
            region: None,
            operator_did: None,
            roles: Vec::new(),
            supported_endpoints: Vec::new(),
            federation_peers: Vec::new(),
            allows_public_ingest: true,
            signing_key_b64: Some(base64::engine::general_purpose::STANDARD.encode([7_u8; 32])),
        })
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("WATTETHERIA_GATEWAY_IDENTITY_DISPLAY_NAME")
        );
    }
}
