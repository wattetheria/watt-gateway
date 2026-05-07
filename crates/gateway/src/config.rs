use crate::gateway_identity::GatewayIdentityConfig;
use anyhow::{Context, Result};
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
pub use wattetheria_gateway_p2p::GatewayP2pConfig;

#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub database_url: String,
    pub nats_url: Option<String>,
    pub request_timeout_secs: u64,
    pub registry_admin_token: Option<String>,
    pub bootstrap_registry_urls: Vec<String>,
    pub gateway_identity: GatewayIdentityConfig,
    pub p2p: GatewayP2pConfig,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let bind_addr = env::var("WATTETHERIA_GATEWAY_BIND")
            .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
            .parse()
            .context("parse WATTETHERIA_GATEWAY_BIND")?;
        let database_url = env::var("WATTETHERIA_GATEWAY_DATABASE_URL").unwrap_or_else(|_| {
            "postgres://postgres:postgres@127.0.0.1:5432/wattetheria_gateway".to_string()
        });
        let nats_url = env::var("WATTETHERIA_GATEWAY_NATS_URL").ok();
        let request_timeout_secs = env::var("WATTETHERIA_GATEWAY_REQUEST_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(10);
        let registry_admin_token = env::var("WATTETHERIA_GATEWAY_REGISTRY_ADMIN_TOKEN").ok();
        let bootstrap_registry_urls = parse_csv_env("WATTETHERIA_GATEWAY_BOOTSTRAP_REGISTRY_URLS");
        let gateway_identity = GatewayIdentityConfig {
            gateway_id: env::var("WATTETHERIA_GATEWAY_IDENTITY_ID").ok(),
            display_name: env::var("WATTETHERIA_GATEWAY_IDENTITY_DISPLAY_NAME").ok(),
            base_url: env::var("WATTETHERIA_GATEWAY_IDENTITY_BASE_URL").ok(),
            region: env::var("WATTETHERIA_GATEWAY_IDENTITY_REGION").ok(),
            operator_did: env::var("WATTETHERIA_GATEWAY_IDENTITY_OPERATOR_DID")
                .ok()
                .or_else(|| env::var("WATTETHERIA_GATEWAY_IDENTITY_OPERATOR_ID").ok()),
            roles: parse_csv_env("WATTETHERIA_GATEWAY_IDENTITY_ROLES"),
            supported_endpoints: parse_csv_env("WATTETHERIA_GATEWAY_IDENTITY_SUPPORTED_ENDPOINTS"),
            federation_peers: parse_csv_env("WATTETHERIA_GATEWAY_IDENTITY_FEDERATION_PEERS"),
            allows_public_ingest: env::var("WATTETHERIA_GATEWAY_IDENTITY_ALLOWS_PUBLIC_INGEST")
                .ok()
                .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
                .unwrap_or(true),
            signing_key_b64: env::var("WATTETHERIA_GATEWAY_IDENTITY_SIGNING_KEY").ok(),
        };
        let mut p2p = GatewayP2pConfig {
            enabled: env::var("WATTETHERIA_GATEWAY_P2P_ENABLED")
                .ok()
                .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
                .unwrap_or(false),
            ..GatewayP2pConfig::default()
        };
        if let Ok(state_dir) = env::var("WATTETHERIA_GATEWAY_P2P_STATE_DIR") {
            p2p.state_dir = PathBuf::from(state_dir);
        }
        if let Ok(listen_addrs) = env::var("WATTETHERIA_GATEWAY_P2P_LISTEN_ADDRS") {
            p2p.listen_addrs = parse_csv(&listen_addrs);
        }
        if let Ok(bootstrap_peers) = env::var("WATTETHERIA_GATEWAY_P2P_BOOTSTRAP_PEERS") {
            p2p.bootstrap_peers = parse_csv(&bootstrap_peers);
        }
        if p2p.enabled {
            p2p.validate()?;
        }
        Ok(Self {
            bind_addr,
            database_url,
            nats_url,
            request_timeout_secs,
            registry_admin_token,
            bootstrap_registry_urls,
            gateway_identity,
            p2p,
        })
    }
}

fn parse_csv_env(name: &str) -> Vec<String> {
    env::var(name)
        .ok()
        .map(|value| parse_csv(&value))
        .unwrap_or_default()
}

fn parse_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}
