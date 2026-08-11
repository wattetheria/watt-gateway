use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub database_url: String,
    pub rabbitmq_endpoint: String,
    pub rabbitmq_username: String,
    pub rabbitmq_password: String,
    pub rabbitmq_prefetch: u16,
    pub delivery_page_size: usize,
    pub mailbox_message_ttl_ms: u64,
    pub mailbox_max_length_bytes: u64,
    pub dead_letter_max_length_bytes: u64,
    pub max_delivery_attempts: u32,
    pub cluster_queue_limit: u64,
    pub mailbox_shard_admission_percent: u64,
    pub max_active_tenants: u64,
    pub max_fanout_recipients: u64,
    pub max_fanout_deliveries_per_second: u64,
    pub max_fanout_bytes_per_publish: u64,
    pub fanout_confirm_timeout: Duration,
    pub max_global_publishes_per_second: u64,
    pub global_publish_burst: u64,
    pub global_interactive_reserved_per_second: u64,
    pub reserved_non_global_deliveries_per_second: u64,
    pub fanout_admission_utilization_percent: u64,
    pub commit_hmac_secret: Vec<u8>,
    pub session_ttl: Duration,
    pub skip_grant_validation: bool,
    pub object_store_root: Option<PathBuf>,
    pub max_object_bytes: u64,
    pub membership_binding_timeout: Duration,
    pub membership_mutation_window: Duration,
    pub max_membership_mutations_per_scope_per_window: u64,
    pub max_membership_binding_lag: Duration,
    pub instance_id: String,
    pub internal_route: Option<String>,
    pub internal_bind_addr: Option<SocketAddr>,
    pub internal_mtls_identity_pem: Option<Vec<u8>>,
    pub internal_mtls_ca_pem: Option<Vec<u8>>,
    pub delivery_owner_lease: Duration,
    pub delivery_commit_forward_timeout: Duration,
    pub metadata_cleanup_interval: Duration,
    pub acknowledged_gap_retention: Duration,
    pub trusted_network_genesis: BTreeMap<String, String>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Config")
            .field("bind_addr", &self.bind_addr)
            .field("database_url", &"[redacted]")
            .field(
                "rabbitmq_endpoint",
                &redact_endpoint(&self.rabbitmq_endpoint),
            )
            .field("rabbitmq_username", &"[redacted]")
            .field("rabbitmq_password", &"[redacted]")
            .field("rabbitmq_prefetch", &self.rabbitmq_prefetch)
            .field("delivery_page_size", &self.delivery_page_size)
            .finish_non_exhaustive()
    }
}

impl Config {
    pub fn from_env() -> Result<Self> {
        if env::var("WATTSWARM_CS_MESSAGE_BUS").unwrap_or_else(|_| "rabbitmq".to_owned())
            != "rabbitmq"
        {
            bail!("WATTSWARM_CS_MESSAGE_BUS must be rabbitmq in V1");
        }
        let password_file = required("WATTSWARM_RABBITMQ_PASSWORD_FILE")?;
        let commit_secret_file = required("WATTSWARM_CS_COMMIT_HMAC_SECRET_FILE")?;
        let config = Self {
            bind_addr: env::var("WATTSWARM_CS_BIND_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:8090".to_owned())
                .parse()?,
            database_url: required("WATTSWARM_CS_DATABASE_URL")?,
            rabbitmq_endpoint: required("WATTSWARM_RABBITMQ_ENDPOINT")?,
            rabbitmq_username: required("WATTSWARM_RABBITMQ_USERNAME")?,
            rabbitmq_password: std::fs::read_to_string(password_file)?.trim().to_owned(),
            rabbitmq_prefetch: number("WATTSWARM_RABBITMQ_PREFETCH", 128)?,
            delivery_page_size: number("WATTSWARM_CS_DELIVERY_PAGE_SIZE", 64)?,
            mailbox_message_ttl_ms: number("WATTSWARM_RABBITMQ_MAILBOX_MESSAGE_TTL", 86_400_000)?,
            mailbox_max_length_bytes: number(
                "WATTSWARM_RABBITMQ_MAILBOX_MAX_LENGTH_BYTES",
                268_435_456,
            )?,
            dead_letter_max_length_bytes: number(
                "WATTSWARM_RABBITMQ_DEAD_LETTER_MAX_LENGTH_BYTES",
                268_435_456,
            )?,
            max_delivery_attempts: number("WATTSWARM_RABBITMQ_MAX_DELIVERY_ATTEMPTS", 10)?,
            cluster_queue_limit: number("WATTSWARM_RABBITMQ_CLUSTER_QUEUE_LIMIT", 1_000)?,
            mailbox_shard_admission_percent: number(
                "WATTSWARM_CS_MAILBOX_SHARD_ADMISSION_PERCENT",
                80,
            )?,
            max_active_tenants: number("WATTSWARM_CS_MAX_ACTIVE_TENANTS_PER_NETWORK_CELL", 400)?,
            max_fanout_recipients: number("WATTSWARM_CS_MAX_FANOUT_RECIPIENTS", 400)?,
            max_fanout_deliveries_per_second: number(
                "WATTSWARM_CS_MAX_FANOUT_DELIVERIES_PER_SECOND",
                100_000,
            )?,
            max_fanout_bytes_per_publish: number(
                "WATTSWARM_CS_MAX_FANOUT_BYTES_PER_PUBLISH",
                67_108_864,
            )?,
            fanout_confirm_timeout: Duration::from_millis(number(
                "WATTSWARM_CS_FANOUT_CONFIRM_TIMEOUT",
                10_000,
            )?),
            max_global_publishes_per_second: number(
                "WATTSWARM_CS_MAX_GLOBAL_PUBLISHES_PER_SECOND",
                100,
            )?,
            global_publish_burst: number("WATTSWARM_CS_GLOBAL_PUBLISH_BURST", 20)?,
            global_interactive_reserved_per_second: number(
                "WATTSWARM_CS_GLOBAL_INTERACTIVE_RESERVED_PER_SECOND",
                10,
            )?,
            reserved_non_global_deliveries_per_second: number(
                "WATTSWARM_CS_RESERVED_NON_GLOBAL_DELIVERIES_PER_SECOND",
                10_000,
            )?,
            fanout_admission_utilization_percent: number(
                "WATTSWARM_CS_FANOUT_ADMISSION_UTILIZATION_PERCENT",
                80,
            )?,
            commit_hmac_secret: std::fs::read(commit_secret_file)?,
            session_ttl: Duration::from_secs(number("WATTSWARM_CS_SESSION_TTL_SECONDS", 900)?),
            skip_grant_validation: flag("WATTSWARM_CS_SKIP_GRANT_VALIDATION", false)?,
            object_store_root: env::var_os("WATTSWARM_CS_OBJECT_STORE_ROOT").map(PathBuf::from),
            max_object_bytes: number("WATTSWARM_CS_MAX_OBJECT_BYTES", 67_108_864)?,
            membership_binding_timeout: Duration::from_millis(number(
                "WATTSWARM_CS_MEMBERSHIP_BINDING_TIMEOUT",
                10_000,
            )?),
            membership_mutation_window: Duration::from_millis(number(
                "WATTSWARM_CS_MEMBERSHIP_MUTATION_WINDOW",
                60_000,
            )?),
            max_membership_mutations_per_scope_per_window: number(
                "WATTSWARM_CS_MAX_MEMBERSHIP_MUTATIONS_PER_SCOPE_PER_WINDOW",
                100,
            )?,
            max_membership_binding_lag: Duration::from_millis(number(
                "WATTSWARM_CS_MAX_MEMBERSHIP_BINDING_LAG",
                30_000,
            )?),
            instance_id: env::var("WATTSWARM_CS_INSTANCE_ID")
                .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string()),
            internal_route: env::var("WATTSWARM_CS_INTERNAL_ROUTE").ok(),
            internal_bind_addr: env::var("WATTSWARM_CS_INTERNAL_BIND_ADDR")
                .ok()
                .map(|value| value.parse())
                .transpose()?,
            internal_mtls_identity_pem: optional_secret_file(
                "WATTSWARM_CS_INTERNAL_MTLS_IDENTITY_FILE",
            )?,
            internal_mtls_ca_pem: optional_secret_file("WATTSWARM_CS_INTERNAL_MTLS_CA_FILE")?,
            delivery_owner_lease: Duration::from_millis(number(
                "WATTSWARM_CS_DELIVERY_OWNER_LEASE",
                30_000,
            )?),
            delivery_commit_forward_timeout: Duration::from_millis(number(
                "WATTSWARM_CS_DELIVERY_COMMIT_FORWARD_TIMEOUT",
                5_000,
            )?),
            metadata_cleanup_interval: Duration::from_millis(number(
                "WATTSWARM_CS_METADATA_CLEANUP_INTERVAL",
                60_000,
            )?),
            acknowledged_gap_retention: Duration::from_millis(number(
                "WATTSWARM_CS_ACKNOWLEDGED_GAP_RETENTION",
                86_400_000,
            )?),
            trusted_network_genesis: load_trusted_network_genesis()?,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if !self.rabbitmq_endpoint.starts_with("amqps://") {
            bail!("RabbitMQ endpoint must use amqps");
        }
        if self.rabbitmq_password.is_empty() || self.commit_hmac_secret.len() < 32 {
            bail!("RabbitMQ password and a 32-byte commit secret are required");
        }
        if self.delivery_page_size == 0 || self.rabbitmq_prefetch == 0 {
            bail!("delivery page size and RabbitMQ prefetch must be positive");
        }
        if self.max_object_bytes == 0
            || self.max_fanout_bytes_per_publish == 0
            || self.dead_letter_max_length_bytes == 0
        {
            bail!("CS Object Store maximum object size must be positive");
        }
        if self.max_membership_mutations_per_scope_per_window == 0
            || self.membership_binding_timeout.is_zero()
            || self.membership_mutation_window.is_zero()
            || self.max_membership_binding_lag.is_zero()
            || self.delivery_owner_lease.is_zero()
            || self.delivery_commit_forward_timeout.is_zero()
            || self.metadata_cleanup_interval.is_zero()
            || self.acknowledged_gap_retention.is_zero()
            || self.fanout_confirm_timeout.is_zero()
        {
            bail!("membership and delivery-owner limits must be positive");
        }
        if self
            .internal_route
            .as_deref()
            .is_some_and(|route| !route.starts_with("https://"))
        {
            bail!("Gateway internal owner route must use HTTPS");
        }
        let internal_values = [
            self.internal_route.is_some(),
            self.internal_bind_addr.is_some(),
            self.internal_mtls_identity_pem.is_some(),
            self.internal_mtls_ca_pem.is_some(),
        ];
        if internal_values.iter().any(|configured| *configured)
            && internal_values.iter().any(|configured| !*configured)
        {
            bail!(
                "Gateway internal owner forwarding requires route, bind address, mTLS identity, and CA"
            );
        }
        if self.max_fanout_recipients < self.max_active_tenants {
            bail!("MAX_FANOUT_RECIPIENTS must cover every active tenant");
        }
        for (network_id, genesis_node_id) in &self.trusted_network_genesis {
            if network_id.trim().is_empty()
                || !matches!(hex::decode(genesis_node_id), Ok(bytes) if bytes.len() == 32)
            {
                bail!("trusted network genesis entries require a network id and Ed25519 node id");
            }
        }
        let queue_budget = self.max_active_tenants.saturating_mul(2).saturating_add(16);
        let admitted_queues = self
            .cluster_queue_limit
            .saturating_mul(self.mailbox_shard_admission_percent)
            / 100;
        if queue_budget > admitted_queues {
            bail!("two-mailbox tenant queue budget exceeds RabbitMQ admission threshold");
        }
        if self.max_global_publishes_per_second == 0
            || self.global_interactive_reserved_per_second == 0
            || self.global_interactive_reserved_per_second > self.max_global_publishes_per_second
            || self.reserved_non_global_deliveries_per_second == 0
        {
            bail!("invalid Global publish, Interactive reserve, or non-Global delivery rate");
        }
        let required_delivery_rate = self
            .max_global_publishes_per_second
            .saturating_mul(self.max_active_tenants)
            .saturating_add(self.reserved_non_global_deliveries_per_second);
        let safe_delivery_rate = self
            .max_fanout_deliveries_per_second
            .saturating_mul(self.fanout_admission_utilization_percent)
            / 100;
        if required_delivery_rate > safe_delivery_rate {
            bail!("Global fanout delivery-rate admission invariant is not satisfied");
        }
        Ok(())
    }
}

fn required(key: &str) -> Result<String> {
    env::var(key).with_context(|| format!("{key} is required"))
}

fn optional_secret_file(key: &str) -> Result<Option<Vec<u8>>> {
    env::var_os(key)
        .map(std::fs::read)
        .transpose()
        .with_context(|| format!("read {key}"))
}

fn load_trusted_network_genesis() -> Result<BTreeMap<String, String>> {
    let Some(path) = env::var_os("WATTSWARM_CS_TRUSTED_NETWORK_GENESIS_FILE") else {
        return Ok(BTreeMap::new());
    };
    let bytes = std::fs::read(&path).with_context(|| {
        format!(
            "read WATTSWARM_CS_TRUSTED_NETWORK_GENESIS_FILE {}",
            std::path::Path::new(&path).display()
        )
    })?;
    serde_json::from_slice(&bytes).context("decode trusted network genesis map")
}

fn number<T>(key: &str, default: T) -> Result<T>
where
    T: std::str::FromStr + ToString,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    env::var(key)
        .unwrap_or_else(|_| default.to_string())
        .parse()
        .with_context(|| format!("parse {key}"))
}

fn flag(key: &str, default: bool) -> Result<bool> {
    let Some(value) = env::var(key).ok() else {
        return Ok(default);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => bail!("parse {key}: expected a boolean"),
    }
}

fn redact_endpoint(endpoint: &str) -> String {
    endpoint
        .rsplit_once('@')
        .map(|(_, host)| format!("amqps://{host}"))
        .unwrap_or_else(|| endpoint.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> Config {
        Config {
            bind_addr: "127.0.0.1:8090".parse().unwrap(),
            database_url: "postgres://secret".to_owned(),
            rabbitmq_endpoint: "amqps://broker/vhost".to_owned(),
            rabbitmq_username: "user".to_owned(),
            rabbitmq_password: "contract-secret-password".to_owned(),
            rabbitmq_prefetch: 128,
            delivery_page_size: 64,
            mailbox_message_ttl_ms: 1000,
            mailbox_max_length_bytes: 1_000_000,
            dead_letter_max_length_bytes: 1_000_000,
            max_delivery_attempts: 10,
            cluster_queue_limit: 1_100,
            mailbox_shard_admission_percent: 80,
            max_active_tenants: 400,
            max_fanout_recipients: 400,
            max_fanout_deliveries_per_second: 100_000,
            max_fanout_bytes_per_publish: 67_108_864,
            fanout_confirm_timeout: Duration::from_secs(10),
            max_global_publishes_per_second: 100,
            global_publish_burst: 20,
            global_interactive_reserved_per_second: 10,
            reserved_non_global_deliveries_per_second: 10_000,
            fanout_admission_utilization_percent: 80,
            commit_hmac_secret: vec![1; 32],
            session_ttl: Duration::from_secs(900),
            skip_grant_validation: false,
            object_store_root: None,
            max_object_bytes: 67_108_864,
            membership_binding_timeout: Duration::from_secs(10),
            membership_mutation_window: Duration::from_secs(60),
            max_membership_mutations_per_scope_per_window: 100,
            max_membership_binding_lag: Duration::from_secs(30),
            instance_id: "gateway-test".to_owned(),
            internal_route: None,
            internal_bind_addr: None,
            internal_mtls_identity_pem: None,
            internal_mtls_ca_pem: None,
            delivery_owner_lease: Duration::from_secs(30),
            delivery_commit_forward_timeout: Duration::from_secs(5),
            metadata_cleanup_interval: Duration::from_secs(60),
            acknowledged_gap_retention: Duration::from_secs(86_400),
            trusted_network_genesis: BTreeMap::new(),
        }
    }

    #[test]
    fn validates_multiplicative_global_capacity_and_queue_cardinality() {
        valid().validate().unwrap();
        let mut invalid = valid();
        invalid.max_fanout_deliveries_per_second = 10;
        assert!(invalid.validate().is_err());
        let debug = format!("{:?}", valid());
        assert!(!debug.contains("contract-secret-password"));

        let mut invalid = valid();
        invalid.reserved_non_global_deliveries_per_second = 0;
        assert!(invalid.validate().is_err());
        assert!(!debug.contains("postgres://secret"));
    }

    #[test]
    fn internal_owner_forwarding_requires_a_complete_mtls_listener_configuration() {
        let mut invalid = valid();
        invalid.internal_route = Some("https://gateway-a.internal:8443".to_owned());
        assert!(invalid.validate().is_err());

        invalid.internal_bind_addr = Some("127.0.0.1:8443".parse().unwrap());
        invalid.internal_mtls_identity_pem = Some(b"identity".to_vec());
        invalid.internal_mtls_ca_pem = Some(b"ca".to_vec());
        invalid.validate().unwrap();
    }
}
