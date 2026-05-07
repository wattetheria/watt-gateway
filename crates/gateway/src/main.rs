use anyhow::Context;
use async_nats::ConnectOptions;
use tracing::{info, warn};
use wattetheria_gateway::{
    config::Config, db, gateway_identity::GatewayIdentity, gateway_network, http, node_client,
    registry_client, state::AppState,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "wattetheria_gateway=info,axum=info".into()),
        )
        .init();

    let config = Config::from_env()?;
    let gateway_identity = GatewayIdentity::from_config(config.gateway_identity.clone())
        .context("load gateway identity")?;
    let gateway_network_runtime = if config.p2p.enabled {
        info!("starting gateway shared p2p runtime");
        Some(
            gateway_network::GatewayNetworkRuntime::new(
                gateway_network::GatewayNetworkNode::generate(config.p2p.clone())
                    .context("generate gateway p2p node")?,
            )
            .context("start gateway p2p runtime")?,
        )
    } else {
        None
    };
    let gateway_network = gateway_network_runtime
        .as_ref()
        .map(|runtime| runtime.export_handle(chrono::Utc::now().timestamp() as u64))
        .transpose()
        .context("export gateway p2p info")?;
    let pool = db::connect(&config.database_url)
        .await
        .context("connect postgres")?;
    db::init_schema(&pool).await.context("init schema")?;

    let nats = match &config.nats_url {
        Some(url) => {
            info!("connecting to nats at {url}");
            Some(
                ConnectOptions::new()
                    .connect(url)
                    .await
                    .context("connect nats")?,
            )
        }
        None => {
            warn!("WATTETHERIA_GATEWAY_NATS_URL not set; running without event bus");
            None
        }
    };
    let (ui_stream_tx, _) = tokio::sync::broadcast::channel(512);

    let app_state = AppState {
        pool,
        node_client: node_client::NodeClient::new(config.request_timeout_secs)?,
        registry_client: registry_client::RegistryClient::new(config.request_timeout_secs)?,
        nats,
        registry_admin_token: config.registry_admin_token,
        bootstrap_registry_urls: config.bootstrap_registry_urls,
        gateway_identity,
        gateway_network,
        ui_stream_tx,
    };
    let app = http::router(app_state);

    info!("wattetheria-gateway listening on {}", config.bind_addr);
    let listener = tokio::net::TcpListener::bind(config.bind_addr)
        .await
        .context("bind listener")?;
    axum::serve(listener, app).await.context("serve axum app")?;
    Ok(())
}
