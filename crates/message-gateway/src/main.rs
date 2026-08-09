use anyhow::Context;
use std::sync::Arc;
use tracing::{info, warn};
use wattetheria_message_gateway::{config::Config, db, http, rabbit::RabbitAdapter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "wattetheria_message_gateway=info,axum=info".into()),
        )
        .init();
    let config = Arc::new(Config::from_env()?);
    let pool = db::connect(&config.database_url).await?;
    db::init_schema(&pool).await?;
    db::seed_trusted_network_genesis(&pool, &config).await?;
    db::validate_all_active_tenant_admission(&pool, &config).await?;
    let rabbit = RabbitAdapter::connect(Arc::clone(&config)).await?;
    let gap_pool = pool.clone();
    let gap_rabbit = rabbit.clone();
    tokio::spawn(async move {
        loop {
            if let Err(error) = gap_rabbit.drain_dead_letters(&gap_pool, 128).await {
                warn!(error = %error, "RabbitMQ gap recorder poll failed");
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    });
    let cleanup_pool = pool.clone();
    let cleanup_interval = config.metadata_cleanup_interval;
    let gap_retention = config.acknowledged_gap_retention;
    tokio::spawn(async move {
        loop {
            if let Err(error) = db::cleanup_expired_metadata(&cleanup_pool, gap_retention).await {
                warn!(error = %error, "Gateway metadata cleanup failed");
            }
            tokio::time::sleep(cleanup_interval).await;
        }
    });
    let lease_rabbit = rabbit.clone();
    let lease_poll = std::cmp::max(
        std::time::Duration::from_millis(25),
        config.delivery_owner_lease / 4,
    );
    tokio::spawn(async move {
        loop {
            if let Err(error) = lease_rabbit.reap_expired_pages().await {
                warn!(error = %error, "RabbitMQ page lease reaper failed");
            }
            tokio::time::sleep(lease_poll).await;
        }
    });
    let state = http::AppState {
        pool,
        config: Arc::clone(&config),
        rabbit,
    };
    let app = http::router(state.clone());
    let listener = tokio::net::TcpListener::bind(config.bind_addr)
        .await
        .context("bind Message Gateway listener")?;
    info!(bind_addr = %config.bind_addr, "Wattswarm Message Gateway listening");
    if let Some(internal_bind_addr) = config.internal_bind_addr {
        let tls = wattetheria_message_gateway::internal_tls::server_config(&config)?;
        let internal_app = http::internal_router(state);
        info!(bind_addr = %internal_bind_addr, "Wattswarm Message Gateway internal mTLS listener ready");
        tokio::try_join!(
            async move {
                axum::serve(listener, app)
                    .await
                    .context("serve Message Gateway")
            },
            async move {
                axum_server::bind_rustls(internal_bind_addr, tls)
                    .serve(internal_app.into_make_service())
                    .await
                    .context("serve Message Gateway internal mTLS listener")
            }
        )?;
    } else {
        axum::serve(listener, app)
            .await
            .context("serve Message Gateway")?;
    }
    Ok(())
}
