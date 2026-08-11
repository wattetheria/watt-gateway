use anyhow::{Context, Result, bail};
use sqlx::{PgPool, Postgres, Row, Transaction, postgres::PgPoolOptions};
use wattswarm_network_transport_core::{DeliveryClass, SwarmScope};
// Temporarily disabled with the Grant admission endpoint. The production
// Docker build pins a Wattswarm revision without NetworkMembershipGrant.

use crate::config::Config;

#[derive(Debug, Clone)]
pub struct DeliveryOwner {
    pub instance_id: String,
    pub consumer_epoch: uuid::Uuid,
    pub owner_route: String,
}

pub async fn connect(database_url: &str) -> Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(20)
        .connect(database_url)
        .await
        .context("connect Message Gateway PostgreSQL")
}

pub async fn init_schema(pool: &PgPool) -> Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('wattswarm-message-gateway-schema', 0))",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::raw_sql(
        r#"
        CREATE TABLE IF NOT EXISTS gateway_challenges (
            challenge_id UUID PRIMARY KEY,
            network_id TEXT NOT NULL,
            principals_json JSONB NOT NULL,
            nonce TEXT NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            consumed_at TIMESTAMPTZ
        );
        CREATE TABLE IF NOT EXISTS gateway_sessions (
            session_id UUID PRIMARY KEY,
            token_hash TEXT UNIQUE NOT NULL,
            network_id TEXT NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
        );
        CREATE TABLE IF NOT EXISTS gateway_session_principals (
            session_id UUID NOT NULL REFERENCES gateway_sessions(session_id) ON DELETE CASCADE,
            principal_id TEXT NOT NULL,
            verified_at TIMESTAMPTZ NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY(session_id, principal_id)
        );
        CREATE TABLE IF NOT EXISTS gateway_principal_instances (
            network_id TEXT NOT NULL,
            principal_id TEXT NOT NULL,
            tenant_instance_id TEXT NOT NULL,
            history_unavailable BOOLEAN NOT NULL DEFAULT FALSE,
            first_seen_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY(network_id, principal_id)
        );
        CREATE TABLE IF NOT EXISTS gateway_scope_memberships (
            network_id TEXT NOT NULL,
            scope_label TEXT NOT NULL,
            principal_id TEXT NOT NULL,
            membership_version TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('active', 'revoked')),
            authorized_at TIMESTAMPTZ NOT NULL,
            revoked_at TIMESTAMPTZ,
            interactive_binding_state TEXT NOT NULL DEFAULT 'pending',
            bulk_binding_state TEXT NOT NULL DEFAULT 'pending',
            roles_json JSONB NOT NULL DEFAULT '[]'::jsonb,
            binding_updated_at TIMESTAMPTZ,
            PRIMARY KEY(network_id, scope_label, principal_id)
        );
        CREATE TABLE IF NOT EXISTS gateway_network_membership_grants (
            network_id TEXT NOT NULL,
            principal_id TEXT NOT NULL,
            grant_id TEXT NOT NULL,
            grant_json JSONB NOT NULL,
            issued_at_ms BIGINT NOT NULL,
            expires_at_ms BIGINT,
            updated_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY(network_id, principal_id)
        );
        CREATE TABLE IF NOT EXISTS gateway_scope_versions (
            network_id TEXT NOT NULL,
            scope_label TEXT NOT NULL,
            active_membership_version TEXT NOT NULL,
            routing_fence BIGINT NOT NULL DEFAULT 0,
            updated_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY(network_id, scope_label)
        );
        CREATE TABLE IF NOT EXISTS gateway_network_authorities (
            network_id TEXT NOT NULL,
            principal_id TEXT NOT NULL,
            authority_kind TEXT NOT NULL,
            projection_version TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('active', 'revoked')),
            updated_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY(network_id, principal_id, authority_kind)
        );
        CREATE TABLE IF NOT EXISTS gateway_scope_route_bindings (
            network_id TEXT NOT NULL,
            scope_label TEXT NOT NULL,
            route_address TEXT NOT NULL,
            principal_id TEXT NOT NULL,
            delivery_class TEXT NOT NULL,
            membership_version TEXT NOT NULL,
            binding_state TEXT NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY(network_id, scope_label, route_address, principal_id, delivery_class)
        );
        CREATE TABLE IF NOT EXISTS gateway_scope_mutation_windows (
            network_id TEXT NOT NULL,
            scope_label TEXT NOT NULL,
            window_started_at TIMESTAMPTZ NOT NULL,
            mutation_count BIGINT NOT NULL,
            last_membership_version TEXT,
            updated_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY(network_id, scope_label)
        );
        CREATE TABLE IF NOT EXISTS gateway_delivery_owners (
            binding_key TEXT NOT NULL,
            delivery_class TEXT NOT NULL,
            owner_instance_id TEXT NOT NULL,
            consumer_epoch UUID NOT NULL,
            lease_expires_at TIMESTAMPTZ NOT NULL,
            owner_route TEXT NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY(binding_key, delivery_class)
        );
        CREATE TABLE IF NOT EXISTS gateway_global_rate_buckets (
            network_id TEXT NOT NULL,
            routing_cell_id TEXT NOT NULL,
            policy_version BIGINT NOT NULL,
            total_tokens DOUBLE PRECISION NOT NULL,
            bulk_tokens DOUBLE PRECISION NOT NULL,
            last_refill_at TIMESTAMPTZ NOT NULL,
            total_rate DOUBLE PRECISION NOT NULL,
            bulk_rate DOUBLE PRECISION NOT NULL,
            burst_capacity DOUBLE PRECISION NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY(network_id, routing_cell_id)
        );
        CREATE TABLE IF NOT EXISTS gateway_non_global_rate_buckets (
            network_id TEXT NOT NULL,
            routing_cell_id TEXT NOT NULL,
            policy_version BIGINT NOT NULL,
            tokens DOUBLE PRECISION NOT NULL,
            last_refill_at TIMESTAMPTZ NOT NULL,
            rate DOUBLE PRECISION NOT NULL,
            burst_capacity DOUBLE PRECISION NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY(network_id, routing_cell_id)
        );
        CREATE TABLE IF NOT EXISTS gateway_mailbox_gaps (
            network_id TEXT NOT NULL,
            principal_id TEXT NOT NULL,
            gap_id UUID NOT NULL,
            delivery_class TEXT NOT NULL,
            delivery_policy_version BIGINT NOT NULL,
            route_json JSONB NOT NULL,
            reason TEXT NOT NULL,
            first_affected_at TIMESTAMPTZ NOT NULL,
            last_affected_at TIMESTAMPTZ NOT NULL,
            approximate_count BIGINT NOT NULL,
            delivered_at TIMESTAMPTZ,
            delivery_page_id TEXT,
            acknowledged_at TIMESTAMPTZ,
            PRIMARY KEY(network_id, principal_id, gap_id)
        );
        CREATE TABLE IF NOT EXISTS gateway_publish_receipts (
            network_id TEXT NOT NULL,
            principal_id TEXT NOT NULL,
            record_id TEXT NOT NULL,
            authorized_route_hash TEXT NOT NULL,
            record_hash TEXT NOT NULL,
            membership_version TEXT,
            delivery_class TEXT NOT NULL,
            delivery_policy_version BIGINT NOT NULL,
            expected_recipients BIGINT NOT NULL,
            binding_set_hash TEXT NOT NULL,
            publish_status TEXT NOT NULL,
            confirmed_at TIMESTAMPTZ,
            expires_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY(network_id, principal_id, record_id)
        );
        CREATE TABLE IF NOT EXISTS gateway_audit (
            audit_id UUID PRIMARY KEY,
            network_id TEXT,
            principal_id TEXT,
            action TEXT NOT NULL,
            outcome TEXT NOT NULL,
            details_json JSONB NOT NULL DEFAULT '{}',
            created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
        );
        ALTER TABLE gateway_mailbox_gaps
            ADD COLUMN IF NOT EXISTS delivery_page_id TEXT;
        ALTER TABLE gateway_mailbox_gaps
            ADD COLUMN IF NOT EXISTS network_id TEXT NOT NULL DEFAULT '';
        ALTER TABLE gateway_scope_memberships
            ADD COLUMN IF NOT EXISTS roles_json JSONB NOT NULL DEFAULT '[]'::jsonb;
        DELETE FROM gateway_mailbox_gaps WHERE network_id = '';
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conrelid = 'gateway_mailbox_gaps'::regclass
                  AND contype = 'p'
                  AND pg_get_constraintdef(oid) NOT LIKE '%network_id%'
            ) THEN
                ALTER TABLE gateway_mailbox_gaps DROP CONSTRAINT gateway_mailbox_gaps_pkey;
                ALTER TABLE gateway_mailbox_gaps
                    ADD PRIMARY KEY(network_id, principal_id, gap_id);
            END IF;
        END $$;
        ALTER TABLE gateway_publish_receipts
            ADD COLUMN IF NOT EXISTS record_hash TEXT NOT NULL DEFAULT '';
        CREATE INDEX IF NOT EXISTS idx_gateway_scope_memberships_active
            ON gateway_scope_memberships(network_id, scope_label, state, membership_version);
        CREATE INDEX IF NOT EXISTS idx_gateway_network_membership_grants_expiry
            ON gateway_network_membership_grants(network_id, principal_id, expires_at_ms);
        CREATE INDEX IF NOT EXISTS idx_gateway_delivery_owner_lease
            ON gateway_delivery_owners(lease_expires_at);
        CREATE INDEX IF NOT EXISTS idx_gateway_mailbox_gaps_pending
            ON gateway_mailbox_gaps(network_id, principal_id, delivery_class, acknowledged_at);
        "#,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/*
 * Temporarily disabled until the pinned Wattswarm revision exposes Grant
 * types. Keep this implementation for re-enabling with the matching pin.
pub async fn upsert_network_membership_grant(
    tx: &mut Transaction<'_, Postgres>,
    grant: &NetworkMembershipGrant,
    grant_id: &str,
) -> Result<()> {
    let issued_at_ms = i64::try_from(grant.issued_at)
        .context("network membership grant issued_at exceeds PostgreSQL BIGINT")?;
    let expires_at_ms = grant
        .expires_at
        .map(|value| {
            i64::try_from(value)
                .context("network membership grant expires_at exceeds PostgreSQL BIGINT")
        })
        .transpose()?;
    sqlx::query(
        "INSERT INTO gateway_network_membership_grants(
             network_id, principal_id, grant_id, grant_json,
             issued_at_ms, expires_at_ms, updated_at
         ) VALUES ($1,$2,$3,$4,$5,$6,clock_timestamp())
         ON CONFLICT(network_id, principal_id) DO UPDATE SET
             grant_id = EXCLUDED.grant_id,
             grant_json = EXCLUDED.grant_json,
             issued_at_ms = EXCLUDED.issued_at_ms,
             expires_at_ms = EXCLUDED.expires_at_ms,
             updated_at = clock_timestamp()",
    )
    .bind(&grant.network_id)
    .bind(&grant.principal_id)
    .bind(grant_id)
    .bind(serde_json::to_value(grant)?)
    .bind(issued_at_ms)
    .bind(expires_at_ms)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
*/

pub async fn seed_trusted_network_genesis(pool: &PgPool, config: &Config) -> Result<()> {
    for (network_id, genesis_node_id) in &config.trusted_network_genesis {
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!("trusted-genesis:{network_id}"))
            .execute(&mut *tx)
            .await?;
        let existing = sqlx::query_scalar::<_, String>(
            "SELECT principal_id FROM gateway_network_authorities
             WHERE network_id = $1 AND authority_kind = 'genesis' AND state = 'active'",
        )
        .bind(network_id)
        .fetch_optional(&mut *tx)
        .await?;
        if existing
            .as_deref()
            .is_some_and(|value| value != genesis_node_id)
        {
            bail!("configured network genesis conflicts with the persisted authority projection");
        }
        sqlx::query(
            "INSERT INTO gateway_network_authorities(
                 network_id, principal_id, authority_kind, projection_version, state, updated_at
             ) VALUES ($1,$2,'genesis','trusted-config-v1','active',clock_timestamp())
             ON CONFLICT(network_id, principal_id, authority_kind) DO UPDATE SET
                 projection_version = EXCLUDED.projection_version,
                 state = 'active', updated_at = clock_timestamp()",
        )
        .bind(network_id)
        .bind(genesis_node_id)
        .execute(&mut *tx)
        .await?;
        let initialized: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM gateway_scope_versions
             WHERE network_id = $1 AND scope_label = 'global')",
        )
        .bind(network_id)
        .fetch_one(&mut *tx)
        .await?;
        if !initialized {
            let roles = serde_json::to_value(std::collections::HashSet::from([
                wattswarm_protocol::types::Role::Proposer,
                wattswarm_protocol::types::Role::Verifier,
                wattswarm_protocol::types::Role::Committer,
                wattswarm_protocol::types::Role::Finalizer,
            ]))?;
            let version = format!("trusted-genesis:{genesis_node_id}");
            sqlx::query(
                "INSERT INTO gateway_scope_memberships(
                     network_id, scope_label, principal_id, membership_version, state,
                     authorized_at, interactive_binding_state, bulk_binding_state, roles_json
                 ) VALUES ($1,'global',$2,$3,'active',clock_timestamp(),'pending','pending',$4)",
            )
            .bind(network_id)
            .bind(genesis_node_id)
            .bind(&version)
            .bind(roles)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO gateway_scope_versions(
                     network_id, scope_label, active_membership_version, routing_fence, updated_at
                 ) VALUES ($1,'global',$2,1,clock_timestamp())",
            )
            .bind(network_id)
            .bind(version)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
    }
    Ok(())
}

pub async fn validate_all_active_tenant_admission(pool: &PgPool, config: &Config) -> Result<()> {
    let mut network_ids = sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT network_id FROM gateway_scope_memberships
         WHERE scope_label = 'global' AND state = 'active'",
    )
    .fetch_all(pool)
    .await?;
    network_ids.extend(config.trusted_network_genesis.keys().cloned());
    network_ids.sort();
    network_ids.dedup();
    for network_id in network_ids {
        validate_active_tenant_admission(pool, config, &network_id).await?;
    }
    Ok(())
}

pub async fn cleanup_expired_metadata(
    pool: &PgPool,
    acknowledged_gap_retention: std::time::Duration,
) -> Result<u64> {
    let retention_ms = i64::try_from(acknowledged_gap_retention.as_millis())
        .context("acknowledged gap retention is too large")?;
    let mut removed = 0_u64;
    for statement in [
        "DELETE FROM gateway_challenges WHERE expires_at <= clock_timestamp()",
        "DELETE FROM gateway_sessions WHERE expires_at <= clock_timestamp()",
        "DELETE FROM gateway_publish_receipts WHERE expires_at <= clock_timestamp()",
        "DELETE FROM gateway_delivery_owners WHERE lease_expires_at <= clock_timestamp()",
    ] {
        removed =
            removed.saturating_add(sqlx::query(statement).execute(pool).await?.rows_affected());
    }
    removed = removed.saturating_add(
        sqlx::query(
            "DELETE FROM gateway_mailbox_gaps
             WHERE acknowledged_at IS NOT NULL
               AND acknowledged_at <= clock_timestamp() - ($1::BIGINT * INTERVAL '1 millisecond')",
        )
        .bind(retention_ms)
        .execute(pool)
        .await?
        .rows_affected(),
    );
    removed = removed.saturating_add(
        sqlx::query(
            "DELETE FROM gateway_audit
             WHERE created_at <= clock_timestamp()
                 - ($1::BIGINT * INTERVAL '1 millisecond')",
        )
        .bind(retention_ms)
        .execute(pool)
        .await?
        .rows_affected(),
    );
    Ok(removed)
}

pub async fn principal_is_admitted(
    pool: &PgPool,
    network_id: &str,
    principal_id: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(
             SELECT 1
             FROM gateway_scope_memberships membership
             LEFT JOIN gateway_network_membership_grants grant_projection
               ON grant_projection.network_id = membership.network_id
              AND grant_projection.principal_id = membership.principal_id
             WHERE membership.network_id = $1
               AND membership.scope_label = 'global'
               AND membership.principal_id = $2
               AND membership.state = 'active'
               AND (
                   grant_projection.expires_at_ms IS NULL
                   OR grant_projection.expires_at_ms >
                      (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT
               )
         )",
    )
    .bind(network_id)
    .bind(principal_id)
    .fetch_one(pool)
    .await?)
}

pub async fn register_principal_instance(
    tx: &mut Transaction<'_, Postgres>,
    network_id: &str,
    principal_id: &str,
    tenant_instance_id: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "INSERT INTO gateway_principal_instances(
             network_id, principal_id, tenant_instance_id, history_unavailable,
             first_seen_at, updated_at
         ) VALUES ($1,$2,$3,FALSE,clock_timestamp(),clock_timestamp())
         ON CONFLICT(network_id, principal_id) DO UPDATE SET
             history_unavailable = gateway_principal_instances.history_unavailable
                 OR gateway_principal_instances.tenant_instance_id <> EXCLUDED.tenant_instance_id,
             tenant_instance_id = EXCLUDED.tenant_instance_id,
             updated_at = clock_timestamp()
         RETURNING history_unavailable",
    )
    .bind(network_id)
    .bind(principal_id)
    .bind(tenant_instance_id)
    .fetch_one(&mut **tx)
    .await?)
}

pub async fn record_audit(
    tx: &mut Transaction<'_, Postgres>,
    network_id: Option<&str>,
    principal_id: Option<&str>,
    action: &str,
    outcome: &str,
    details: serde_json::Value,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO gateway_audit(
             audit_id, network_id, principal_id, action, outcome, details_json
         ) VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(network_id)
    .bind(principal_id)
    .bind(action)
    .bind(outcome)
    .bind(details)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub async fn principal_is_global_authority(
    pool: &PgPool,
    network_id: &str,
    principal_id: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(
             SELECT 1 FROM gateway_network_authorities
             WHERE network_id = $1 AND principal_id = $2
               AND authority_kind = 'genesis' AND state = 'active'
         )",
    )
    .bind(network_id)
    .bind(principal_id)
    .fetch_one(pool)
    .await?)
}

pub async fn active_tenant_count(pool: &PgPool, network_id: &str) -> Result<u64> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT membership.principal_id)
         FROM gateway_scope_memberships membership
         LEFT JOIN gateway_network_membership_grants grant_projection
           ON grant_projection.network_id = membership.network_id
          AND grant_projection.principal_id = membership.principal_id
         WHERE membership.network_id = $1
           AND membership.scope_label = 'global'
           AND membership.state = 'active'
           AND (
               grant_projection.expires_at_ms IS NULL
               OR grant_projection.expires_at_ms >
                  (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT
           )",
    )
    .bind(network_id)
    .fetch_one(pool)
    .await?;
    Ok(count.max(0) as u64)
}

pub async fn validate_active_tenant_admission(
    pool: &PgPool,
    config: &Config,
    network_id: &str,
) -> Result<u64> {
    let active = active_tenant_count(pool, network_id).await?;
    if active > config.max_active_tenants || active > config.max_fanout_recipients {
        bail!("active tenant count exceeds ClientServer cell admission");
    }
    let admitted_queues = config
        .cluster_queue_limit
        .saturating_mul(config.mailbox_shard_admission_percent)
        / 100;
    if active.saturating_mul(2).saturating_add(16) > admitted_queues {
        bail!("active tenant mailbox queues exceed cell admission threshold");
    }
    let required_delivery_rate = config
        .max_global_publishes_per_second
        .saturating_mul(active)
        .saturating_add(config.reserved_non_global_deliveries_per_second);
    let safe_delivery_rate = config
        .max_fanout_deliveries_per_second
        .saturating_mul(config.fanout_admission_utilization_percent)
        / 100;
    if required_delivery_rate > safe_delivery_rate {
        bail!("active tenant count violates Global delivery-rate admission");
    }
    Ok(active)
}

pub async fn begin_scope_fence<'a>(
    pool: &'a PgPool,
    network_id: &str,
    scope_label: &str,
    exclusive: bool,
) -> Result<Transaction<'a, Postgres>> {
    let mut tx = pool.begin().await?;
    let key = format!("{}:{network_id}{scope_label}", network_id.len());
    let statement = if exclusive {
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))"
    } else {
        "SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))"
    };
    sqlx::query(statement).bind(key).execute(&mut *tx).await?;
    Ok(tx)
}

pub async fn record_membership_mutation(
    tx: &mut Transaction<'_, Postgres>,
    config: &Config,
    network_id: &str,
    scope_label: &str,
    membership_version: &str,
) -> Result<()> {
    let window_ms = config.membership_mutation_window.as_millis() as i64;
    sqlx::query(
        "INSERT INTO gateway_scope_mutation_windows(
             network_id, scope_label, window_started_at, mutation_count,
             last_membership_version, updated_at
         ) VALUES ($1, $2, clock_timestamp(), 1, $3, clock_timestamp())
         ON CONFLICT(network_id, scope_label) DO UPDATE SET
             window_started_at = CASE
                 WHEN gateway_scope_mutation_windows.window_started_at
                      <= clock_timestamp() - ($4 * INTERVAL '1 millisecond')
                 THEN clock_timestamp()
                 ELSE gateway_scope_mutation_windows.window_started_at
             END,
             mutation_count = CASE
                 WHEN gateway_scope_mutation_windows.window_started_at
                      <= clock_timestamp() - ($4 * INTERVAL '1 millisecond')
                 THEN 1
                 WHEN gateway_scope_mutation_windows.last_membership_version = $3
                 THEN gateway_scope_mutation_windows.mutation_count
                 ELSE gateway_scope_mutation_windows.mutation_count + 1
             END,
             last_membership_version = $3,
             updated_at = clock_timestamp()",
    )
    .bind(network_id)
    .bind(scope_label)
    .bind(membership_version)
    .bind(window_ms)
    .execute(&mut **tx)
    .await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT mutation_count FROM gateway_scope_mutation_windows
         WHERE network_id = $1 AND scope_label = $2",
    )
    .bind(network_id)
    .bind(scope_label)
    .fetch_one(&mut **tx)
    .await?;
    if count as u64 > config.max_membership_mutations_per_scope_per_window {
        bail!("membership mutation window limit exceeded");
    }
    Ok(())
}

pub fn mailbox_binding_key(network_id: &str, principal_id: &str) -> String {
    format!("{}:{network_id}{principal_id}", network_id.len())
}

#[allow(clippy::too_many_arguments)]
pub async fn try_acquire_delivery_owner(
    pool: &PgPool,
    network_id: &str,
    principal_id: &str,
    delivery_class: DeliveryClass,
    instance_id: &str,
    consumer_epoch: uuid::Uuid,
    owner_route: Option<&str>,
    lease: std::time::Duration,
) -> Result<bool> {
    let lease_ms = i64::try_from(lease.as_millis()).context("owner lease is too large")?;
    let result = sqlx::query(
        "INSERT INTO gateway_delivery_owners(
             binding_key, delivery_class, owner_instance_id, consumer_epoch,
             lease_expires_at, owner_route, updated_at
         ) VALUES ($1,$2,$3,$4,clock_timestamp() + ($6 * INTERVAL '1 millisecond'),$5,clock_timestamp())
         ON CONFLICT(binding_key, delivery_class) DO UPDATE SET
             owner_instance_id = EXCLUDED.owner_instance_id,
             consumer_epoch = EXCLUDED.consumer_epoch,
             lease_expires_at = EXCLUDED.lease_expires_at,
             owner_route = EXCLUDED.owner_route,
             updated_at = clock_timestamp()
         WHERE gateway_delivery_owners.lease_expires_at <= clock_timestamp()
            OR gateway_delivery_owners.consumer_epoch = EXCLUDED.consumer_epoch",
    )
    .bind(mailbox_binding_key(network_id, principal_id))
    .bind(delivery_class.as_str())
    .bind(instance_id)
    .bind(consumer_epoch)
    .bind(owner_route.unwrap_or_default())
    .bind(lease_ms)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn load_delivery_owner(
    pool: &PgPool,
    network_id: &str,
    principal_id: &str,
    delivery_class: DeliveryClass,
) -> Result<Option<DeliveryOwner>> {
    let row = sqlx::query(
        "SELECT owner_instance_id, consumer_epoch, owner_route
         FROM gateway_delivery_owners
         WHERE binding_key = $1 AND delivery_class = $2
           AND lease_expires_at > clock_timestamp()",
    )
    .bind(mailbox_binding_key(network_id, principal_id))
    .bind(delivery_class.as_str())
    .fetch_optional(pool)
    .await?;
    row.map(|row| {
        Ok(DeliveryOwner {
            instance_id: row.try_get("owner_instance_id")?,
            consumer_epoch: row.try_get("consumer_epoch")?,
            owner_route: row.try_get("owner_route")?,
        })
    })
    .transpose()
}

pub async fn release_delivery_owner(
    pool: &PgPool,
    network_id: &str,
    principal_id: &str,
    delivery_class: DeliveryClass,
    instance_id: &str,
    consumer_epoch: uuid::Uuid,
) -> Result<bool> {
    Ok(sqlx::query(
        "DELETE FROM gateway_delivery_owners
         WHERE binding_key = $1 AND delivery_class = $2
           AND owner_instance_id = $3 AND consumer_epoch = $4",
    )
    .bind(mailbox_binding_key(network_id, principal_id))
    .bind(delivery_class.as_str())
    .bind(instance_id)
    .bind(consumer_epoch)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

pub async fn authorized_scope_version_and_count(
    pool: &PgPool,
    network_id: &str,
    scope: &SwarmScope,
    principal_id: &str,
    allow_network_member_author: bool,
) -> Result<(Option<String>, u64)> {
    if let SwarmScope::Node(recipient) = scope {
        if !principal_is_admitted(pool, network_id, principal_id).await?
            || !principal_is_admitted(pool, network_id, recipient).await?
        {
            bail!("direct route author or recipient is not an active network member");
        }
        return Ok((None, 1));
    }
    let scope_label = scope.label()?;
    let author_allowed: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1
             FROM gateway_scope_memberships membership
             LEFT JOIN gateway_network_membership_grants grant_projection
               ON grant_projection.network_id = membership.network_id
              AND grant_projection.principal_id = membership.principal_id
             WHERE membership.network_id = $1
               AND (membership.scope_label = $2 OR ($4 AND membership.scope_label = 'global'))
               AND membership.principal_id = $3
               AND membership.state = 'active'
               AND (
                   grant_projection.expires_at_ms IS NULL
                   OR grant_projection.expires_at_ms >
                      (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT
               )
         )",
    )
    .bind(network_id)
    .bind(&scope_label)
    .bind(principal_id)
    .bind(allow_network_member_author)
    .fetch_one(pool)
    .await?;
    if !author_allowed {
        bail!("principal is not authorized for publish scope");
    }
    let version = sqlx::query_scalar::<_, String>(
        "SELECT active_membership_version FROM gateway_scope_versions
         WHERE network_id = $1 AND scope_label = $2",
    )
    .bind(network_id)
    .bind(&scope_label)
    .fetch_optional(pool)
    .await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM gateway_scope_memberships
         LEFT JOIN gateway_network_membership_grants grant_projection
           ON grant_projection.network_id = gateway_scope_memberships.network_id
          AND grant_projection.principal_id = gateway_scope_memberships.principal_id
         WHERE gateway_scope_memberships.network_id = $1
           AND gateway_scope_memberships.scope_label = $2
           AND gateway_scope_memberships.state = 'active'
           AND (
               grant_projection.expires_at_ms IS NULL
               OR grant_projection.expires_at_ms >
                  (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT
           )
           AND ($3::TEXT IS NULL OR gateway_scope_memberships.membership_version = $3)",
    )
    .bind(network_id)
    .bind(&scope_label)
    .bind(&version)
    .fetch_one(pool)
    .await?;
    Ok((version, count as u64))
}

pub async fn scope_contains_principal(
    pool: &PgPool,
    network_id: &str,
    scope: &SwarmScope,
    principal_id: &str,
    membership_version: Option<&str>,
) -> Result<bool> {
    if let SwarmScope::Node(recipient) = scope {
        return Ok(recipient == principal_id);
    }
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1
             FROM gateway_scope_memberships membership
             LEFT JOIN gateway_network_membership_grants grant_projection
               ON grant_projection.network_id = membership.network_id
              AND grant_projection.principal_id = membership.principal_id
             WHERE membership.network_id = $1
               AND membership.scope_label = $2
               AND membership.principal_id = $3
               AND membership.state = 'active'
               AND (
                   grant_projection.expires_at_ms IS NULL
                   OR grant_projection.expires_at_ms >
                      (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT
               )
               AND ($4::TEXT IS NULL OR membership.membership_version = $4)
         )",
    )
    .bind(network_id)
    .bind(scope.label()?)
    .bind(principal_id)
    .bind(membership_version)
    .fetch_one(pool)
    .await?)
}

#[allow(clippy::too_many_arguments)]
pub async fn acquire_global_token(
    pool: &PgPool,
    network_id: &str,
    routing_cell_id: &str,
    class: DeliveryClass,
    total_rate: u64,
    bulk_rate: u64,
    burst: u64,
    policy_version: u64,
) -> Result<bool> {
    let mut tx = pool.begin().await?;
    ensure_bucket(
        &mut tx,
        network_id,
        routing_cell_id,
        total_rate,
        bulk_rate,
        burst,
        policy_version,
    )
    .await?;
    let row = sqlx::query(
        "SELECT total_tokens, bulk_tokens,
                EXTRACT(EPOCH FROM (clock_timestamp() - last_refill_at))::DOUBLE PRECISION AS elapsed
         FROM gateway_global_rate_buckets
         WHERE network_id = $1 AND routing_cell_id = $2
         FOR UPDATE",
    )
    .bind(network_id)
    .bind(routing_cell_id)
    .fetch_one(&mut *tx)
    .await?;
    let elapsed = row.try_get::<f64, _>("elapsed")?.max(0.0);
    let total =
        (row.try_get::<f64, _>("total_tokens")? + elapsed * total_rate as f64).min(burst as f64);
    let bulk_capacity = burst.saturating_sub(1).max(1) as f64;
    let bulk =
        (row.try_get::<f64, _>("bulk_tokens")? + elapsed * bulk_rate as f64).min(bulk_capacity);
    let allowed = total >= 1.0 && (class == DeliveryClass::Interactive || bulk >= 1.0);
    sqlx::query(
        "UPDATE gateway_global_rate_buckets
         SET total_tokens = $3, bulk_tokens = $4, last_refill_at = clock_timestamp(),
             total_rate = $5, bulk_rate = $6, burst_capacity = $7,
             policy_version = $8, updated_at = clock_timestamp()
         WHERE network_id = $1 AND routing_cell_id = $2",
    )
    .bind(network_id)
    .bind(routing_cell_id)
    .bind(if allowed { total - 1.0 } else { total })
    .bind(if allowed && class == DeliveryClass::Bulk {
        bulk - 1.0
    } else {
        bulk
    })
    .bind(total_rate as f64)
    .bind(bulk_rate as f64)
    .bind(burst as f64)
    .bind(policy_version as i64)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(allowed)
}

pub async fn acquire_non_global_delivery_tokens(
    pool: &PgPool,
    network_id: &str,
    routing_cell_id: &str,
    cost: u64,
    rate: u64,
    policy_version: u64,
) -> Result<bool> {
    if cost == 0 {
        return Ok(true);
    }
    if rate == 0 || cost > rate {
        return Ok(false);
    }
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO gateway_non_global_rate_buckets(
             network_id, routing_cell_id, policy_version, tokens, last_refill_at,
             rate, burst_capacity, updated_at
         ) VALUES ($1,$2,$3,$4,clock_timestamp(),$4,$4,clock_timestamp())
         ON CONFLICT(network_id, routing_cell_id) DO NOTHING",
    )
    .bind(network_id)
    .bind(routing_cell_id)
    .bind(policy_version as i64)
    .bind(rate as f64)
    .execute(&mut *tx)
    .await?;
    let row = sqlx::query(
        "SELECT tokens,
                EXTRACT(EPOCH FROM (clock_timestamp() - last_refill_at))::DOUBLE PRECISION AS elapsed
         FROM gateway_non_global_rate_buckets
         WHERE network_id = $1 AND routing_cell_id = $2
         FOR UPDATE",
    )
    .bind(network_id)
    .bind(routing_cell_id)
    .fetch_one(&mut *tx)
    .await?;
    let available = (row.try_get::<f64, _>("tokens")?
        + row.try_get::<f64, _>("elapsed")?.max(0.0) * rate as f64)
        .min(rate as f64);
    let allowed = available >= cost as f64;
    sqlx::query(
        "UPDATE gateway_non_global_rate_buckets
         SET tokens = $3, last_refill_at = clock_timestamp(), rate = $4,
             burst_capacity = $4, policy_version = $5, updated_at = clock_timestamp()
         WHERE network_id = $1 AND routing_cell_id = $2",
    )
    .bind(network_id)
    .bind(routing_cell_id)
    .bind(if allowed {
        available - cost as f64
    } else {
        available
    })
    .bind(rate as f64)
    .bind(policy_version as i64)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(allowed)
}

#[allow(clippy::too_many_arguments)]
async fn ensure_bucket(
    tx: &mut Transaction<'_, Postgres>,
    network_id: &str,
    routing_cell_id: &str,
    total_rate: u64,
    bulk_rate: u64,
    burst: u64,
    policy_version: u64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO gateway_global_rate_buckets(
             network_id, routing_cell_id, policy_version, total_tokens, bulk_tokens,
             last_refill_at, total_rate, bulk_rate, burst_capacity, updated_at
         ) VALUES ($1, $2, $3, $4, $5, clock_timestamp(), $6, $7, $4, clock_timestamp())
         ON CONFLICT(network_id, routing_cell_id) DO NOTHING",
    )
    .bind(network_id)
    .bind(routing_cell_id)
    .bind(policy_version as i64)
    .bind(burst as f64)
    .bind(burst.saturating_sub(1).max(1) as f64)
    .bind(total_rate as f64)
    .bind(bulk_rate as f64)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
