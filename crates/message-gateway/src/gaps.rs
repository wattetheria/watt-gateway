use anyhow::Result;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use wattswarm_network_transport_core::{
    DeliveryClass, EventTransportRoute, MailboxGap, MailboxGapReason,
};

#[allow(clippy::too_many_arguments)]
pub async fn record_gap(
    pool: &PgPool,
    network_id: &str,
    principal_id: &str,
    delivery_class: DeliveryClass,
    policy_version: u64,
    route: &EventTransportRoute,
    reason: MailboxGapReason,
    affected_at_ms: u64,
) -> Result<String> {
    let gap_id = compressed_gap_id(
        network_id,
        principal_id,
        delivery_class,
        policy_version,
        route,
        reason,
        affected_at_ms / 3_600_000,
    )?;
    let affected_at =
        DateTime::from_timestamp_millis(affected_at_ms as i64).unwrap_or_else(Utc::now);
    sqlx::query(
        "INSERT INTO gateway_mailbox_gaps(
             network_id, principal_id, gap_id, delivery_class, delivery_policy_version, route_json,
             reason, first_affected_at, last_affected_at, approximate_count
         ) VALUES ($1, $2, $3::uuid, $4, $5, $6, $7, $8, $8, 1)
         ON CONFLICT(network_id, principal_id, gap_id) DO UPDATE SET
             last_affected_at = GREATEST(gateway_mailbox_gaps.last_affected_at, excluded.last_affected_at),
             approximate_count = gateway_mailbox_gaps.approximate_count + 1",
    )
    .bind(network_id)
    .bind(principal_id)
    .bind(&gap_id)
    .bind(delivery_class.as_str())
    .bind(policy_version as i64)
    .bind(serde_json::to_value(route)?)
    .bind(reason_label(reason))
    .bind(affected_at)
    .execute(pool)
    .await?;
    Ok(gap_id)
}

pub async fn load_for_page(
    pool: &PgPool,
    network_id: &str,
    principal_id: &str,
    delivery_class: DeliveryClass,
    page_id: &str,
    limit: usize,
    redelivery_after: std::time::Duration,
) -> Result<Vec<MailboxGap>> {
    let redelivery_after_ms = i64::try_from(redelivery_after.as_millis())?;
    let rows = sqlx::query(
        "SELECT gap_id, delivery_policy_version, route_json, reason,
                first_affected_at, last_affected_at, approximate_count
         FROM gateway_mailbox_gaps
         WHERE network_id = $1 AND principal_id = $2 AND delivery_class = $3
           AND acknowledged_at IS NULL
           AND (delivery_page_id IS NULL OR delivery_page_id = $4
                OR delivered_at <= clock_timestamp() - ($6::BIGINT * INTERVAL '1 millisecond'))
         ORDER BY first_affected_at, gap_id
         LIMIT $5",
    )
    .bind(network_id)
    .bind(principal_id)
    .bind(delivery_class.as_str())
    .bind(page_id)
    .bind(limit as i64)
    .bind(redelivery_after_ms)
    .fetch_all(pool)
    .await?;
    if !rows.is_empty() {
        sqlx::query(
            "UPDATE gateway_mailbox_gaps
             SET delivery_page_id = $4, delivered_at = clock_timestamp()
             WHERE network_id = $1 AND principal_id = $2 AND delivery_class = $3
               AND acknowledged_at IS NULL AND gap_id = ANY($5)",
        )
        .bind(network_id)
        .bind(principal_id)
        .bind(delivery_class.as_str())
        .bind(page_id)
        .bind(
            rows.iter()
                .map(|row| row.get::<uuid::Uuid, _>("gap_id"))
                .collect::<Vec<_>>(),
        )
        .execute(pool)
        .await?;
    }
    rows.into_iter()
        .map(|row| {
            let first: DateTime<Utc> = row.try_get("first_affected_at")?;
            let last: DateTime<Utc> = row.try_get("last_affected_at")?;
            let reason: String = row.try_get("reason")?;
            Ok(MailboxGap {
                gap_id: row.get::<uuid::Uuid, _>("gap_id").to_string(),
                delivery_class,
                delivery_policy_version: row.get::<i64, _>("delivery_policy_version") as u64,
                route: serde_json::from_value(row.try_get("route_json")?)?,
                reason: parse_reason(&reason)?,
                first_affected_at: first.timestamp_millis() as u64,
                last_affected_at: last.timestamp_millis() as u64,
                approximate_count: row.get::<i64, _>("approximate_count") as u64,
            })
        })
        .collect()
}

pub async fn acknowledge_page(
    pool: &PgPool,
    network_id: &str,
    principal_id: &str,
    delivery_class: DeliveryClass,
    page_id: &str,
) -> Result<u64> {
    Ok(sqlx::query(
        "UPDATE gateway_mailbox_gaps
         SET acknowledged_at = clock_timestamp()
         WHERE network_id = $1 AND principal_id = $2 AND delivery_class = $3
           AND delivery_page_id = $4 AND acknowledged_at IS NULL",
    )
    .bind(network_id)
    .bind(principal_id)
    .bind(delivery_class.as_str())
    .bind(page_id)
    .execute(pool)
    .await?
    .rows_affected())
}

fn compressed_gap_id(
    network_id: &str,
    principal_id: &str,
    class: DeliveryClass,
    policy_version: u64,
    route: &EventTransportRoute,
    reason: MailboxGapReason,
    hour_bucket: u64,
) -> Result<String> {
    let digest = Sha256::digest(serde_json::to_vec(&(
        network_id,
        principal_id,
        class,
        policy_version,
        route,
        reason,
        hour_bucket,
    ))?);
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Ok(uuid::Uuid::from_bytes(bytes).to_string())
}

fn reason_label(reason: MailboxGapReason) -> &'static str {
    match reason {
        MailboxGapReason::Expired => "expired",
        MailboxGapReason::DeliveryLimitExceeded => "delivery_limit_exceeded",
        MailboxGapReason::AdministrativeRemoval => "administrative_removal",
    }
}

fn parse_reason(reason: &str) -> Result<MailboxGapReason> {
    Ok(match reason {
        "expired" => MailboxGapReason::Expired,
        "delivery_limit_exceeded" => MailboxGapReason::DeliveryLimitExceeded,
        "administrative_removal" => MailboxGapReason::AdministrativeRemoval,
        _ => anyhow::bail!("invalid stored MailboxGap reason"),
    })
}
