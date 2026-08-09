use crate::config::Config;
use crate::rabbit::RabbitAdapter;
use anyhow::Result;
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use wattswarm_network_transport_core::{DeliveryClass, PropagationLane, SwarmScope};

#[derive(Clone, Default)]
pub struct GatewayObservability {
    state: Arc<Mutex<RuntimeState>>,
}

#[derive(Debug, Default)]
struct RuntimeState {
    started_at: u64,
    sessions_accepted: u64,
    sessions_rejected: u64,
    duplicate_publishes_suppressed: u64,
    publish_nacks: u64,
    publish_unroutable: u64,
    publish_errors: u64,
    binding_attempts: u64,
    binding_failures: u64,
    membership_updates: u64,
    membership_update_failures: u64,
    old_membership_version_rejections: u64,
    global_backpressure: u64,
    non_global_backpressure: u64,
    postgres_fail_closed: u64,
    delivery_pages: u64,
    recipient_deliveries: u64,
    mailbox_deliveries_pulled: u64,
    redeliveries: u64,
    local_commits: u64,
    forwarded_commits: u64,
    commit_forward_failures: u64,
    owner_lost_requeues: u64,
    dead_letters: u64,
    dead_letter_bytes: u64,
    expired_dead_letters: u64,
    delivery_limit_dead_letters: u64,
    confirm_latency: LatencySamples,
    delivery_page_latency: LatencySamples,
    commit_latency: LatencySamples,
    binding_latency: LatencySamples,
    membership_binding_latency: LatencySamples,
    global_token_acquire_latency: LatencySamples,
    non_global_token_acquire_latency: LatencySamples,
    fanout: BTreeMap<String, FanoutRuntime>,
}

#[derive(Debug, Default)]
struct LatencySamples {
    count: u64,
    total_ms: u64,
    max_ms: u64,
    samples_ms: Vec<u64>,
}

#[derive(Debug, Default)]
struct FanoutRuntime {
    publishes: u64,
    expected_recipients: u64,
    recipient_deliveries: u64,
    confirm_latency: LatencySamples,
}

#[derive(Debug, Clone, Serialize)]
pub struct LatencySnapshot {
    pub count: u64,
    pub average_ms: u64,
    pub max_ms: u64,
    pub p50_ms: u64,
    pub p95_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct FanoutSnapshot {
    pub publishes: u64,
    pub expected_recipients: u64,
    pub recipient_deliveries: u64,
    pub confirm_latency: LatencySnapshot,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeSnapshot {
    pub started_at: u64,
    pub sessions_accepted: u64,
    pub sessions_rejected: u64,
    pub duplicate_publishes_suppressed: u64,
    pub publish_nacks: u64,
    pub publish_unroutable: u64,
    pub publish_errors: u64,
    pub binding_attempts: u64,
    pub binding_failures: u64,
    pub membership_updates: u64,
    pub membership_update_failures: u64,
    pub old_membership_version_rejections: u64,
    pub global_backpressure: u64,
    pub non_global_backpressure: u64,
    pub postgres_fail_closed: u64,
    pub delivery_pages: u64,
    pub recipient_deliveries: u64,
    pub recipient_deliveries_per_second: f64,
    pub mailbox_deliveries_pulled: u64,
    pub redeliveries: u64,
    pub local_commits: u64,
    pub forwarded_commits: u64,
    pub commit_forward_failures: u64,
    pub owner_lost_requeues: u64,
    pub dead_letters: u64,
    pub dead_letter_bytes: u64,
    pub expired_dead_letters: u64,
    pub delivery_limit_dead_letters: u64,
    pub confirm_latency: LatencySnapshot,
    pub delivery_page_latency: LatencySnapshot,
    pub commit_latency: LatencySnapshot,
    pub binding_latency: LatencySnapshot,
    pub membership_binding_latency: LatencySnapshot,
    pub global_token_acquire_latency: LatencySnapshot,
    pub non_global_token_acquire_latency: LatencySnapshot,
    pub fanout_by_network_scope_lane: BTreeMap<String, FanoutSnapshot>,
}

impl LatencySamples {
    fn observe(&mut self, elapsed: Duration) {
        let millis = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        self.count = self.count.saturating_add(1);
        self.total_ms = self.total_ms.saturating_add(millis);
        self.max_ms = self.max_ms.max(millis);
        if self.samples_ms.len() == 512 {
            self.samples_ms.remove(0);
        }
        self.samples_ms.push(millis);
    }

    fn snapshot(&self) -> LatencySnapshot {
        let mut samples = self.samples_ms.clone();
        samples.sort_unstable();
        LatencySnapshot {
            count: self.count,
            average_ms: self.total_ms.checked_div(self.count).unwrap_or_default(),
            max_ms: self.max_ms,
            p50_ms: percentile(&samples, 50),
            p95_ms: percentile(&samples, 95),
        }
    }
}

impl GatewayObservability {
    pub fn new() -> Self {
        let result = Self::default();
        result.with_state(|state| state.started_at = now_ms());
        result
    }

    pub fn record_session(&self, accepted: bool) {
        self.with_state(|state| {
            if accepted {
                state.sessions_accepted = state.sessions_accepted.saturating_add(1);
            } else {
                state.sessions_rejected = state.sessions_rejected.saturating_add(1);
            }
        });
    }

    pub fn record_duplicate_publish(&self) {
        self.with_state(|state| {
            state.duplicate_publishes_suppressed =
                state.duplicate_publishes_suppressed.saturating_add(1);
        });
    }

    pub fn record_publish_confirm(
        &self,
        network_id: &str,
        scope: &SwarmScope,
        lane: PropagationLane,
        expected_recipients: u64,
        started: Instant,
        outcome: PublishConfirmOutcome,
    ) {
        self.with_state(|state| {
            let elapsed = started.elapsed();
            state.confirm_latency.observe(elapsed);
            match outcome {
                PublishConfirmOutcome::Confirmed => {}
                PublishConfirmOutcome::Nack => {
                    state.publish_nacks = state.publish_nacks.saturating_add(1)
                }
                PublishConfirmOutcome::Unroutable => {
                    state.publish_unroutable = state.publish_unroutable.saturating_add(1);
                }
                PublishConfirmOutcome::Error => {
                    state.publish_errors = state.publish_errors.saturating_add(1);
                }
            }
            let key = format!(
                "{network_id}|{}|{}",
                scope.label().unwrap_or_else(|_| "invalid".to_owned()),
                lane.as_str()
            );
            let fanout = state.fanout.entry(key).or_default();
            fanout.publishes = fanout.publishes.saturating_add(1);
            fanout.expected_recipients = fanout
                .expected_recipients
                .saturating_add(expected_recipients);
            if outcome == PublishConfirmOutcome::Confirmed {
                fanout.recipient_deliveries = fanout
                    .recipient_deliveries
                    .saturating_add(expected_recipients);
                state.recipient_deliveries = state
                    .recipient_deliveries
                    .saturating_add(expected_recipients);
            }
            fanout.confirm_latency.observe(elapsed);
        });
    }

    pub fn record_binding(&self, started: Instant, success: bool) {
        self.with_state(|state| {
            state.binding_attempts = state.binding_attempts.saturating_add(1);
            state.binding_latency.observe(started.elapsed());
            if !success {
                state.binding_failures = state.binding_failures.saturating_add(1);
            }
        });
    }

    pub fn record_membership_update(&self, started: Instant, success: bool) {
        self.with_state(|state| {
            state.membership_binding_latency.observe(started.elapsed());
            if success {
                state.membership_updates = state.membership_updates.saturating_add(1);
            } else {
                state.membership_update_failures =
                    state.membership_update_failures.saturating_add(1);
            }
        });
    }

    pub fn record_old_membership_version_rejection(&self) {
        self.with_state(|state| {
            state.old_membership_version_rejections =
                state.old_membership_version_rejections.saturating_add(1);
        });
    }

    pub fn record_backpressure(&self, global: bool) {
        self.with_state(|state| {
            if global {
                state.global_backpressure = state.global_backpressure.saturating_add(1);
            } else {
                state.non_global_backpressure = state.non_global_backpressure.saturating_add(1);
            }
        });
    }

    pub fn record_postgres_fail_closed(&self) {
        self.with_state(|state| {
            state.postgres_fail_closed = state.postgres_fail_closed.saturating_add(1);
        });
    }

    pub fn record_token_bucket_acquire(&self, started: Instant, global: bool) {
        self.with_state(|state| {
            if global {
                state
                    .global_token_acquire_latency
                    .observe(started.elapsed());
            } else {
                state
                    .non_global_token_acquire_latency
                    .observe(started.elapsed());
            }
        });
    }

    pub fn record_delivery_page(&self, started: Instant, deliveries: u64, redeliveries: u64) {
        self.with_state(|state| {
            state.delivery_pages = state.delivery_pages.saturating_add(1);
            state.redeliveries = state.redeliveries.saturating_add(redeliveries);
            state.delivery_page_latency.observe(started.elapsed());
            state.mailbox_deliveries_pulled =
                state.mailbox_deliveries_pulled.saturating_add(deliveries);
        });
    }

    pub fn record_commit(&self, started: Instant, forwarded: bool, success: bool) {
        self.with_state(|state| {
            state.commit_latency.observe(started.elapsed());
            if forwarded {
                state.forwarded_commits = state.forwarded_commits.saturating_add(1);
                if !success {
                    state.commit_forward_failures = state.commit_forward_failures.saturating_add(1);
                }
            } else if success {
                state.local_commits = state.local_commits.saturating_add(1);
            }
        });
    }

    pub fn record_owner_lost_requeue(&self, count: u64) {
        self.with_state(|state| {
            state.owner_lost_requeues = state.owner_lost_requeues.saturating_add(count);
        });
    }

    pub fn record_dead_letter(&self, bytes: u64, expired: bool) {
        self.with_state(|state| {
            state.dead_letters = state.dead_letters.saturating_add(1);
            state.dead_letter_bytes = state.dead_letter_bytes.saturating_add(bytes);
            if expired {
                state.expired_dead_letters = state.expired_dead_letters.saturating_add(1);
            } else {
                state.delivery_limit_dead_letters =
                    state.delivery_limit_dead_letters.saturating_add(1);
            }
        });
    }

    pub fn snapshot(&self) -> RuntimeSnapshot {
        self.with_state(|state| {
            let elapsed_seconds = now_ms().saturating_sub(state.started_at).max(1) as f64 / 1_000.0;
            RuntimeSnapshot {
                started_at: state.started_at,
                sessions_accepted: state.sessions_accepted,
                sessions_rejected: state.sessions_rejected,
                duplicate_publishes_suppressed: state.duplicate_publishes_suppressed,
                publish_nacks: state.publish_nacks,
                publish_unroutable: state.publish_unroutable,
                publish_errors: state.publish_errors,
                binding_attempts: state.binding_attempts,
                binding_failures: state.binding_failures,
                membership_updates: state.membership_updates,
                membership_update_failures: state.membership_update_failures,
                old_membership_version_rejections: state.old_membership_version_rejections,
                global_backpressure: state.global_backpressure,
                non_global_backpressure: state.non_global_backpressure,
                postgres_fail_closed: state.postgres_fail_closed,
                delivery_pages: state.delivery_pages,
                recipient_deliveries: state.recipient_deliveries,
                recipient_deliveries_per_second: state.recipient_deliveries as f64
                    / elapsed_seconds,
                mailbox_deliveries_pulled: state.mailbox_deliveries_pulled,
                redeliveries: state.redeliveries,
                local_commits: state.local_commits,
                forwarded_commits: state.forwarded_commits,
                commit_forward_failures: state.commit_forward_failures,
                owner_lost_requeues: state.owner_lost_requeues,
                dead_letters: state.dead_letters,
                dead_letter_bytes: state.dead_letter_bytes,
                expired_dead_letters: state.expired_dead_letters,
                delivery_limit_dead_letters: state.delivery_limit_dead_letters,
                confirm_latency: state.confirm_latency.snapshot(),
                delivery_page_latency: state.delivery_page_latency.snapshot(),
                commit_latency: state.commit_latency.snapshot(),
                binding_latency: state.binding_latency.snapshot(),
                membership_binding_latency: state.membership_binding_latency.snapshot(),
                global_token_acquire_latency: state.global_token_acquire_latency.snapshot(),
                non_global_token_acquire_latency: state.non_global_token_acquire_latency.snapshot(),
                fanout_by_network_scope_lane: state
                    .fanout
                    .iter()
                    .map(|(key, value)| {
                        (
                            key.clone(),
                            FanoutSnapshot {
                                publishes: value.publishes,
                                expected_recipients: value.expected_recipients,
                                recipient_deliveries: value.recipient_deliveries,
                                confirm_latency: value.confirm_latency.snapshot(),
                            },
                        )
                    })
                    .collect(),
            }
        })
    }

    fn with_state<T>(&self, action: impl FnOnce(&mut RuntimeState) -> T) -> T {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        action(&mut state)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishConfirmOutcome {
    Confirmed,
    Nack,
    Unroutable,
    Error,
}

pub async fn operational_snapshot(
    pool: &PgPool,
    config: &Config,
    rabbit: &RabbitAdapter,
    network_id: &str,
) -> Result<Value> {
    let principals = sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT principal_id FROM gateway_scope_memberships
         WHERE network_id = $1 AND scope_label = 'global' AND state = 'active'
         ORDER BY principal_id",
    )
    .bind(network_id)
    .fetch_all(pool)
    .await?;
    let active_tenants = principals.len() as u64;
    let mailbox = rabbit
        .mailbox_runtime_snapshot(network_id, &principals)
        .await?;
    let observed_mailbox_queues = mailbox.observed_mailbox_queues;
    let session_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM gateway_sessions
         WHERE network_id = $1 AND expires_at > clock_timestamp()",
    )
    .bind(network_id)
    .fetch_one(pool)
    .await?;
    let owners = delivery_owners(pool, network_id, &principals).await?;
    let membership = membership_snapshot(pool, network_id).await?;
    let tokens = token_snapshot(pool, network_id).await?;
    let gaps = gap_snapshot(pool, network_id).await?;
    let receipt = receipt_snapshot(pool, network_id).await?;
    let admitted_queue_limit = config
        .cluster_queue_limit
        .saturating_mul(config.mailbox_shard_admission_percent)
        / 100;
    let configured_mailbox_queues = active_tenants.saturating_mul(2);
    Ok(json!({
        "backend": "client_server",
        "component": "gateway",
        "network_id": network_id,
        "updated_at": now_ms(),
        "gateway_session": {
            "active_sessions": session_count.max(0),
        },
        "runtime": rabbit.observability().snapshot(),
        "mailbox": mailbox,
        "owners": owners,
        "cell": {
            "routing_cell_id": "cell-0",
            "active_tenants": active_tenants,
            "interactive_mailbox_queues": active_tenants,
            "bulk_mailbox_queues": active_tenants,
            "configured_mailbox_queues": configured_mailbox_queues,
            "observed_mailbox_queues": observed_mailbox_queues,
            "cluster_queue_limit": config.cluster_queue_limit,
            "admitted_queue_limit": admitted_queue_limit,
            "admission_utilization_percent": configured_mailbox_queues
                .saturating_add(16)
                .saturating_mul(100)
                .checked_div(admitted_queue_limit)
                .unwrap_or(u64::MAX),
            "new_cell_required": configured_mailbox_queues.saturating_add(16) >= admitted_queue_limit,
        },
        "membership": membership,
        "shared_token_buckets": tokens,
        "history_integrity": gaps,
        "publish_receipts": receipt,
    }))
}

async fn delivery_owners(
    pool: &PgPool,
    network_id: &str,
    principals: &[String],
) -> Result<Vec<Value>> {
    let mut result = Vec::new();
    for principal in principals {
        for class in DeliveryClass::ALL {
            if let Some(owner) =
                crate::db::load_delivery_owner(pool, network_id, principal, class).await?
            {
                result.push(json!({
                    "principal_id": principal,
                    "delivery_class": class,
                    "owner_instance_id": owner.instance_id,
                    "consumer_epoch": owner.consumer_epoch,
                    "owner_route_configured": !owner.owner_route.is_empty(),
                }));
            }
        }
    }
    Ok(result)
}

async fn membership_snapshot(pool: &PgPool, network_id: &str) -> Result<Value> {
    let row = sqlx::query(
        "SELECT
             COUNT(*) FILTER (WHERE state = 'active') AS active_memberships,
             COUNT(*) FILTER (WHERE state = 'active' AND
                 (interactive_binding_state <> 'active' OR bulk_binding_state <> 'active')) AS binding_drift,
             COALESCE(MAX((EXTRACT(EPOCH FROM (clock_timestamp() - binding_updated_at)) * 1000)::DOUBLE PRECISION)
                 FILTER (WHERE state = 'active'), 0::DOUBLE PRECISION) AS oldest_binding_age_ms
         FROM gateway_scope_memberships WHERE network_id = $1",
    )
    .bind(network_id)
    .fetch_one(pool)
    .await?;
    let version_drift: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM gateway_scope_route_bindings binding
         JOIN gateway_scope_versions version USING(network_id, scope_label)
         WHERE binding.network_id = $1 AND binding.binding_state = 'active'
           AND binding.membership_version <> version.active_membership_version",
    )
    .bind(network_id)
    .fetch_one(pool)
    .await?;
    Ok(json!({
        "active_memberships": row.try_get::<i64, _>("active_memberships")?.max(0),
        "binding_drift": row.try_get::<i64, _>("binding_drift")?.max(0),
        "version_drift": version_drift.max(0),
        "oldest_binding_age_ms": row.try_get::<f64, _>("oldest_binding_age_ms")?.max(0.0) as u64,
    }))
}

async fn token_snapshot(pool: &PgPool, network_id: &str) -> Result<Value> {
    let global = sqlx::query(
        "SELECT total_tokens, bulk_tokens, total_rate, bulk_rate, burst_capacity,
                (EXTRACT(EPOCH FROM (clock_timestamp() - last_refill_at)) * 1000)::DOUBLE PRECISION AS refill_lag_ms
         FROM gateway_global_rate_buckets WHERE network_id = $1 AND routing_cell_id = 'cell-0'",
    )
    .bind(network_id)
    .fetch_optional(pool)
    .await?;
    let non_global = sqlx::query(
        "SELECT tokens, rate, burst_capacity,
                (EXTRACT(EPOCH FROM (clock_timestamp() - last_refill_at)) * 1000)::DOUBLE PRECISION AS refill_lag_ms
         FROM gateway_non_global_rate_buckets WHERE network_id = $1 AND routing_cell_id = 'cell-0'",
    )
    .bind(network_id)
    .fetch_optional(pool)
    .await?;
    Ok(json!({
        "global": global.map(|row| json!({
            "total_tokens": row.get::<f64, _>("total_tokens"),
            "bulk_tokens": row.get::<f64, _>("bulk_tokens"),
            "total_rate": row.get::<f64, _>("total_rate"),
            "bulk_rate": row.get::<f64, _>("bulk_rate"),
            "interactive_reserved_rate": row.get::<f64, _>("total_rate") - row.get::<f64, _>("bulk_rate"),
            "burst_capacity": row.get::<f64, _>("burst_capacity"),
            "refill_lag_ms": row.get::<f64, _>("refill_lag_ms").max(0.0) as u64,
        })),
        "non_global": non_global.map(|row| json!({
            "tokens": row.get::<f64, _>("tokens"),
            "rate": row.get::<f64, _>("rate"),
            "burst_capacity": row.get::<f64, _>("burst_capacity"),
            "refill_lag_ms": row.get::<f64, _>("refill_lag_ms").max(0.0) as u64,
        })),
    }))
}

async fn gap_snapshot(pool: &PgPool, network_id: &str) -> Result<Value> {
    let row = sqlx::query(
        "SELECT
             COUNT(*) FILTER (WHERE acknowledged_at IS NULL) AS pending_gaps,
             COALESCE(SUM(approximate_count) FILTER (WHERE acknowledged_at IS NULL), 0)::BIGINT AS pending_gap_records,
             COALESCE(SUM(approximate_count) FILTER (WHERE reason = 'expired'), 0)::BIGINT AS expired_records,
             COALESCE(SUM(approximate_count) FILTER (WHERE reason <> 'expired'), 0)::BIGINT AS overflow_or_delivery_limit_records,
             COALESCE(MAX((EXTRACT(EPOCH FROM (clock_timestamp() - first_affected_at)) * 1000)::DOUBLE PRECISION)
                 FILTER (WHERE acknowledged_at IS NULL), 0::DOUBLE PRECISION) AS oldest_pending_gap_age_ms
         FROM gateway_mailbox_gaps WHERE network_id = $1",
    )
    .bind(network_id)
    .fetch_one(pool)
    .await?;
    Ok(json!({
        "pending_gaps": row.try_get::<i64, _>("pending_gaps")?.max(0),
        "pending_gap_records": row.try_get::<i64, _>("pending_gap_records")?.max(0),
        "expired_records": row.try_get::<i64, _>("expired_records")?.max(0),
        "overflow_or_delivery_limit_records": row.try_get::<i64, _>("overflow_or_delivery_limit_records")?.max(0),
        "oldest_pending_gap_age_ms": row.try_get::<f64, _>("oldest_pending_gap_age_ms")?.max(0.0) as u64,
        "history_unavailable": row.try_get::<i64, _>("pending_gap_records")? > 0,
    }))
}

async fn receipt_snapshot(pool: &PgPool, network_id: &str) -> Result<Value> {
    let row = sqlx::query(
        "SELECT COUNT(*) AS confirmed_publishes,
                COALESCE(SUM(expected_recipients), 0)::BIGINT AS expected_recipient_deliveries
         FROM gateway_publish_receipts
         WHERE network_id = $1 AND publish_status = 'confirmed' AND expires_at > clock_timestamp()",
    )
    .bind(network_id)
    .fetch_one(pool)
    .await?;
    Ok(json!({
        "confirmed_publishes": row.try_get::<i64, _>("confirmed_publishes")?.max(0),
        "expected_recipient_deliveries": row.try_get::<i64, _>("expected_recipient_deliveries")?.max(0),
    }))
}

fn percentile(samples: &[u64], percentile: usize) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let index = (samples.len().saturating_sub(1)).saturating_mul(percentile) / 100;
    samples[index]
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_snapshot_contains_latency_percentiles_without_sensitive_data() {
        let metrics = GatewayObservability::new();
        metrics.record_session(true);
        metrics.record_publish_confirm(
            "network-a",
            &SwarmScope::Group("group-a".to_owned()),
            PropagationLane::Messages,
            3,
            Instant::now(),
            PublishConfirmOutcome::Confirmed,
        );
        metrics.record_duplicate_publish();
        metrics.record_token_bucket_acquire(Instant::now(), true);
        let value = serde_json::to_value(metrics.snapshot()).unwrap();
        assert_eq!(value["sessions_accepted"], 1);
        assert_eq!(value["duplicate_publishes_suppressed"], 1);
        assert_eq!(value["recipient_deliveries"], 3);
        assert_eq!(value["confirm_latency"]["count"], 1);
        assert_eq!(value["global_token_acquire_latency"]["count"], 1);
        let encoded = value.to_string();
        assert!(!encoded.contains("payload"));
        assert!(!encoded.contains("session_token"));
        assert!(!encoded.contains("commit_token"));
        assert!(!encoded.contains("password"));
    }
}
