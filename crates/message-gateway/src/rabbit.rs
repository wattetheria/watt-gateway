use crate::config::Config;
use crate::observability::{GatewayObservability, PublishConfirmOutcome};
use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use lapin::options::{
    BasicAckOptions, BasicCancelOptions, BasicConsumeOptions, BasicGetOptions, BasicPublishOptions,
    BasicQosOptions, ConfirmSelectOptions, ExchangeDeclareOptions, QueueBindOptions,
    QueueDeclareOptions,
};
use lapin::types::{AMQPValue, FieldTable, LongString};
use lapin::{
    BasicProperties, Channel, Connection, ConnectionProperties, ExchangeKind, message::Delivery,
    publisher_confirm::Confirmation, tcp::OwnedTLSConfig,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use wattswarm_network_transport_core::{
    DeliveryClass, EventTransportRoute, MailboxBinding, MailboxControlDelivery, MailboxDelivery,
    MailboxGapReason, OpaqueSignedRecord, stable_delivery_id,
};

const DIRECT_INTERACTIVE: &str = "wattswarm.cs.direct.interactive.v1";
const DIRECT_BULK: &str = "wattswarm.cs.direct.bulk.v1";
const SCOPE_INTERACTIVE: &str = "wattswarm.cs.scope.interactive.v1";
const SCOPE_BULK: &str = "wattswarm.cs.scope.bulk.v1";
const DEAD_LETTER_EXCHANGE: &str = "wattswarm.cs.dlx.v1";
const DEAD_LETTER_QUEUE: &str = "wattswarm.cs.dlq.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerRecord {
    pub network_id: String,
    pub record_id: String,
    pub source_principal_id: String,
    pub route: EventTransportRoute,
    pub record: OpaqueSignedRecord,
    pub membership_version: Option<String>,
    pub delivery_class: DeliveryClass,
    pub delivery_policy_version: u64,
    pub enqueued_at: u64,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerControlRecord {
    pub network_id: String,
    pub correlation_id: String,
    pub source_principal_id: String,
    pub target_principal_id: String,
    pub control_kind: String,
    pub payload: OpaqueSignedRecord,
    pub gap_route: EventTransportRoute,
    pub delivery_policy_version: u64,
    pub enqueued_at: u64,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "envelope_type", content = "body", rename_all = "snake_case")]
enum BrokerEnvelope {
    Record(BrokerRecord),
    Control(BrokerControlRecord),
}

pub struct PulledPage {
    pub page_id: String,
    pub binding: MailboxBinding,
    pub deliveries: Vec<MailboxDelivery>,
    pub controls: Vec<MailboxControlDelivery>,
    pub consumer_epoch: Uuid,
}

struct PendingPage {
    channel: Channel,
    delivery_tags: Vec<u64>,
    network_id: String,
    principal_id: String,
    delivery_class: DeliveryClass,
    consumer_epoch: Uuid,
    opened_at: tokio::time::Instant,
    oldest_enqueued_at: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MailboxQueueSnapshot {
    pub principal_id: String,
    pub delivery_class: DeliveryClass,
    pub ready_messages: u32,
    pub consumers: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct PendingMailboxPageSnapshot {
    pub principal_id: String,
    pub delivery_class: DeliveryClass,
    pub consumer_epoch: Uuid,
    pub unacked_messages: u64,
    pub oldest_unacked_age_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MailboxRuntimeSnapshot {
    pub observed_mailbox_queues: u64,
    pub missing_mailbox_queues: u64,
    pub ready_messages: u64,
    pub unacked_messages: u64,
    pub redeliveries: u64,
    pub oldest_unacked_age_ms: u64,
    pub dead_letter_ready_messages: u32,
    pub dead_letter_recorded_bytes: u64,
    pub queues: Vec<MailboxQueueSnapshot>,
    pub pending_pages: Vec<PendingMailboxPageSnapshot>,
}

#[derive(Clone)]
pub struct RabbitAdapter {
    connection: Arc<Connection>,
    config: Arc<Config>,
    pending_pages: Arc<Mutex<HashMap<String, PendingPage>>>,
    observability: GatewayObservability,
}

impl RabbitAdapter {
    pub async fn connect(config: Arc<Config>) -> Result<Self> {
        let (endpoint, tls_config) = endpoint_with_credentials(&config)?;
        let connection =
            Connection::connect_with_config(&endpoint, ConnectionProperties::default(), tls_config)
                .await
                .context("connect RabbitMQ")?;
        let adapter = Self {
            connection: Arc::new(connection),
            config,
            pending_pages: Arc::new(Mutex::new(HashMap::new())),
            observability: GatewayObservability::new(),
        };
        adapter.declare_infrastructure().await?;
        Ok(adapter)
    }

    async fn declare_infrastructure(&self) -> Result<()> {
        let channel = self.connection.create_channel().await?;
        channel
            .confirm_select(ConfirmSelectOptions::default())
            .await?;
        for (name, kind) in [
            (DIRECT_INTERACTIVE, ExchangeKind::Direct),
            (DIRECT_BULK, ExchangeKind::Direct),
            (SCOPE_INTERACTIVE, ExchangeKind::Topic),
            (SCOPE_BULK, ExchangeKind::Topic),
            (DEAD_LETTER_EXCHANGE, ExchangeKind::Fanout),
        ] {
            channel
                .exchange_declare(
                    name,
                    kind,
                    ExchangeDeclareOptions {
                        durable: true,
                        ..Default::default()
                    },
                    FieldTable::default(),
                )
                .await?;
        }
        let mut dead_letter_args = FieldTable::default();
        dead_letter_args.insert(
            "x-queue-type".into(),
            AMQPValue::LongString(LongString::from("quorum")),
        );
        dead_letter_args.insert(
            "x-max-length-bytes".into(),
            AMQPValue::LongLongInt(self.config.dead_letter_max_length_bytes as i64),
        );
        dead_letter_args.insert(
            "x-overflow".into(),
            AMQPValue::LongString(LongString::from("reject-publish")),
        );
        channel
            .queue_declare(
                DEAD_LETTER_QUEUE,
                QueueDeclareOptions {
                    durable: true,
                    ..Default::default()
                },
                dead_letter_args,
            )
            .await?;
        channel
            .queue_bind(
                DEAD_LETTER_QUEUE,
                DEAD_LETTER_EXCHANGE,
                "",
                QueueBindOptions::default(),
                FieldTable::default(),
            )
            .await?;
        Ok(())
    }

    pub async fn ensure_tenant_mailboxes(
        &self,
        network_id: &str,
        principal_id: &str,
    ) -> Result<()> {
        let started = std::time::Instant::now();
        let result = async {
            let channel = self.connection.create_channel().await?;
            for class in DeliveryClass::ALL {
                let queue = queue_name(network_id, principal_id, class);
                channel
                    .queue_declare(
                        &queue,
                        QueueDeclareOptions {
                            durable: true,
                            ..Default::default()
                        },
                        mailbox_arguments(&self.config),
                    )
                    .await?;
                channel
                    .queue_bind(
                        &queue,
                        direct_exchange(class),
                        &direct_route_key(network_id, principal_id),
                        QueueBindOptions::default(),
                        FieldTable::default(),
                    )
                    .await?;
            }
            Ok(())
        }
        .await;
        self.observability.record_binding(started, result.is_ok());
        result
    }

    pub async fn bind_scope_member(
        &self,
        network_id: &str,
        principal_id: &str,
        route_address: &str,
        membership_version: &str,
    ) -> Result<()> {
        let started = std::time::Instant::now();
        let result = async {
            self.ensure_tenant_mailboxes(network_id, principal_id)
                .await?;
            let channel = self.connection.create_channel().await?;
            for class in DeliveryClass::ALL {
                channel
                    .queue_bind(
                        &queue_name(network_id, principal_id, class),
                        scope_exchange(class),
                        &scope_route_key(network_id, route_address, membership_version),
                        QueueBindOptions::default(),
                        FieldTable::default(),
                    )
                    .await?;
            }
            Ok(())
        }
        .await;
        self.observability.record_binding(started, result.is_ok());
        result
    }

    pub async fn unbind_scope_member(
        &self,
        network_id: &str,
        principal_id: &str,
        route_address: &str,
        membership_version: &str,
    ) -> Result<()> {
        let started = std::time::Instant::now();
        let result = async {
            let channel = self.connection.create_channel().await?;
            for class in DeliveryClass::ALL {
                channel
                    .queue_unbind(
                        &queue_name(network_id, principal_id, class),
                        scope_exchange(class),
                        &scope_route_key(network_id, route_address, membership_version),
                        FieldTable::default(),
                    )
                    .await?;
            }
            Ok(())
        }
        .await;
        self.observability.record_binding(started, result.is_ok());
        result
    }

    pub async fn publish(
        &self,
        recipient: Option<&str>,
        broker_record: &BrokerRecord,
    ) -> Result<()> {
        let channel = self.connection.create_channel().await?;
        channel
            .confirm_select(ConfirmSelectOptions::default())
            .await?;
        let (exchange, key) = if let Some(recipient) = recipient {
            self.ensure_tenant_mailboxes(&broker_record.network_id, recipient)
                .await?;
            (
                direct_exchange(broker_record.delivery_class),
                direct_route_key(&broker_record.network_id, recipient),
            )
        } else {
            let membership_version = broker_record
                .membership_version
                .as_deref()
                .context("shared-scope publish is missing its membership version")?;
            (
                scope_exchange(broker_record.delivery_class),
                scope_route_key(
                    &broker_record.network_id,
                    &broker_record.route.address,
                    membership_version,
                ),
            )
        };
        let pending_confirm = channel
            .basic_publish(
                exchange,
                &key,
                BasicPublishOptions {
                    mandatory: true,
                    ..Default::default()
                },
                &serde_json::to_vec(&BrokerEnvelope::Record(broker_record.clone()))?,
                BasicProperties::default()
                    .with_delivery_mode(2)
                    .with_message_id(broker_record.record_id.clone().into())
                    .with_content_type("application/json".into()),
            )
            .await?;
        let confirm = tokio::time::timeout(self.config.fanout_confirm_timeout, pending_confirm)
            .await
            .context("RabbitMQ publisher confirm timed out")??;
        match confirm {
            Confirmation::Ack(None) => Ok(()),
            Confirmation::Ack(Some(returned)) => {
                bail!(
                    "RabbitMQ mandatory publish was returned: {}",
                    returned.reply_text
                )
            }
            Confirmation::Nack(_) => bail!("RabbitMQ nacked durable publish"),
            Confirmation::NotRequested => bail!("RabbitMQ publisher confirm was not requested"),
        }
    }

    pub async fn publish_control(&self, control: &BrokerControlRecord) -> Result<()> {
        let started = std::time::Instant::now();
        self.ensure_tenant_mailboxes(&control.network_id, &control.target_principal_id)
            .await?;
        let channel = self.connection.create_channel().await?;
        channel
            .confirm_select(ConfirmSelectOptions::default())
            .await?;
        let pending_confirm = channel
            .basic_publish(
                direct_exchange(DeliveryClass::Interactive),
                &direct_route_key(&control.network_id, &control.target_principal_id),
                BasicPublishOptions {
                    mandatory: true,
                    ..Default::default()
                },
                &serde_json::to_vec(&BrokerEnvelope::Control(control.clone()))?,
                BasicProperties::default()
                    .with_delivery_mode(2)
                    .with_message_id(control.correlation_id.clone().into())
                    .with_content_type("application/json".into()),
            )
            .await?;
        let confirm = tokio::time::timeout(self.config.fanout_confirm_timeout, pending_confirm)
            .await
            .context("RabbitMQ control publisher confirm timed out")??;
        let result = match confirm {
            Confirmation::Ack(None) => Ok(()),
            Confirmation::Ack(Some(returned)) => bail!(
                "RabbitMQ mandatory control publish was returned: {}",
                returned.reply_text
            ),
            Confirmation::Nack(_) => bail!("RabbitMQ nacked durable control publish"),
            Confirmation::NotRequested => {
                bail!("RabbitMQ control publisher confirm was not requested")
            }
        };
        let outcome = publish_confirm_outcome(&result);
        self.observability.record_publish_confirm(
            &control.network_id,
            &control.gap_route.scope,
            control.gap_route.lane,
            1,
            started,
            outcome,
        );
        result
    }

    pub async fn pull_page(
        &self,
        network_id: &str,
        principal_id: &str,
        delivery_class: DeliveryClass,
        page_id: &str,
        consumer_epoch: Uuid,
        limit: usize,
    ) -> Result<Option<PulledPage>> {
        let page_started = std::time::Instant::now();
        self.abandon_expired_pages(network_id, principal_id, delivery_class)
            .await?;
        let opened_at = tokio::time::Instant::now();
        self.ensure_tenant_mailboxes(network_id, principal_id)
            .await?;
        let channel = self.connection.create_channel().await?;
        channel
            .basic_qos(
                self.config
                    .rabbitmq_prefetch
                    .min(u16::try_from(limit.max(1)).unwrap_or(u16::MAX)),
                BasicQosOptions::default(),
            )
            .await?;
        let queue = queue_name(network_id, principal_id, delivery_class);
        let consumer_tag = format!("cs-page-{page_id}");
        let mut consumer = channel
            .basic_consume(
                &queue,
                &consumer_tag,
                BasicConsumeOptions::default(),
                FieldTable::default(),
            )
            .await?;
        let mut messages = Vec::<Delivery>::new();
        for _ in 0..limit {
            match tokio::time::timeout(std::time::Duration::from_millis(100), consumer.next()).await
            {
                Ok(Some(Ok(message))) => messages.push(message),
                Ok(Some(Err(error))) => return Err(error.into()),
                Ok(None) | Err(_) => break,
            }
        }
        channel
            .basic_cancel(&consumer_tag, BasicCancelOptions::default())
            .await?;
        if messages.is_empty() {
            channel.close(200, "empty mailbox page").await?;
            self.observability.record_delivery_page(page_started, 0, 0);
            return Ok(None);
        }
        let mut deliveries = Vec::with_capacity(messages.len());
        let mut controls = Vec::new();
        let mut tags = Vec::with_capacity(messages.len());
        let mut redeliveries = 0_u64;
        let mut oldest_enqueued_at = u64::MAX;
        for message in messages {
            redeliveries = redeliveries.saturating_add(u64::from(message.redelivered));
            match serde_json::from_slice::<BrokerEnvelope>(&message.data)? {
                BrokerEnvelope::Record(record) => {
                    if record.network_id != network_id || record.delivery_class != delivery_class {
                        bail!("RabbitMQ mailbox record binding mismatch");
                    }
                    if record.source_principal_id == principal_id {
                        channel
                            .basic_ack(message.delivery_tag, BasicAckOptions { multiple: false })
                            .await?;
                        continue;
                    }
                    oldest_enqueued_at = oldest_enqueued_at.min(record.enqueued_at);
                    deliveries.push(MailboxDelivery {
                        delivery_id: stable_delivery_id(
                            network_id,
                            &record.record_id,
                            principal_id,
                            record.membership_version.as_deref(),
                        )?,
                        record_id: record.record_id,
                        route: record.route,
                        record: record.record,
                        membership_version: record.membership_version,
                        enqueued_at: record.enqueued_at,
                        expires_at: record.expires_at,
                    });
                }
                BrokerEnvelope::Control(control) => {
                    if control.network_id != network_id
                        || control.target_principal_id != principal_id
                        || delivery_class != DeliveryClass::Interactive
                    {
                        bail!("RabbitMQ mailbox control binding mismatch");
                    }
                    oldest_enqueued_at = oldest_enqueued_at.min(control.enqueued_at);
                    controls.push(MailboxControlDelivery {
                        delivery_id: stable_delivery_id(
                            network_id,
                            &control.correlation_id,
                            principal_id,
                            None,
                        )?,
                        correlation_id: control.correlation_id,
                        source_principal_id: control.source_principal_id,
                        target_principal_id: control.target_principal_id,
                        control_kind: control.control_kind,
                        payload: control.payload,
                        enqueued_at: control.enqueued_at,
                        expires_at: control.expires_at,
                    });
                }
            }
            tags.push(message.delivery_tag);
        }
        self.pending_pages.lock().await.insert(
            page_id.to_owned(),
            PendingPage {
                channel,
                delivery_tags: tags,
                network_id: network_id.to_owned(),
                principal_id: principal_id.to_owned(),
                delivery_class,
                consumer_epoch,
                opened_at,
                oldest_enqueued_at,
            },
        );
        if deliveries.is_empty() && controls.is_empty() {
            let pending = self.pending_pages.lock().await.remove(page_id);
            if let Some(pending) = pending {
                pending.channel.close(200, "self delivery filtered").await?;
            }
            self.observability
                .record_delivery_page(page_started, 0, redeliveries);
            return Ok(None);
        }
        let delivery_count = (deliveries.len() + controls.len()) as u64;
        self.observability
            .record_delivery_page(page_started, delivery_count, redeliveries);
        Ok(Some(PulledPage {
            page_id: page_id.to_owned(),
            binding: MailboxBinding {
                network_id: network_id.to_owned(),
                recipient_principal_id: principal_id.to_owned(),
                delivery_class,
            },
            deliveries,
            controls,
            consumer_epoch,
        }))
    }

    pub async fn commit_page(
        &self,
        page_id: &str,
        principal_id: &str,
        delivery_class: DeliveryClass,
        consumer_epoch: Uuid,
    ) -> Result<Option<usize>> {
        let Some(pending) = self.pending_pages.lock().await.remove(page_id) else {
            return Ok(None);
        };
        if pending.principal_id != principal_id
            || pending.delivery_class != delivery_class
            || pending.consumer_epoch != consumer_epoch
        {
            bail!("page commit owner, principal, class, or epoch mismatch");
        }
        for tag in &pending.delivery_tags {
            pending
                .channel
                .basic_ack(*tag, BasicAckOptions { multiple: false })
                .await?;
        }
        pending.channel.close(200, "mailbox page committed").await?;
        Ok(Some(pending.delivery_tags.len()))
    }

    pub async fn abandon_page(&self, page_id: &str) -> Result<bool> {
        let Some(pending) = self.pending_pages.lock().await.remove(page_id) else {
            return Ok(false);
        };
        pending.channel.close(500, "test or owner shutdown").await?;
        Ok(true)
    }

    async fn abandon_expired_pages(
        &self,
        network_id: &str,
        principal_id: &str,
        delivery_class: DeliveryClass,
    ) -> Result<()> {
        let expired = {
            let mut pages = self.pending_pages.lock().await;
            let page_ids = pages
                .iter()
                .filter(|(_, page)| {
                    page.network_id == network_id
                        && page.principal_id == principal_id
                        && page.delivery_class == delivery_class
                        && page.opened_at.elapsed() >= self.config.delivery_owner_lease
                })
                .map(|(page_id, _)| page_id.clone())
                .collect::<Vec<_>>();
            page_ids
                .into_iter()
                .filter_map(|page_id| pages.remove(&page_id))
                .collect::<Vec<_>>()
        };
        for page in expired {
            page.channel
                .close(500, "mailbox page owner lease expired")
                .await?;
        }
        Ok(())
    }

    pub async fn reap_expired_pages(&self) -> Result<u64> {
        let expired = {
            let mut pages = self.pending_pages.lock().await;
            let page_ids = pages
                .iter()
                .filter(|(_, page)| page.opened_at.elapsed() >= self.config.delivery_owner_lease)
                .map(|(page_id, _)| page_id.clone())
                .collect::<Vec<_>>();
            page_ids
                .into_iter()
                .filter_map(|page_id| pages.remove(&page_id))
                .collect::<Vec<_>>()
        };
        let count = expired.len() as u64;
        for page in expired {
            page.channel
                .close(500, "mailbox page owner lease expired")
                .await?;
        }
        self.observability.record_owner_lost_requeue(count);
        Ok(count)
    }

    pub async fn drain_dead_letters(&self, pool: &sqlx::PgPool, limit: usize) -> Result<u64> {
        let channel = self.connection.create_channel().await?;
        let mut recorded = 0_u64;
        for _ in 0..limit {
            let Some(message) = channel
                .basic_get(DEAD_LETTER_QUEUE, BasicGetOptions { no_ack: false })
                .await?
            else {
                break;
            };
            let envelope: BrokerEnvelope = serde_json::from_slice(&message.data)?;
            let dead_letter_bytes = message.data.len() as u64;
            let (network_id, source_principal_id, route, delivery_class, delivery_policy_version) =
                match envelope {
                    BrokerEnvelope::Record(record) => (
                        record.network_id,
                        Some(record.source_principal_id),
                        record.route,
                        record.delivery_class,
                        record.delivery_policy_version,
                    ),
                    BrokerEnvelope::Control(control) => (
                        control.network_id,
                        None,
                        control.gap_route,
                        DeliveryClass::Interactive,
                        control.delivery_policy_version,
                    ),
                };
            let headers = message.properties.headers().as_ref();
            let reason = headers
                .and_then(|table| table.inner().get("x-first-death-reason"))
                .and_then(amqp_string)
                .unwrap_or("delivery_limit");
            let queue = headers
                .and_then(|table| table.inner().get("x-first-death-queue"))
                .and_then(amqp_string)
                .context("dead letter is missing x-first-death-queue")?;
            let principal_id = principal_from_queue_name(queue, &network_id)
                .context("dead letter queue does not identify a mailbox principal")?;
            if source_principal_id.as_deref() == Some(principal_id) {
                channel
                    .basic_ack(
                        message.delivery.delivery_tag,
                        BasicAckOptions { multiple: false },
                    )
                    .await?;
                continue;
            }
            let gap_reason = if reason == "expired" {
                MailboxGapReason::Expired
            } else {
                MailboxGapReason::DeliveryLimitExceeded
            };
            crate::gaps::record_gap(
                pool,
                &network_id,
                principal_id,
                delivery_class,
                delivery_policy_version,
                &route,
                gap_reason,
                chrono::Utc::now().timestamp_millis().max(0) as u64,
            )
            .await?;
            channel
                .basic_ack(
                    message.delivery.delivery_tag,
                    BasicAckOptions { multiple: false },
                )
                .await?;
            recorded = recorded.saturating_add(1);
            self.observability
                .record_dead_letter(dead_letter_bytes, gap_reason == MailboxGapReason::Expired);
        }
        Ok(recorded)
    }

    pub fn observability(&self) -> &GatewayObservability {
        &self.observability
    }

    pub async fn mailbox_runtime_snapshot(
        &self,
        network_id: &str,
        principals: &[String],
    ) -> Result<MailboxRuntimeSnapshot> {
        let mut queues = Vec::with_capacity(principals.len().saturating_mul(2));
        let mut missing = 0_u64;
        let mut ready = 0_u64;
        for principal in principals {
            for class in DeliveryClass::ALL {
                let channel = self.connection.create_channel().await?;
                match channel
                    .queue_declare(
                        &queue_name(network_id, principal, class),
                        QueueDeclareOptions {
                            passive: true,
                            ..Default::default()
                        },
                        FieldTable::default(),
                    )
                    .await
                {
                    Ok(queue) => {
                        ready = ready.saturating_add(u64::from(queue.message_count()));
                        queues.push(MailboxQueueSnapshot {
                            principal_id: principal.clone(),
                            delivery_class: class,
                            ready_messages: queue.message_count(),
                            consumers: queue.consumer_count(),
                        });
                    }
                    Err(_) => missing = missing.saturating_add(1),
                }
            }
        }
        let dlq_channel = self.connection.create_channel().await?;
        let dead_letter_ready_messages = dlq_channel
            .queue_declare(
                DEAD_LETTER_QUEUE,
                QueueDeclareOptions {
                    passive: true,
                    ..Default::default()
                },
                FieldTable::default(),
            )
            .await?
            .message_count();
        let now = now_ms();
        let pending_pages = self
            .pending_pages
            .lock()
            .await
            .values()
            .map(|page| PendingMailboxPageSnapshot {
                principal_id: page.principal_id.clone(),
                delivery_class: page.delivery_class,
                consumer_epoch: page.consumer_epoch,
                unacked_messages: page.delivery_tags.len() as u64,
                oldest_unacked_age_ms: now.saturating_sub(page.oldest_enqueued_at),
            })
            .collect::<Vec<_>>();
        let unacked_messages = pending_pages.iter().map(|page| page.unacked_messages).sum();
        let oldest_unacked_age_ms = pending_pages
            .iter()
            .map(|page| page.oldest_unacked_age_ms)
            .max()
            .unwrap_or_default();
        let runtime = self.observability.snapshot();
        Ok(MailboxRuntimeSnapshot {
            observed_mailbox_queues: queues.len() as u64,
            missing_mailbox_queues: missing,
            ready_messages: ready,
            unacked_messages,
            redeliveries: runtime.redeliveries,
            oldest_unacked_age_ms,
            dead_letter_ready_messages,
            dead_letter_recorded_bytes: runtime.dead_letter_bytes,
            queues,
            pending_pages,
        })
    }
}

fn publish_confirm_outcome(result: &Result<()>) -> PublishConfirmOutcome {
    match result {
        Ok(()) => PublishConfirmOutcome::Confirmed,
        Err(error) if error.to_string().contains("returned") => PublishConfirmOutcome::Unroutable,
        Err(error) if error.to_string().contains("nacked") => PublishConfirmOutcome::Nack,
        Err(_) => PublishConfirmOutcome::Error,
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn amqp_string(value: &AMQPValue) -> Option<&str> {
    match value {
        AMQPValue::LongString(value) => std::str::from_utf8(value.as_bytes()).ok(),
        AMQPValue::ShortString(value) => Some(value.as_str()),
        _ => None,
    }
}

fn principal_from_queue_name<'a>(queue: &'a str, network_id: &str) -> Option<&'a str> {
    let expected_network = network_queue_component(network_id);
    let mut parts = queue.split('.');
    match (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) {
        (Some("ws"), Some("cs"), Some(network), Some(principal), Some(_class), None)
            if network == expected_network =>
        {
            Some(principal)
        }
        _ => None,
    }
}

fn endpoint_with_credentials(config: &Config) -> Result<(String, OwnedTLSConfig)> {
    let mut endpoint = url::Url::parse(&config.rabbitmq_endpoint)?;
    let ca_cert_path = endpoint
        .query_pairs()
        .find_map(|(key, value)| (key == "cacertfile").then(|| value.into_owned()));
    if ca_cert_path.is_some() {
        endpoint.query_pairs_mut().clear().extend_pairs(
            url::Url::parse(&config.rabbitmq_endpoint)?
                .query_pairs()
                .filter(|(key, _)| key != "cacertfile"),
        );
    }
    endpoint
        .set_username(&config.rabbitmq_username)
        .map_err(|_| anyhow::anyhow!("invalid RabbitMQ username"))?;
    endpoint
        .set_password(Some(&config.rabbitmq_password))
        .map_err(|_| anyhow::anyhow!("invalid RabbitMQ password"))?;
    let cert_chain = ca_cert_path
        .map(std::fs::read_to_string)
        .transpose()
        .context("read RabbitMQ CA certificate")?;
    Ok((
        endpoint.into(),
        OwnedTLSConfig {
            identity: None,
            cert_chain,
        },
    ))
}

fn mailbox_arguments(config: &Config) -> FieldTable {
    let mut args = FieldTable::default();
    args.insert(
        "x-queue-type".into(),
        AMQPValue::LongString(LongString::from("quorum")),
    );
    args.insert(
        "x-message-ttl".into(),
        AMQPValue::LongLongInt(config.mailbox_message_ttl_ms as i64),
    );
    args.insert(
        "x-max-length-bytes".into(),
        AMQPValue::LongLongInt(config.mailbox_max_length_bytes as i64),
    );
    args.insert(
        "x-overflow".into(),
        AMQPValue::LongString(LongString::from("reject-publish")),
    );
    args.insert(
        "x-delivery-limit".into(),
        AMQPValue::LongInt(config.max_delivery_attempts as i32),
    );
    args.insert(
        "x-dead-letter-exchange".into(),
        AMQPValue::LongString(LongString::from(DEAD_LETTER_EXCHANGE)),
    );
    args.insert(
        "x-dead-letter-strategy".into(),
        AMQPValue::LongString(LongString::from("at-least-once")),
    );
    args
}

fn queue_name(network_id: &str, principal_id: &str, class: DeliveryClass) -> String {
    format!(
        "ws.cs.{}.{}.{}",
        network_queue_component(network_id),
        principal_id,
        class.as_str()
    )
}

fn network_queue_component(network_id: &str) -> String {
    hex::encode(Sha256::digest(network_id.as_bytes()))
}

fn direct_route_key(network_id: &str, principal_id: &str) -> String {
    hex::encode(Sha256::digest(
        serde_json::to_vec(&(network_id, principal_id)).expect("tuple serialization cannot fail"),
    ))
}

fn scope_route_key(network_id: &str, address: &str, membership_version: &str) -> String {
    hex::encode(Sha256::digest(
        serde_json::to_vec(&(network_id, address, membership_version))
            .expect("tuple serialization cannot fail"),
    ))
}

fn direct_exchange(class: DeliveryClass) -> &'static str {
    match class {
        DeliveryClass::Interactive => DIRECT_INTERACTIVE,
        DeliveryClass::Bulk => DIRECT_BULK,
    }
}

fn scope_exchange(class: DeliveryClass) -> &'static str {
    match class {
        DeliveryClass::Interactive => SCOPE_INTERACTIVE,
        DeliveryClass::Bulk => SCOPE_BULK,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mailbox_queue_names_bind_the_full_network_identity() {
        let principal = "a".repeat(64);
        let first = queue_name("network-a", &principal, DeliveryClass::Interactive);
        let second = queue_name("network-b", &principal, DeliveryClass::Interactive);

        assert_ne!(first, second);
        assert!(first.contains(&network_queue_component("network-a")));
        assert_eq!(
            principal_from_queue_name(&first, "network-a"),
            Some(principal.as_str())
        );
        assert_eq!(principal_from_queue_name(&first, "network-b"), None);
        assert!(first.len() <= 255);
    }
}
