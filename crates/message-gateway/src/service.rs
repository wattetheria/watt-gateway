use crate::auth::VerifiedSession;
use crate::config::Config;
use crate::db;
use crate::observability::PublishConfirmOutcome;
use crate::rabbit::{BrokerControlRecord, BrokerRecord, RabbitAdapter};
use anyhow::{Context, Result, bail};
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::{BTreeSet, HashMap, HashSet};
use wattswarm_network_client_server::{
    ControlAcceptance, ControlFrame, DeliveryClassInput, EventDeliveryUrgency, PublishAcceptance,
    PublishFrame, PublishPayloadType, control_frame_signing_message, delivery_class_for_record,
};
use wattswarm_network_transport_core::{
    CheckpointAnnouncement, DeliveryClass, EventTransportRoute, PropagationLane, RuleAnnouncement,
    SummaryAnnouncement, SwarmScope,
};
use wattswarm_protocol::types::{
    Event, EventKind, EventPayload, Membership, Role, ScopeHint, SignatureEnvelope,
};

/* Grant-only helper retained for re-enabling the temporarily disabled Grant
 * admission flow after the Wattswarm changes are published.
fn now_ms() -> u64 {
    Utc::now().timestamp_millis().max(0) as u64
}
*/

struct ValidatedFrame {
    route: EventTransportRoute,
    urgency: EventDeliveryUrgency,
    membership_mutation: Option<MembershipMutation>,
}

enum MembershipMutation {
    Snapshot {
        scope: SwarmScope,
        membership: Membership,
        quorum_threshold: u32,
        quorum_signatures: Vec<SignatureEnvelope>,
        version: String,
    },
    Principal {
        scope: SwarmScope,
        principal_id: String,
        active: bool,
        version: String,
    },
}

pub async fn ensure_tenant_transport_admission(
    pool: &PgPool,
    rabbit: &RabbitAdapter,
    config: &Config,
    network_id: &str,
    principal_id: &str,
) -> Result<()> {
    db::validate_active_tenant_admission(pool, config, network_id).await?;
    // Temporarily disabled while Gateway Grant admission is commented out
    // for CS transport testing. Mailbox and route binding setup below remains.
    /*
    if !db::principal_is_admitted(pool, network_id, principal_id).await? {
        bail!("principal is not an active network member");
    }
    */
    rabbit
        .ensure_tenant_mailboxes(network_id, principal_id)
        .await?;
    let routes = sqlx::query_as::<_, (String, String)>(
        "SELECT DISTINCT route_address, membership_version FROM gateway_scope_route_bindings
         WHERE network_id = $1 AND scope_label = 'global' AND binding_state = 'active'",
    )
    .bind(network_id)
    .fetch_all(pool)
    .await?;
    for (route, membership_version) in routes {
        rabbit
            .bind_scope_member(network_id, principal_id, &route, &membership_version)
            .await?;
    }
    Ok(())
}

/*
 * Temporarily disabled: Grant admission depends on types and crypto helpers
 * that are newer than the Wattswarm revision pinned by the production Docker
 * build. Keep this code for re-enabling after the Wattswarm changes are
 * published and the Docker pin is advanced.
pub async fn admit_grant(
    pool: &PgPool,
    rabbit: &RabbitAdapter,
    config: &Config,
    request: &GrantAdmissionRequest,
) -> Result<GrantAdmissionResponse> {
    let grant = &request.grant;
    let expected_genesis = config
        .trusted_network_genesis
        .get(&grant.network_id)
        .context("network is not configured with a trusted Genesis authority")?;
    validate_network_membership_grant_for_admission(
        grant,
        expected_genesis,
        config.skip_grant_validation,
    )?;
    if !config.skip_grant_validation
        && !db::principal_is_global_authority(pool, &grant.network_id, expected_genesis).await?
    {
        bail!("configured network Genesis authority is not active");
    }

    let grant_id = wattswarm_crypto::network_membership_grant_id(grant)?;
    let mut tx = db::begin_scope_fence(pool, &grant.network_id, "global", true).await?;
    db::upsert_network_membership_grant(&mut tx, grant, &grant_id).await?;
    let active_version = sqlx::query_scalar::<_, String>(
        "SELECT membership_version FROM gateway_scope_memberships
         LEFT JOIN gateway_network_membership_grants grant_projection
           ON grant_projection.network_id = gateway_scope_memberships.network_id
          AND grant_projection.principal_id = gateway_scope_memberships.principal_id
         WHERE gateway_scope_memberships.network_id = $1
           AND gateway_scope_memberships.scope_label = 'global'
           AND gateway_scope_memberships.principal_id = $2
           AND gateway_scope_memberships.state = 'active'
           AND (
               grant_projection.expires_at_ms IS NULL
               OR grant_projection.expires_at_ms >
                  (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT
           )",
    )
    .bind(&grant.network_id)
    .bind(&grant.principal_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(membership_version) = active_version {
        tx.commit().await?;
        return Ok(GrantAdmissionResponse {
            network_id: grant.network_id.clone(),
            principal_id: grant.principal_id.clone(),
            membership_version,
            status: "active".to_owned(),
        });
    }

    let membership_version = format!("grant:{grant_id}");
    apply_membership_mutation(
        &mut tx,
        rabbit,
        config,
        &grant.network_id,
        &MembershipMutation::Principal {
            scope: SwarmScope::Global,
            principal_id: grant.principal_id.clone(),
            active: true,
            version: membership_version.clone(),
        },
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(GrantAdmissionResponse {
        network_id: grant.network_id.clone(),
        principal_id: grant.principal_id.clone(),
        membership_version,
        status: "active".to_owned(),
    })
}

fn validate_network_membership_grant(
    grant: &NetworkMembershipGrant,
    expected_issuer: &str,
) -> Result<()> {
    wattswarm_crypto::verify_network_membership_grant(grant, expected_issuer, now_ms())
}

fn validate_network_membership_grant_for_admission(
    grant: &NetworkMembershipGrant,
    expected_issuer: &str,
    skip_trusted_issuer_validation: bool,
) -> Result<()> {
    if skip_trusted_issuer_validation {
        return wattswarm_crypto::verify_network_membership_grant(
            grant,
            &grant.issuer_genesis_id,
            now_ms(),
        )
        .context("local CS test Grant signature or structure is invalid");
    }
    validate_network_membership_grant(grant, expected_issuer)
}
*/

pub async fn send_control(
    pool: &PgPool,
    rabbit: &RabbitAdapter,
    config: &Config,
    session: &VerifiedSession,
    frame: &ControlFrame,
) -> Result<ControlAcceptance> {
    if frame.framing_version != "1"
        || frame.network_id != session.network_id
        || frame.source_principal_id != session.principal_id
        || frame.correlation_id.trim().is_empty()
        || frame.payload.as_bytes().len() > 1024 * 1024
    {
        bail!("control frame binding or size is invalid");
    }
    // Temporarily disabled with Gateway Grant admission. The target mailbox
    // is still created by RabbitMQ delivery code below.
    /*
    if !db::principal_is_admitted(pool, &session.network_id, &frame.target_principal_id).await? {
        bail!("control target is not an active network member");
    }
    */
    wattswarm_crypto::verify_signature(
        &frame.source_principal_id,
        &control_frame_signing_message(frame)?,
        &frame.signature_hex,
    )?;
    let delivery_id = wattswarm_network_transport_core::stable_delivery_id(
        &session.network_id,
        &frame.correlation_id,
        &frame.target_principal_id,
        None,
    )?;
    let gap_route = EventTransportRoute::from_kind_label(
        SwarmScope::Node(frame.target_principal_id.clone()),
        PropagationLane::Events,
        "ClientServerControl",
        false,
    )?;
    let route_hash = hex::encode(Sha256::digest(serde_json::to_vec(&gap_route)?));
    let control_binding_hash =
        hex::encode(Sha256::digest(serde_json::to_vec(&serde_json::json!({
            "target_principal_id": frame.target_principal_id,
            "control_kind": frame.control_kind,
            "payload": frame.payload,
        }))?));
    let duplicate: Option<(String, String, String, i64)> = sqlx::query_as(
        "SELECT authorized_route_hash, binding_set_hash, delivery_class,
                delivery_policy_version
         FROM gateway_publish_receipts
         WHERE network_id = $1 AND principal_id = $2 AND record_id = $3
           AND publish_status = 'confirmed' AND expires_at > clock_timestamp()",
    )
    .bind(&session.network_id)
    .bind(&session.principal_id)
    .bind(&frame.correlation_id)
    .fetch_optional(pool)
    .await?;
    if let Some((stored_route_hash, stored_binding_hash, stored_class, stored_policy)) = duplicate {
        if stored_route_hash != route_hash
            || stored_binding_hash != control_binding_hash
            || stored_class != "interactive"
            || stored_policy != wattswarm_network_client_server::DELIVERY_POLICY_VERSION as i64
        {
            bail!("control correlation id was already used with different immutable fields");
        }
        rabbit.observability().record_duplicate_publish();
        return Ok(ControlAcceptance {
            correlation_id: frame.correlation_id.clone(),
            delivery_id,
        });
    }
    rabbit
        .publish_control(&BrokerControlRecord {
            network_id: session.network_id.clone(),
            correlation_id: frame.correlation_id.clone(),
            source_principal_id: frame.source_principal_id.clone(),
            target_principal_id: frame.target_principal_id.clone(),
            control_kind: frame.control_kind.as_str().to_owned(),
            payload: frame.payload.clone(),
            gap_route: gap_route.clone(),
            delivery_policy_version: wattswarm_network_client_server::DELIVERY_POLICY_VERSION,
            enqueued_at: Utc::now().timestamp_millis().max(0) as u64,
            expires_at: Some(
                Utc::now().timestamp_millis().max(0) as u64 + config.mailbox_message_ttl_ms,
            ),
        })
        .await?;
    sqlx::query(
        "INSERT INTO gateway_publish_receipts(
             network_id, principal_id, record_id, authorized_route_hash, membership_version,
             delivery_class, delivery_policy_version, expected_recipients, binding_set_hash,
             publish_status, confirmed_at, expires_at
         ) VALUES ($1,$2,$3,$4,NULL,'interactive',$5,1,$6,'confirmed',clock_timestamp(),$7)
         ON CONFLICT(network_id, principal_id, record_id) DO NOTHING",
    )
    .bind(&session.network_id)
    .bind(&session.principal_id)
    .bind(&frame.correlation_id)
    .bind(&route_hash)
    .bind(wattswarm_network_client_server::DELIVERY_POLICY_VERSION as i64)
    .bind(&control_binding_hash)
    .bind(Utc::now() + Duration::hours(24))
    .execute(pool)
    .await?;
    Ok(ControlAcceptance {
        correlation_id: frame.correlation_id.clone(),
        delivery_id,
    })
}

pub async fn publish(
    pool: &PgPool,
    rabbit: &RabbitAdapter,
    config: &Config,
    session: &VerifiedSession,
    frame: &PublishFrame,
) -> Result<PublishAcceptance> {
    if frame.framing_version != "1"
        || frame.delivery_policy_version != wattswarm_network_client_server::DELIVERY_POLICY_VERSION
        || frame.route.network_id != session.network_id
    {
        bail!("publish framing, policy, or network mismatch");
    }
    let validated = validate_record_frame(frame, session)?;
    let route = &validated.route;
    if let Some(MembershipMutation::Snapshot {
        membership,
        quorum_threshold,
        quorum_signatures,
        ..
    }) = validated.membership_mutation.as_ref()
    {
        validate_membership_snapshot_authority(
            pool,
            &session.network_id,
            &session.principal_id,
            membership,
            *quorum_threshold,
            quorum_signatures,
        )
        .await?;
    }
    if route.scope == SwarmScope::Global
        && matches!(
            route.lane,
            PropagationLane::Rules | PropagationLane::Checkpoints
        )
        && !db::principal_is_global_authority(pool, &session.network_id, &session.principal_id)
            .await?
    {
        bail!("Global Rule/Checkpoint signer is not the projected Genesis authority");
    }
    let delivery_class = delivery_class_for_record(DeliveryClassInput {
        lane: route.lane,
        event_urgency: validated.urgency,
    });
    let record_hash = hex::encode(Sha256::digest(frame.payload.as_bytes()));
    let route_hash = hex::encode(Sha256::digest(serde_json::to_vec(route)?));
    if let Some(receipt) = load_confirmed_receipt(
        pool,
        &session.network_id,
        &session.principal_id,
        &frame.record_id,
        &record_hash,
        &route_hash,
    )
    .await?
    {
        if receipt.delivery_class != delivery_class
            || receipt.delivery_policy_version != frame.delivery_policy_version
        {
            bail!("idempotent publish classification mismatch");
        }
        rabbit.observability().record_duplicate_publish();
        return Ok(receipt);
    }
    let scope_label = route.scope.label()?;
    let mut scope_fence = db::begin_scope_fence(
        pool,
        &session.network_id,
        &scope_label,
        validated.membership_mutation.is_some(),
    )
    .await?;
    let allow_network_member_author = matches!(
        validated.membership_mutation.as_ref(),
        Some(MembershipMutation::Principal {
            principal_id,
            active: true,
            ..
        }) if principal_id == &session.principal_id
    );
    let (mut membership_version, mut physical_recipients) = db::authorized_scope_version_and_count(
        pool,
        &session.network_id,
        &route.scope,
        &session.principal_id,
        allow_network_member_author,
    )
    .await?;
    let mutation_applied_before_publish =
        if let Some(mutation) = validated.membership_mutation.as_ref() {
            let mutation_started = std::time::Instant::now();
            let mutation_result = apply_membership_mutation(
                &mut scope_fence,
                rabbit,
                config,
                &session.network_id,
                mutation,
                Some(&route.address),
            )
            .await;
            rabbit
                .observability()
                .record_membership_update(mutation_started, mutation_result.is_ok());
            physical_recipients = mutation_result?;
            membership_version = Some(match mutation {
                MembershipMutation::Snapshot { version, .. }
                | MembershipMutation::Principal { version, .. } => version.clone(),
            });
            true
        } else {
            false
        };
    if physical_recipients == 0 || physical_recipients > config.max_fanout_recipients {
        bail!("scope fanout is empty or exceeds recipient admission");
    }
    let author_is_recipient = match validated.membership_mutation.as_ref() {
        Some(MembershipMutation::Snapshot { membership, .. }) => {
            membership.members.contains_key(&session.principal_id)
        }
        Some(MembershipMutation::Principal {
            principal_id,
            active,
            ..
        }) if principal_id == &session.principal_id => *active,
        _ => {
            db::scope_contains_principal(
                pool,
                &session.network_id,
                &route.scope,
                &session.principal_id,
                membership_version.as_deref(),
            )
            .await?
        }
    };
    let expected_recipients = physical_recipients.saturating_sub(u64::from(author_is_recipient));
    let fanout_bytes = (frame.payload.as_bytes().len() as u64)
        .checked_mul(physical_recipients)
        .context("fanout byte budget overflow")?;
    if fanout_bytes > config.max_fanout_bytes_per_publish {
        bail!("scope fanout exceeds the per-publish byte budget");
    }
    if matches!(route.scope, SwarmScope::Group(_) | SwarmScope::Region(_)) && {
        let acquire_started = std::time::Instant::now();
        let result = db::acquire_non_global_delivery_tokens(
            pool,
            &session.network_id,
            "cell-0",
            physical_recipients,
            config.reserved_non_global_deliveries_per_second,
            frame.delivery_policy_version,
        )
        .await;
        rabbit
            .observability()
            .record_token_bucket_acquire(acquire_started, false);
        if result.is_err() {
            rabbit.observability().record_postgres_fail_closed();
        }
        !result?
    } {
        rabbit.observability().record_backpressure(false);
        bail!("non-Global fanout is backpressured by the shared cell token bucket");
    }
    if route.scope == SwarmScope::Global {
        let bulk_rate = config
            .max_global_publishes_per_second
            .saturating_sub(config.global_interactive_reserved_per_second);
        let acquire_started = std::time::Instant::now();
        let result = db::acquire_global_token(
            pool,
            &session.network_id,
            "cell-0",
            delivery_class,
            config.max_global_publishes_per_second,
            bulk_rate,
            config.global_publish_burst,
            frame.delivery_policy_version,
        )
        .await;
        rabbit
            .observability()
            .record_token_bucket_acquire(acquire_started, true);
        if result.is_err() {
            rabbit.observability().record_postgres_fail_closed();
        }
        if !result? {
            rabbit.observability().record_backpressure(true);
            bail!("Global publish is backpressured by the shared cell token bucket");
        }
    }
    if !mutation_applied_before_publish {
        reconcile_scope_bindings(pool, rabbit, config, &session.network_id, route).await?;
    }
    let direct_recipient = match &route.scope {
        SwarmScope::Node(node_id) => Some(node_id.as_str()),
        _ => None,
    };
    let confirm_started = std::time::Instant::now();
    let publish_result = rabbit
        .publish(
            direct_recipient,
            &BrokerRecord {
                network_id: session.network_id.clone(),
                source_principal_id: session.principal_id.clone(),
                record_id: frame.record_id.clone(),
                route: route.clone(),
                record: frame.payload.clone(),
                membership_version: membership_version.clone(),
                delivery_class,
                delivery_policy_version: frame.delivery_policy_version,
                enqueued_at: Utc::now().timestamp_millis() as u64,
                expires_at: Some(
                    Utc::now().timestamp_millis() as u64 + config.mailbox_message_ttl_ms,
                ),
            },
        )
        .await;
    let outcome = match &publish_result {
        Ok(()) => PublishConfirmOutcome::Confirmed,
        Err(error) if error.to_string().contains("returned") => PublishConfirmOutcome::Unroutable,
        Err(error) if error.to_string().contains("nacked") => PublishConfirmOutcome::Nack,
        Err(_) => PublishConfirmOutcome::Error,
    };
    rabbit.observability().record_publish_confirm(
        &session.network_id,
        &route.scope,
        route.lane,
        expected_recipients,
        confirm_started,
        outcome,
    );
    publish_result?;
    let binding_hash = hex::encode(Sha256::digest(format!(
        "{}:{}:{}",
        route_hash,
        membership_version.as_deref().unwrap_or_default(),
        expected_recipients
    )));
    let receipt_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO gateway_publish_receipts(
             network_id, principal_id, record_id, authorized_route_hash, record_hash, membership_version,
             delivery_class, delivery_policy_version, expected_recipients, binding_set_hash,
             publish_status, confirmed_at, expires_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'confirmed',clock_timestamp(),$11)
         ON CONFLICT(network_id, principal_id, record_id) DO UPDATE SET
             authorized_route_hash = EXCLUDED.authorized_route_hash,
             record_hash = EXCLUDED.record_hash,
             membership_version = EXCLUDED.membership_version,
             delivery_class = EXCLUDED.delivery_class,
             delivery_policy_version = EXCLUDED.delivery_policy_version,
             expected_recipients = EXCLUDED.expected_recipients,
             binding_set_hash = EXCLUDED.binding_set_hash,
             publish_status = 'confirmed', confirmed_at = clock_timestamp(),
             expires_at = EXCLUDED.expires_at
         WHERE gateway_publish_receipts.expires_at <= clock_timestamp()",
    )
    .bind(&session.network_id)
    .bind(&session.principal_id)
    .bind(&frame.record_id)
    .bind(route_hash)
    .bind(record_hash)
    .bind(&membership_version)
    .bind(delivery_class.as_str())
    .bind(frame.delivery_policy_version as i64)
    .bind(expected_recipients as i64)
    .bind(binding_hash)
    .bind(Utc::now() + Duration::hours(24))
    .execute(&mut *scope_fence)
    .await?;
    db::record_audit(
        &mut scope_fence,
        Some(&session.network_id),
        Some(&session.principal_id),
        "publish",
        "confirmed",
        serde_json::json!({
            "record_id": frame.record_id,
            "scope": route.scope,
            "lane": route.lane,
            "delivery_class": delivery_class,
            "delivery_policy_version": frame.delivery_policy_version,
            "membership_version": membership_version,
            "expected_recipients": expected_recipients,
        }),
    )
    .await?;
    scope_fence.commit().await?;
    Ok(PublishAcceptance {
        publish_receipt: receipt_id,
        record_id: frame.record_id.clone(),
        delivery_class,
        delivery_policy_version: frame.delivery_policy_version,
        membership_version,
    })
}

fn validate_record_frame(
    frame: &PublishFrame,
    session: &VerifiedSession,
) -> Result<ValidatedFrame> {
    const MAX_PUBLISH_FRAME_BYTES: usize = 1024 * 1024;
    if frame.payload.as_bytes().len() > MAX_PUBLISH_FRAME_BYTES {
        bail!("publish frame exceeds the V1 size limit");
    }
    match frame.payload_type {
        PublishPayloadType::Event | PublishPayloadType::Message => {
            validate_event_frame(frame, session)
        }
        PublishPayloadType::Rule => validate_rule_frame(frame, session),
        PublishPayloadType::Checkpoint => validate_checkpoint_frame(frame, session),
        PublishPayloadType::Summary => validate_summary_frame(frame, session),
    }
}

fn validate_event_frame(frame: &PublishFrame, session: &VerifiedSession) -> Result<ValidatedFrame> {
    let event: Event = serde_json::from_slice(frame.payload.as_bytes())?;
    wattswarm_crypto::verify_event_signature(&event)?;
    if event.event_id != frame.record_id || event.author_node_id != session.principal_id {
        bail!("signed Event identity or author does not match session");
    }
    let scope = ScopeHint::parse_with_prefix_fallback(&event.swarm_scope)
        .map(scope_from_hint)
        .context("signed Event has invalid swarm scope")?;
    let lane = if event.event_kind == EventKind::TopicMessagePosted {
        PropagationLane::Messages
    } else {
        PropagationLane::Events
    };
    let public_global_control = is_public_global_control(&event.payload);
    let expected_route = EventTransportRoute::from_kind_label(
        scope,
        lane,
        &format!("{:?}", event.event_kind),
        public_global_control,
    )?;
    if expected_route != frame.route.transport {
        bail!("transport route does not match signed Event scope and kind");
    }
    if frame.payload_type == PublishPayloadType::Message
        && expected_route.lane != PropagationLane::Messages
    {
        bail!("Message payload type requires the existing Messages lane Event");
    }
    if expected_route.scope == SwarmScope::Global && !public_global_control {
        bail!("non-control Event cannot use the Global route");
    }
    let urgency = if matches!(expected_route.scope, SwarmScope::Node(_)) {
        EventDeliveryUrgency::ExplicitRecipient
    } else if public_global_control {
        EventDeliveryUrgency::TimeSensitiveControl
    } else {
        EventDeliveryUrgency::Background
    };
    let membership_mutation = match &event.payload {
        EventPayload::MembershipUpdated(payload) => Some(MembershipMutation::Snapshot {
            scope: SwarmScope::Global,
            membership: payload.new_membership.clone(),
            quorum_threshold: payload.quorum_threshold,
            quorum_signatures: payload.quorum_signatures.clone(),
            version: event.event_id.clone(),
        }),
        EventPayload::FeedSubscriptionUpdated(payload) => {
            let scope = payload
                .scope()
                .map(scope_from_hint)
                .context("subscription mutation has invalid scope")?;
            if payload.subscriber_node_id != event.author_node_id {
                bail!("subscription mutation author must be its subscriber");
            }
            (!matches!(scope, SwarmScope::Global | SwarmScope::Node(_))).then_some(
                MembershipMutation::Principal {
                    scope,
                    principal_id: payload.subscriber_node_id.clone(),
                    active: payload.active,
                    version: event.event_id.clone(),
                },
            )
        }
        _ => None,
    };
    if membership_mutation.as_ref().is_some_and(|mutation| {
        let scope = match mutation {
            MembershipMutation::Snapshot { scope, .. }
            | MembershipMutation::Principal { scope, .. } => scope,
        };
        scope != &expected_route.scope
    }) {
        bail!("membership mutation scope does not match signed Event route");
    }
    Ok(ValidatedFrame {
        route: expected_route,
        urgency,
        membership_mutation,
    })
}

fn validate_rule_frame(frame: &PublishFrame, session: &VerifiedSession) -> Result<ValidatedFrame> {
    let rule: RuleAnnouncement = serde_json::from_slice(frame.payload.as_bytes())?;
    let expected_id = hex::encode(Sha256::digest(frame.payload.as_bytes()));
    if frame.record_id != expected_id {
        bail!("Rule record id does not match its canonical record bytes");
    }
    if rule.scope == SwarmScope::Global {
        verify_authority_record(
            session,
            rule.authority_signer_node_id.as_deref(),
            rule.authority_signature_hex.as_deref(),
            &serde_json::to_vec(&serde_json::json!({
                "scope": &rule.scope,
                "rule_set": &rule.rule_set,
                "rule_version": rule.rule_version,
                "activation_epoch": rule.activation_epoch,
            }))?,
        )?;
    }
    let expected_route = announcement_route(
        rule.scope.clone(),
        PropagationLane::Rules,
        rule.scope == SwarmScope::Global,
    )?;
    if expected_route != frame.route.transport {
        bail!("Rule transport route mismatch");
    }
    Ok(ValidatedFrame {
        route: expected_route,
        urgency: EventDeliveryUrgency::TimeSensitiveControl,
        membership_mutation: None,
    })
}

fn validate_checkpoint_frame(
    frame: &PublishFrame,
    session: &VerifiedSession,
) -> Result<ValidatedFrame> {
    let checkpoint: CheckpointAnnouncement = serde_json::from_slice(frame.payload.as_bytes())?;
    if checkpoint.checkpoint_id != frame.record_id {
        bail!("Checkpoint record id mismatch");
    }
    if checkpoint.scope == SwarmScope::Global {
        verify_authority_record(
            session,
            checkpoint.authority_signer_node_id.as_deref(),
            checkpoint.authority_signature_hex.as_deref(),
            &serde_json::to_vec(&serde_json::json!({
                "scope": &checkpoint.scope,
                "checkpoint_id": &checkpoint.checkpoint_id,
                "artifact_path": &checkpoint.artifact_path,
            }))?,
        )?;
    }
    let expected_route = announcement_route(
        checkpoint.scope.clone(),
        PropagationLane::Checkpoints,
        checkpoint.scope == SwarmScope::Global,
    )?;
    if expected_route != frame.route.transport {
        bail!("Checkpoint transport route mismatch");
    }
    Ok(ValidatedFrame {
        route: expected_route,
        urgency: EventDeliveryUrgency::Background,
        membership_mutation: None,
    })
}

fn validate_summary_frame(
    frame: &PublishFrame,
    session: &VerifiedSession,
) -> Result<ValidatedFrame> {
    let summary: SummaryAnnouncement = serde_json::from_slice(frame.payload.as_bytes())?;
    if summary.summary_id != frame.record_id || summary.source_node_id != session.principal_id {
        bail!("Summary identity or source does not match session");
    }
    let expected_route = announcement_route(summary.scope, PropagationLane::Summaries, false)?;
    if expected_route != frame.route.transport {
        bail!("Summary transport route mismatch");
    }
    Ok(ValidatedFrame {
        route: expected_route,
        urgency: EventDeliveryUrgency::Background,
        membership_mutation: None,
    })
}

fn verify_authority_record(
    session: &VerifiedSession,
    signer: Option<&str>,
    signature: Option<&str>,
    message: &[u8],
) -> Result<()> {
    let (Some(signer), Some(signature)) = (signer, signature) else {
        bail!("Global authority record requires an author signature");
    };
    if signer != session.principal_id {
        bail!("Global authority record signer does not match session");
    }
    wattswarm_crypto::verify_signature(signer, message, signature)
}

fn announcement_route(
    scope: SwarmScope,
    lane: PropagationLane,
    public_global_control: bool,
) -> Result<EventTransportRoute> {
    EventTransportRoute::from_kind_label(scope, lane, lane.as_str(), public_global_control)
}

async fn reconcile_scope_bindings(
    pool: &PgPool,
    rabbit: &RabbitAdapter,
    config: &Config,
    network_id: &str,
    route: &EventTransportRoute,
) -> Result<()> {
    if matches!(route.scope, SwarmScope::Node(_)) {
        return Ok(());
    }
    let scope_label = route.scope.label()?;
    let active_version = sqlx::query_scalar::<_, String>(
        "SELECT active_membership_version FROM gateway_scope_versions
         WHERE network_id = $1 AND scope_label = $2",
    )
    .bind(network_id)
    .bind(&scope_label)
    .fetch_optional(pool)
    .await?;
    let active_version = active_version.context("shared scope has no active membership version")?;
    let members = sqlx::query_scalar::<_, String>(
        "SELECT principal_id FROM gateway_scope_memberships
         WHERE network_id = $1 AND scope_label = $2 AND state = 'active'
           AND membership_version = $3
         ORDER BY principal_id",
    )
    .bind(network_id)
    .bind(&scope_label)
    .bind(&active_version)
    .fetch_all(pool)
    .await?;
    let bound = sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT principal_id FROM gateway_scope_route_bindings
         WHERE network_id = $1 AND scope_label = $2 AND route_address = $3
           AND binding_state = 'active'",
    )
    .bind(network_id)
    .bind(&scope_label)
    .bind(&route.address)
    .fetch_all(pool)
    .await?;
    let desired = members.iter().cloned().collect::<BTreeSet<_>>();
    let existing = bound.into_iter().collect::<BTreeSet<_>>();
    tokio::time::timeout(config.membership_binding_timeout, async {
        for principal in &desired {
            rabbit
                .bind_scope_member(network_id, principal, &route.address, &active_version)
                .await?;
        }
        for principal in existing.difference(&desired) {
            rabbit
                .unbind_scope_member(network_id, principal, &route.address, &active_version)
                .await?;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("membership binding reconciliation timed out")??;
    sqlx::query(
        "DELETE FROM gateway_scope_route_bindings
         WHERE network_id = $1 AND scope_label = $2 AND route_address = $3",
    )
    .bind(network_id)
    .bind(&scope_label)
    .bind(&route.address)
    .execute(pool)
    .await?;
    for principal in &members {
        for class in DeliveryClass::ALL {
            sqlx::query(
                "INSERT INTO gateway_scope_route_bindings(
                     network_id, scope_label, route_address, principal_id, delivery_class,
                     membership_version, binding_state, updated_at
                 ) VALUES ($1,$2,$3,$4,$5,$6,'active',clock_timestamp())",
            )
            .bind(network_id)
            .bind(&scope_label)
            .bind(&route.address)
            .bind(principal)
            .bind(class.as_str())
            .bind(&active_version)
            .execute(pool)
            .await?;
        }
    }
    sqlx::query(
        "UPDATE gateway_scope_memberships
         SET interactive_binding_state = 'active', bulk_binding_state = 'active',
             binding_updated_at = clock_timestamp()
         WHERE network_id = $1 AND scope_label = $2 AND state = 'active'",
    )
    .bind(network_id)
    .bind(scope_label)
    .execute(pool)
    .await?;
    Ok(())
}

async fn apply_membership_mutation(
    tx: &mut Transaction<'_, Postgres>,
    rabbit: &RabbitAdapter,
    config: &Config,
    network_id: &str,
    mutation: &MembershipMutation,
    additional_route: Option<&str>,
) -> Result<u64> {
    let started = std::time::Instant::now();
    let (scope, version) = match mutation {
        MembershipMutation::Snapshot { scope, version, .. }
        | MembershipMutation::Principal { scope, version, .. } => (scope, version),
    };
    let scope_label = scope.label()?;
    db::record_membership_mutation(tx, config, network_id, &scope_label, version).await?;
    let existing = sqlx::query_scalar::<_, String>(
        "SELECT principal_id FROM gateway_scope_memberships
         WHERE network_id = $1 AND scope_label = $2 AND state = 'active'",
    )
    .bind(network_id)
    .bind(&scope_label)
    .fetch_all(&mut **tx)
    .await?
    .into_iter()
    .collect::<BTreeSet<_>>();
    let desired = match mutation {
        MembershipMutation::Snapshot { membership, .. } => {
            membership.members.keys().cloned().collect()
        }
        MembershipMutation::Principal {
            principal_id,
            active,
            ..
        } => {
            let mut desired = existing.clone();
            if *active {
                desired.insert(principal_id.clone());
            } else {
                desired.remove(principal_id);
            }
            desired
        }
    };
    if scope == &SwarmScope::Global {
        validate_proposed_tenant_count(config, desired.len() as u64)?;
    }
    let mut routes = sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT route_address FROM gateway_scope_route_bindings
         WHERE network_id = $1 AND scope_label = $2",
    )
    .bind(network_id)
    .bind(&scope_label)
    .fetch_all(&mut **tx)
    .await?;
    if let Some(route) = additional_route
        && !routes.iter().any(|existing| existing == route)
    {
        routes.push(route.to_owned());
    }
    tokio::time::timeout(config.membership_binding_timeout, async {
        for route_address in &routes {
            for principal in &desired {
                rabbit
                    .bind_scope_member(network_id, principal, route_address, version)
                    .await?;
            }
        }
        for principal in desired.difference(&existing) {
            rabbit
                .ensure_tenant_mailboxes(network_id, principal)
                .await?;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("membership mutation binding timed out")??;

    sqlx::query(
        "UPDATE gateway_scope_memberships
         SET state = 'revoked', membership_version = $3, revoked_at = clock_timestamp(),
             interactive_binding_state = 'revoked', bulk_binding_state = 'revoked',
             binding_updated_at = clock_timestamp()
         WHERE network_id = $1 AND scope_label = $2",
    )
    .bind(network_id)
    .bind(&scope_label)
    .bind(version)
    .execute(&mut **tx)
    .await?;
    for principal in &desired {
        let roles = match mutation {
            MembershipMutation::Snapshot { membership, .. } => serde_json::to_value(
                membership
                    .members
                    .get(principal)
                    .cloned()
                    .unwrap_or_default(),
            )?,
            MembershipMutation::Principal { .. } => serde_json::json!([]),
        };
        sqlx::query(
            "INSERT INTO gateway_scope_memberships(
                 network_id, scope_label, principal_id, membership_version, state,
                 authorized_at, revoked_at, interactive_binding_state,
                 bulk_binding_state, roles_json, binding_updated_at
             ) VALUES ($1,$2,$3,$4,'active',clock_timestamp(),NULL,'active','active',$5,clock_timestamp())
             ON CONFLICT(network_id, scope_label, principal_id) DO UPDATE SET
                 membership_version = EXCLUDED.membership_version,
                 state = 'active', revoked_at = NULL,
                 interactive_binding_state = 'active', bulk_binding_state = 'active',
                 roles_json = EXCLUDED.roles_json,
                 binding_updated_at = clock_timestamp()",
        )
        .bind(network_id)
        .bind(&scope_label)
        .bind(principal)
        .bind(version)
        .bind(roles)
        .execute(&mut **tx)
        .await?;
    }
    sqlx::query(
        "DELETE FROM gateway_scope_route_bindings
         WHERE network_id = $1 AND scope_label = $2",
    )
    .bind(network_id)
    .bind(&scope_label)
    .execute(&mut **tx)
    .await?;
    for route_address in &routes {
        for principal in &desired {
            for class in DeliveryClass::ALL {
                sqlx::query(
                    "INSERT INTO gateway_scope_route_bindings(
                         network_id, scope_label, route_address, principal_id, delivery_class,
                         membership_version, binding_state, updated_at
                     ) VALUES ($1,$2,$3,$4,$5,$6,'active',clock_timestamp())",
                )
                .bind(network_id)
                .bind(&scope_label)
                .bind(route_address)
                .bind(principal)
                .bind(class.as_str())
                .bind(version)
                .execute(&mut **tx)
                .await?;
            }
        }
    }
    sqlx::query(
        "INSERT INTO gateway_scope_versions(
             network_id, scope_label, active_membership_version, routing_fence, updated_at
         ) VALUES ($1,$2,$3,1,clock_timestamp())
         ON CONFLICT(network_id, scope_label) DO UPDATE SET
             active_membership_version = EXCLUDED.active_membership_version,
             routing_fence = gateway_scope_versions.routing_fence + 1,
             updated_at = clock_timestamp()",
    )
    .bind(network_id)
    .bind(scope_label)
    .bind(version)
    .execute(&mut **tx)
    .await?;
    if started.elapsed() > config.max_membership_binding_lag {
        bail!("membership binding lag exceeds configured guardrail");
    }
    Ok(desired.len() as u64)
}

async fn validate_membership_snapshot_authority(
    pool: &PgPool,
    network_id: &str,
    author_principal_id: &str,
    membership: &Membership,
    quorum_threshold: u32,
    quorum_signatures: &[SignatureEnvelope],
) -> Result<()> {
    if quorum_threshold == 0 || quorum_signatures.len() < quorum_threshold as usize {
        bail!("membership quorum signatures are insufficient");
    }
    let genesis = sqlx::query_scalar::<_, String>(
        "SELECT principal_id FROM gateway_network_authorities
         WHERE network_id = $1 AND authority_kind = 'genesis' AND state = 'active'",
    )
    .bind(network_id)
    .fetch_one(pool)
    .await
    .context("network Genesis authority is not projected")?;
    let rows = sqlx::query(
        "SELECT principal_id, roles_json FROM gateway_scope_memberships
         WHERE network_id = $1 AND scope_label = 'global' AND state = 'active'",
    )
    .bind(network_id)
    .fetch_all(pool)
    .await?;
    let mut current_roles = HashMap::<String, HashSet<Role>>::new();
    for row in rows {
        current_roles.insert(
            row.try_get("principal_id")?,
            serde_json::from_value(row.try_get("roles_json")?)?,
        );
    }
    let allowed_signers = if author_principal_id == genesis {
        HashSet::from([genesis.clone()])
    } else {
        if !current_roles
            .get(author_principal_id)
            .is_some_and(|roles| roles.contains(&Role::Finalizer))
        {
            bail!("MembershipUpdated author is not a projected Finalizer");
        }
        current_roles
            .into_iter()
            .filter_map(|(principal, roles)| roles.contains(&Role::Finalizer).then_some(principal))
            .collect()
    };
    let message = serde_json::to_vec(membership)?;
    let mut unique = HashSet::new();
    let mut valid = 0_u32;
    for signature in quorum_signatures {
        if !unique.insert(signature.signer_node_id.clone())
            || !allowed_signers.contains(&signature.signer_node_id)
        {
            continue;
        }
        if wattswarm_crypto::verify_signature(
            &signature.signer_node_id,
            &message,
            &signature.signature_hex,
        )
        .is_ok()
        {
            valid = valid.saturating_add(1);
        }
    }
    if valid < quorum_threshold {
        bail!("membership quorum signatures are invalid");
    }
    Ok(())
}

fn validate_proposed_tenant_count(config: &Config, active: u64) -> Result<()> {
    if active > config.max_active_tenants || active > config.max_fanout_recipients {
        bail!("membership would exceed ClientServer tenant or fanout admission");
    }
    let admitted_queues = config
        .cluster_queue_limit
        .saturating_mul(config.mailbox_shard_admission_percent)
        / 100;
    if active.saturating_mul(2).saturating_add(16) > admitted_queues {
        bail!("membership would exceed RabbitMQ queue admission");
    }
    let required = config
        .max_global_publishes_per_second
        .saturating_mul(active)
        .saturating_add(config.reserved_non_global_deliveries_per_second);
    let safe = config
        .max_fanout_deliveries_per_second
        .saturating_mul(config.fanout_admission_utilization_percent)
        / 100;
    if required > safe {
        bail!("membership would exceed Global delivery-rate admission");
    }
    Ok(())
}

async fn load_confirmed_receipt(
    pool: &PgPool,
    network_id: &str,
    principal_id: &str,
    record_id: &str,
    record_hash: &str,
    route_hash: &str,
) -> Result<Option<PublishAcceptance>> {
    let row = sqlx::query(
        "SELECT authorized_route_hash, record_hash, membership_version,
                delivery_class, delivery_policy_version
         FROM gateway_publish_receipts
         WHERE network_id = $1 AND principal_id = $2 AND record_id = $3
           AND publish_status = 'confirmed' AND expires_at > clock_timestamp()",
    )
    .bind(network_id)
    .bind(principal_id)
    .bind(record_id)
    .fetch_optional(pool)
    .await?;
    row.map(|row| {
        let stored_route_hash: String = row.try_get("authorized_route_hash")?;
        let stored_record_hash: String = row.try_get("record_hash")?;
        if stored_route_hash != route_hash || stored_record_hash != record_hash {
            bail!("idempotent publish record or route mismatch");
        }
        let class: String = row.try_get("delivery_class")?;
        Ok(PublishAcceptance {
            publish_receipt: format!("existing:{record_id}"),
            record_id: record_id.to_owned(),
            delivery_class: match class.as_str() {
                "interactive" => DeliveryClass::Interactive,
                "bulk" => DeliveryClass::Bulk,
                _ => bail!("stored receipt has invalid delivery class"),
            },
            delivery_policy_version: row.try_get::<i64, _>("delivery_policy_version")? as u64,
            membership_version: row.try_get("membership_version")?,
        })
    })
    .transpose()
}

fn scope_from_hint(scope: ScopeHint) -> SwarmScope {
    match scope {
        ScopeHint::Global => SwarmScope::Global,
        ScopeHint::Region(id) => SwarmScope::Region(id),
        ScopeHint::Node(id) => SwarmScope::Node(id),
        ScopeHint::Group(id) => SwarmScope::Group(id),
    }
}

fn is_public_global_control(payload: &EventPayload) -> bool {
    matches!(
        payload,
        EventPayload::MembershipUpdated(_)
            | EventPayload::PolicyTuned(_)
            | EventPayload::NetworkParamsUpdated(_)
            | EventPayload::CheckpointCreated(_)
            | EventPayload::AdvisoryCreated(_)
            | EventPayload::AdvisoryApproved(_)
            | EventPayload::AdvisoryApplied(_)
            | EventPayload::EventRevoked(_)
            | EventPayload::SummaryRevoked(_)
            | EventPayload::NodePenalized(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use wattswarm_crypto::NodeIdentity;
    use wattswarm_network_client_server::PublishRoute;
    use wattswarm_network_transport_core::OpaqueSignedRecord;
    use wattswarm_protocol::types::{PolicyTunedPayload, UnsignedEvent};

    fn signed_frame() -> (VerifiedSession, PublishFrame) {
        let identity = NodeIdentity::random();
        let principal_id = identity.node_id();
        let event = identity
            .sign_unsigned_event(&UnsignedEvent::from_payload_with_scope(
                "1".to_owned(),
                principal_id.clone(),
                1,
                1,
                "global".to_owned(),
                EventPayload::PolicyTuned(PolicyTunedPayload {
                    policy_id: "policy".to_owned(),
                    from_policy_hash: "from".to_owned(),
                    to_policy_hash: "to".to_owned(),
                    advisory_id: "advisory".to_owned(),
                }),
            ))
            .unwrap();
        let route = EventTransportRoute::from_kind_label(
            SwarmScope::Global,
            PropagationLane::Events,
            "PolicyTuned",
            true,
        )
        .unwrap();
        (
            VerifiedSession {
                session_id: Uuid::new_v4(),
                network_id: "network".to_owned(),
                principal_id,
            },
            PublishFrame {
                framing_version: "1".to_owned(),
                delivery_policy_version: wattswarm_network_client_server::DELIVERY_POLICY_VERSION,
                record_id: event.event_id.clone(),
                route: PublishRoute {
                    network_id: "network".to_owned(),
                    transport: route,
                },
                payload_type: PublishPayloadType::Event,
                payload: OpaqueSignedRecord::new(serde_json::to_vec(&event).unwrap()).unwrap(),
            },
        )
    }

    /*
     * Temporarily disabled with the Grant admission flow. Keep this test for
     * re-enabling after the Wattswarm Grant API is available at the pinned
     * dependency revision.
    #[test]
    fn local_grant_validation_bypass_accepts_only_a_self_signed_test_grant() {
        let signer = NodeIdentity::random();
        let issued_at = now_ms();
        let principal_id = signer.node_id();
        let grant = wattswarm_crypto::sign_network_membership_grant(
            &wattswarm_protocol::types::UnsignedNetworkMembershipGrant {
                version: wattswarm_protocol::types::NETWORK_MEMBERSHIP_GRANT_VERSION,
                network_id: "network".to_owned(),
                principal_id: principal_id.clone(),
                public_key_hex: principal_id,
                issuer_genesis_id: signer.node_id(),
                issued_at,
                expires_at: Some(issued_at.saturating_add(60 * 60 * 1_000)),
            },
            &signer,
        )
        .unwrap();
        let trusted_genesis = NodeIdentity::random().node_id();

        assert!(
            validate_network_membership_grant_for_admission(&grant, &trusted_genesis, true,)
                .is_ok()
        );
        assert!(
            validate_network_membership_grant_for_admission(&grant, &trusted_genesis, false,)
                .is_err()
        );
    }
    */

    #[test]
    fn rejects_route_author_signature_and_frame_forgery() {
        let (session, frame) = signed_frame();
        validate_record_frame(&frame, &session).unwrap();

        let mut route_forgery = frame.clone();
        route_forgery.route.transport.address = "ws.global.Wrong".to_owned();
        assert!(validate_record_frame(&route_forgery, &session).is_err());

        let mut event: Event = serde_json::from_slice(frame.payload.as_bytes()).unwrap();
        event.signature_hex.replace_range(..2, "00");
        let mut signature_forgery = frame.clone();
        signature_forgery.payload =
            OpaqueSignedRecord::new(serde_json::to_vec(&event).unwrap()).unwrap();
        assert!(validate_record_frame(&signature_forgery, &session).is_err());

        let mut author_forgery = session.clone();
        author_forgery.principal_id = NodeIdentity::random().node_id();
        assert!(validate_record_frame(&frame, &author_forgery).is_err());

        let mut oversized = frame;
        oversized.payload = OpaqueSignedRecord::new(vec![1; 1024 * 1024 + 1]).unwrap();
        assert!(validate_record_frame(&oversized, &session).is_err());
    }
}
