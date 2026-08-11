use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;
use uuid::Uuid;
use wattetheria_message_gateway::rabbit::{BrokerControlRecord, BrokerRecord, RabbitAdapter};
use wattetheria_message_gateway::{
    auth::{self, VerifiedSession},
    commit_token::{CommitClaims, issue},
    config::Config,
    db, gaps, http, internal_tls, service,
};
use wattswarm_crypto::NodeIdentity;
use wattswarm_network_client_server::{
    ChallengeRequest, CommitRequest, GrantAdmissionRequest, LogicalNodePrincipalClaim,
    LogicalNodePrincipalProof, PublishFrame, PublishPayloadType, PublishRoute, SessionProofRequest,
    session_proof_message,
};
use wattswarm_network_transport_core::{
    DeliveryClass, EventTransportRoute, OpaqueSignedRecord, PropagationLane, SummaryAnnouncement,
    SwarmScope,
};
use wattswarm_protocol::types::{
    EventPayload, FeedSubscriptionUpdatedPayload, Membership, MembershipUpdatedPayload,
    NETWORK_MEMBERSHIP_GRANT_VERSION, Role, SignatureEnvelope, UnsignedEvent,
    UnsignedNetworkMembershipGrant,
};

fn config() -> Config {
    Config {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        database_url: "postgres://unused".to_owned(),
        rabbitmq_endpoint: std::env::var("WATTSWARM_RABBITMQ_TEST_ENDPOINT")
            .expect("WATTSWARM_RABBITMQ_TEST_ENDPOINT must point at real TLS RabbitMQ"),
        rabbitmq_username: std::env::var("WATTSWARM_RABBITMQ_TEST_USERNAME")
            .unwrap_or_else(|_| "wattswarm".to_owned()),
        rabbitmq_password: std::env::var("WATTSWARM_RABBITMQ_TEST_PASSWORD")
            .unwrap_or_else(|_| "contract-password".to_owned()),
        rabbitmq_prefetch: 16,
        delivery_page_size: 8,
        mailbox_message_ttl_ms: 1_500,
        mailbox_max_length_bytes: 4_096,
        dead_letter_max_length_bytes: 1_000_000,
        max_delivery_attempts: 3,
        cluster_queue_limit: 1_000,
        mailbox_shard_admission_percent: 80,
        max_active_tenants: 100,
        max_fanout_recipients: 100,
        max_fanout_deliveries_per_second: 10_000,
        max_fanout_bytes_per_publish: 64 * 1024 * 1024,
        fanout_confirm_timeout: Duration::from_secs(10),
        max_global_publishes_per_second: 10,
        global_publish_burst: 5,
        global_interactive_reserved_per_second: 2,
        reserved_non_global_deliveries_per_second: 1_000,
        fanout_admission_utilization_percent: 80,
        commit_hmac_secret: vec![7; 32],
        session_ttl: Duration::from_secs(900),
        skip_grant_validation: false,
        object_store_root: None,
        max_object_bytes: 64 * 1024 * 1024,
        membership_binding_timeout: Duration::from_secs(5),
        membership_mutation_window: Duration::from_secs(60),
        max_membership_mutations_per_scope_per_window: 100,
        max_membership_binding_lag: Duration::from_secs(10),
        instance_id: "rabbit-contract".to_owned(),
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

async fn contract_pool() -> sqlx::PgPool {
    let url = std::env::var("WATTSWARM_MESSAGE_GATEWAY_TEST_DATABASE_URL")
        .expect("WATTSWARM_MESSAGE_GATEWAY_TEST_DATABASE_URL must point at real PostgreSQL");
    let pool = db::connect(&url).await.unwrap();
    db::init_schema(&pool).await.unwrap();
    pool
}

fn record(route: EventTransportRoute, id: &str) -> BrokerRecord {
    BrokerRecord {
        network_id: "network-contract".to_owned(),
        record_id: id.to_owned(),
        source_principal_id: "source-author".to_owned(),
        route,
        record: OpaqueSignedRecord::new(br#"{"signed":true}"#.to_vec()).unwrap(),
        membership_version: Some("v1".to_owned()),
        delivery_class: DeliveryClass::Interactive,
        delivery_policy_version: 1,
        enqueued_at: 1,
        expires_at: None,
    }
}

async fn seed_global_member(pool: &sqlx::PgPool, network_id: &str, principal_id: &str) {
    sqlx::query(
        "INSERT INTO gateway_scope_memberships(
             network_id, scope_label, principal_id, membership_version, state,
             authorized_at, interactive_binding_state, bulk_binding_state
         ) VALUES ($1,'global',$2,'global-v1','active',clock_timestamp(),'active','active')",
    )
    .bind(network_id)
    .bind(principal_id)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO gateway_scope_versions(
             network_id, scope_label, active_membership_version, routing_fence, updated_at
         ) VALUES ($1,'global','global-v1',1,clock_timestamp())
         ON CONFLICT(network_id, scope_label) DO NOTHING",
    )
    .bind(network_id)
    .execute(pool)
    .await
    .unwrap();
}

fn subscription_frame(
    identity: &NodeIdentity,
    network_id: &str,
    group_id: &str,
    active: bool,
    sequence: u64,
) -> PublishFrame {
    let principal_id = identity.node_id();
    let event = identity
        .sign_unsigned_event(&UnsignedEvent::from_payload_with_scope(
            "1".to_owned(),
            principal_id.clone(),
            sequence,
            sequence,
            format!("group:{group_id}"),
            EventPayload::FeedSubscriptionUpdated(FeedSubscriptionUpdatedPayload {
                network_id: network_id.to_owned(),
                subscriber_node_id: principal_id,
                feed_key: format!("hive:{group_id}"),
                scope_hint: format!("group:{group_id}"),
                gossip_kinds: vec!["messages".to_owned()],
                provider_capabilities: None,
                agent_envelope: None,
                active,
            }),
        ))
        .unwrap();
    PublishFrame {
        framing_version: "1".to_owned(),
        delivery_policy_version: wattswarm_network_client_server::DELIVERY_POLICY_VERSION,
        record_id: event.event_id.clone(),
        route: PublishRoute {
            network_id: network_id.to_owned(),
            transport: EventTransportRoute::from_kind_label(
                SwarmScope::Group(group_id.to_owned()),
                PropagationLane::Events,
                "FeedSubscriptionUpdated",
                false,
            )
            .unwrap(),
        },
        payload_type: PublishPayloadType::Event,
        payload: OpaqueSignedRecord::new(serde_json::to_vec(&event).unwrap()).unwrap(),
    }
}

fn summary_frame(
    principal_id: &str,
    network_id: &str,
    group_id: &str,
    summary_id: &str,
) -> PublishFrame {
    let summary = SummaryAnnouncement {
        summary_id: summary_id.to_owned(),
        source_node_id: principal_id.to_owned(),
        scope: SwarmScope::Group(group_id.to_owned()),
        summary_kind: "contract".to_owned(),
        artifact_path: None,
        payload: serde_json::json!({"contract": true}),
    };
    PublishFrame {
        framing_version: "1".to_owned(),
        delivery_policy_version: wattswarm_network_client_server::DELIVERY_POLICY_VERSION,
        record_id: summary_id.to_owned(),
        route: PublishRoute {
            network_id: network_id.to_owned(),
            transport: EventTransportRoute::from_kind_label(
                SwarmScope::Group(group_id.to_owned()),
                PropagationLane::Summaries,
                "summaries",
                false,
            )
            .unwrap(),
        },
        payload_type: PublishPayloadType::Summary,
        payload: OpaqueSignedRecord::new(serde_json::to_vec(&summary).unwrap()).unwrap(),
    }
}

fn membership_frame(
    author: &NodeIdentity,
    network_id: &str,
    membership: Membership,
    quorum_signers: &[&NodeIdentity],
    sequence: u64,
) -> PublishFrame {
    let membership_bytes = serde_json::to_vec(&membership).unwrap();
    let quorum_signatures = quorum_signers
        .iter()
        .map(|identity| SignatureEnvelope {
            signer_node_id: identity.node_id(),
            signature_hex: identity.sign_bytes(&membership_bytes),
        })
        .collect();
    let event = author
        .sign_unsigned_event(&UnsignedEvent::from_payload_with_scope(
            "1".to_owned(),
            author.node_id(),
            sequence,
            sequence,
            "global".to_owned(),
            EventPayload::MembershipUpdated(MembershipUpdatedPayload {
                new_membership: membership,
                quorum_threshold: 1,
                quorum_signatures,
            }),
        ))
        .unwrap();
    PublishFrame {
        framing_version: "1".to_owned(),
        delivery_policy_version: wattswarm_network_client_server::DELIVERY_POLICY_VERSION,
        record_id: event.event_id.clone(),
        route: PublishRoute {
            network_id: network_id.to_owned(),
            transport: EventTransportRoute::from_kind_label(
                SwarmScope::Global,
                PropagationLane::Events,
                "MembershipUpdated",
                true,
            )
            .unwrap(),
        },
        payload_type: PublishPayloadType::Event,
        payload: OpaqueSignedRecord::new(serde_json::to_vec(&event).unwrap()).unwrap(),
    }
}

fn gateway_mtls_material() -> (Vec<u8>, Vec<u8>) {
    let endpoint = url::Url::parse(
        &std::env::var("WATTSWARM_RABBITMQ_TEST_ENDPOINT").expect("RabbitMQ test endpoint"),
    )
    .unwrap();
    let ca_path = endpoint
        .query_pairs()
        .find_map(|(key, value)| (key == "cacertfile").then(|| value.into_owned()))
        .expect("RabbitMQ test CA path");
    let tls_dir = std::path::Path::new(&ca_path).parent().unwrap();
    let mut identity = std::fs::read(tls_dir.join("server.crt")).unwrap();
    identity.extend(std::fs::read(tls_dir.join("server.key")).unwrap());
    (identity, std::fs::read(ca_path).unwrap())
}

#[tokio::test]
#[ignore = "requires real TLS RabbitMQ and PostgreSQL; run through scripts/run-message-gateway-contract.sh"]
async fn trusted_genesis_projects_and_authorizes_membership_quorum_contract() {
    let mut gateway_config = config();
    gateway_config.mailbox_message_ttl_ms = 60_000;
    gateway_config.mailbox_max_length_bytes = 1_000_000;
    let pool = contract_pool().await;
    let network_id = format!("trusted-genesis-{}", Uuid::new_v4());
    let genesis = NodeIdentity::random();
    let member = NodeIdentity::random();
    gateway_config
        .trusted_network_genesis
        .insert(network_id.clone(), genesis.node_id());
    db::seed_trusted_network_genesis(&pool, &gateway_config)
        .await
        .unwrap();
    assert!(
        db::principal_is_global_authority(&pool, &network_id, &genesis.node_id())
            .await
            .unwrap()
    );
    let adapter = RabbitAdapter::connect(Arc::new(gateway_config.clone()))
        .await
        .unwrap();
    service::ensure_tenant_transport_admission(
        &pool,
        &adapter,
        &gateway_config,
        &network_id,
        &genesis.node_id(),
    )
    .await
    .unwrap();

    let mut membership = Membership::new();
    for role in [
        Role::Proposer,
        Role::Verifier,
        Role::Committer,
        Role::Finalizer,
    ] {
        membership.grant(&genesis.node_id(), role);
    }
    membership.grant(&member.node_id(), Role::Proposer);
    let genesis_session = VerifiedSession {
        session_id: Uuid::new_v4(),
        network_id: network_id.clone(),
        principal_id: genesis.node_id(),
    };
    let frame = membership_frame(&genesis, &network_id, membership.clone(), &[&genesis], 1);
    service::publish(&pool, &adapter, &gateway_config, &genesis_session, &frame)
        .await
        .unwrap();
    let member_page = adapter
        .pull_page(
            &network_id,
            &member.node_id(),
            DeliveryClass::Interactive,
            "trusted-membership-page",
            Uuid::new_v4(),
            8,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(member_page.deliveries[0].record_id, frame.record_id);
    adapter
        .commit_page(
            &member_page.page_id,
            &member.node_id(),
            DeliveryClass::Interactive,
            member_page.consumer_epoch,
        )
        .await
        .unwrap();

    let member_session = VerifiedSession {
        session_id: Uuid::new_v4(),
        network_id: network_id.clone(),
        principal_id: member.node_id(),
    };
    let unauthorized = membership_frame(&member, &network_id, membership, &[&member], 2);
    assert!(
        service::publish(
            &pool,
            &adapter,
            &gateway_config,
            &member_session,
            &unauthorized,
        )
        .await
        .is_err(),
        "a projected non-Finalizer must not authorize MembershipUpdated"
    );
}

#[tokio::test]
#[ignore = "requires real TLS RabbitMQ and PostgreSQL; run through scripts/run-message-gateway-contract.sh"]
async fn auto_registration_adds_a_member_once_and_is_idempotent_contract() {
    let pool = contract_pool().await;
    let mut gateway_config = config();
    let network_id = format!("auto-registration-{}", Uuid::new_v4());
    let genesis = NodeIdentity::random();
    let member = NodeIdentity::random();
    gateway_config
        .trusted_network_genesis
        .insert(network_id.clone(), genesis.node_id());
    db::seed_trusted_network_genesis(&pool, &gateway_config)
        .await
        .unwrap();
    let adapter = RabbitAdapter::connect(Arc::new(gateway_config.clone()))
        .await
        .unwrap();
    let issued_at = chrono::Utc::now().timestamp_millis() as u64;
    let grant = wattswarm_crypto::sign_network_membership_grant(
        &UnsignedNetworkMembershipGrant {
            version: NETWORK_MEMBERSHIP_GRANT_VERSION,
            network_id: network_id.clone(),
            principal_id: member.node_id(),
            public_key_hex: member.node_id(),
            issuer_genesis_id: genesis.node_id(),
            issued_at,
            expires_at: None,
        },
        &genesis,
    )
    .unwrap();
    let request = GrantAdmissionRequest { grant };

    let first = service::admit_grant(&pool, &adapter, &gateway_config, &request)
        .await
        .unwrap();
    assert_eq!(first.status, "active");
    assert!(
        db::principal_is_admitted(&pool, &network_id, &member.node_id())
            .await
            .unwrap()
    );

    let second = service::admit_grant(&pool, &adapter, &gateway_config, &request)
        .await
        .unwrap();
    assert_eq!(second.membership_version, first.membership_version);

    sqlx::query(
        "UPDATE gateway_network_membership_grants
         SET expires_at_ms = 0
         WHERE network_id = $1 AND principal_id = $2",
    )
    .bind(&network_id)
    .bind(member.node_id())
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        !db::principal_is_admitted(&pool, &network_id, &member.node_id())
            .await
            .unwrap()
    );

    service::admit_grant(&pool, &adapter, &gateway_config, &request)
        .await
        .unwrap();
    assert!(
        db::principal_is_admitted(&pool, &network_id, &member.node_id())
            .await
            .unwrap()
    );
}

#[tokio::test]
#[ignore = "requires real TLS RabbitMQ and PostgreSQL; run through scripts/run-message-gateway-contract.sh"]
async fn cross_instance_commit_uses_mtls_owner_and_rejects_anonymous_client_contract() {
    let pool = contract_pool().await;
    let identity = NodeIdentity::random();
    let principal_id = identity.node_id();
    let network_id = format!("owner-forward-{}", Uuid::new_v4());
    seed_global_member(&pool, &network_id, &principal_id).await;
    let (mtls_identity, mtls_ca) = gateway_mtls_material();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let internal_addr = listener.local_addr().unwrap();

    let mut owner_config = config();
    owner_config.instance_id = "owner-a".to_owned();
    owner_config.internal_route = Some(format!("https://localhost:{}", internal_addr.port()));
    owner_config.internal_bind_addr = Some(internal_addr);
    owner_config.internal_mtls_identity_pem = Some(mtls_identity.clone());
    owner_config.internal_mtls_ca_pem = Some(mtls_ca.clone());
    owner_config.delivery_owner_lease = Duration::from_secs(5);
    let owner_adapter = RabbitAdapter::connect(Arc::new(owner_config.clone()))
        .await
        .unwrap();
    let owner_state = http::AppState {
        pool: pool.clone(),
        config: Arc::new(owner_config.clone()),
        rabbit: owner_adapter.clone(),
    };
    let tls = internal_tls::server_config(&owner_config).unwrap();
    let internal_server = tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, tls)
            .serve(http::internal_router(owner_state).into_make_service())
            .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let direct_route = EventTransportRoute::from_kind_label(
        SwarmScope::Node(principal_id.clone()),
        PropagationLane::Messages,
        "TopicMessagePosted",
        false,
    )
    .unwrap();
    let mut broker_record = record(direct_route, "owner-forward-record");
    broker_record.network_id = network_id.clone();
    owner_adapter
        .publish(Some(&principal_id), &broker_record)
        .await
        .unwrap();
    let page_id = Uuid::new_v4().to_string();
    let consumer_epoch = Uuid::new_v4();
    assert!(
        db::try_acquire_delivery_owner(
            &pool,
            &network_id,
            &principal_id,
            DeliveryClass::Interactive,
            &owner_config.instance_id,
            consumer_epoch,
            owner_config.internal_route.as_deref(),
            owner_config.delivery_owner_lease,
        )
        .await
        .unwrap()
    );
    owner_adapter
        .pull_page(
            &network_id,
            &principal_id,
            DeliveryClass::Interactive,
            &page_id,
            consumer_epoch,
            8,
        )
        .await
        .unwrap()
        .unwrap();

    let mut edge_config = owner_config.clone();
    edge_config.instance_id = "edge-b".to_owned();
    let edge_adapter = RabbitAdapter::connect(Arc::new(edge_config.clone()))
        .await
        .unwrap();
    let principal = LogicalNodePrincipalClaim {
        principal_id: principal_id.clone(),
        public_key_hex: principal_id.clone(),
        tenant_instance_id: Some("owner-forward-instance".to_owned()),
    };
    let challenge = auth::create_challenge(
        &pool,
        &ChallengeRequest {
            network_id: network_id.clone(),
            principals: vec![principal.clone()],
        },
    )
    .await
    .unwrap();
    let proof_message =
        session_proof_message(&network_id, std::slice::from_ref(&principal), &challenge).unwrap();
    let session = auth::prove_session(
        &pool,
        &edge_config,
        &SessionProofRequest {
            challenge_id: challenge.challenge_id,
            network_id: network_id.clone(),
            principals: vec![principal.clone()],
            proofs: vec![LogicalNodePrincipalProof {
                principal_id: principal_id.clone(),
                signature_hex: identity.sign_bytes(&proof_message),
            }],
            delivery_policy_version: wattswarm_network_client_server::DELIVERY_POLICY_VERSION,
        },
    )
    .await
    .unwrap();
    let commit_token = issue(
        &edge_config.commit_hmac_secret,
        &CommitClaims {
            page_id: page_id.clone(),
            network_id: network_id.clone(),
            principal_id: principal_id.clone(),
            delivery_class: DeliveryClass::Interactive,
            owner_instance_id: owner_config.instance_id.clone(),
            consumer_epoch,
            expires_at: u64::MAX,
        },
    )
    .unwrap();
    let request = CommitRequest {
        page_id: page_id.clone(),
        delivery_class: DeliveryClass::Interactive,
        commit_token,
    };
    let public_edge = http::router(http::AppState {
        pool: pool.clone(),
        config: Arc::new(edge_config),
        rabbit: edge_adapter,
    });
    let response = public_edge
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/mailbox/commit")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", session.session_token),
                )
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        db::load_delivery_owner(
            &pool,
            &network_id,
            &principal_id,
            DeliveryClass::Interactive,
        )
        .await
        .unwrap()
        .is_none()
    );

    let anonymous = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&mtls_ca).unwrap())
        .build()
        .unwrap()
        .post(format!(
            "https://localhost:{}/healthz",
            internal_addr.port()
        ))
        .send()
        .await;
    assert!(
        anonymous.is_err(),
        "internal listener must require a client certificate"
    );
    internal_server.abort();
}

#[tokio::test]
#[ignore = "requires real TLS RabbitMQ and PostgreSQL; run through scripts/run-message-gateway-contract.sh"]
async fn authenticated_content_api_enforces_digest_and_read_limits() {
    let pool = contract_pool().await;
    let identity = NodeIdentity::random();
    let network_id = format!("objects-{}", Uuid::new_v4());
    seed_global_member(&pool, &network_id, &identity.node_id()).await;

    let root = std::env::temp_dir().join(format!("wattswarm-object-contract-{}", Uuid::new_v4()));
    let network_root = root.join(hex::encode(Sha256::digest(network_id.as_bytes())));
    tokio::fs::create_dir_all(&network_root).await.unwrap();
    let content = b"content-addressed task output";
    let digest = hex::encode(Sha256::digest(content));
    tokio::fs::write(network_root.join(format!("sha256:{digest}")), content)
        .await
        .unwrap();

    let mut gateway_config = config();
    gateway_config.object_store_root = Some(root.clone());
    gateway_config.max_object_bytes = 1_024;
    let adapter = RabbitAdapter::connect(Arc::new(gateway_config.clone()))
        .await
        .unwrap();
    let principal = LogicalNodePrincipalClaim {
        principal_id: identity.node_id(),
        public_key_hex: identity.node_id(),
        tenant_instance_id: Some("content-instance".to_owned()),
    };
    let challenge = auth::create_challenge(
        &pool,
        &ChallengeRequest {
            network_id: network_id.clone(),
            principals: vec![principal.clone()],
        },
    )
    .await
    .unwrap();
    let proof_message =
        session_proof_message(&network_id, std::slice::from_ref(&principal), &challenge).unwrap();
    let session = auth::prove_session(
        &pool,
        &gateway_config,
        &SessionProofRequest {
            challenge_id: challenge.challenge_id,
            network_id,
            principals: vec![principal.clone()],
            proofs: vec![LogicalNodePrincipalProof {
                principal_id: principal.principal_id,
                signature_hex: identity.sign_bytes(&proof_message),
            }],
            delivery_policy_version: wattswarm_network_client_server::DELIVERY_POLICY_VERSION,
        },
    )
    .await
    .unwrap();
    let app = http::router(http::AppState {
        pool: pool.clone(),
        config: Arc::new(gateway_config.clone()),
        rabbit: adapter,
    });
    let uri = format!("/v1/objects/sha256:{digest}");

    let unauthorized = app
        .clone()
        .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let internal_on_public = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/v1/mailbox/commit")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        internal_on_public.status(),
        StatusCode::NOT_FOUND,
        "the internal owner ACK endpoint must not exist on the public listener"
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&uri)
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", session.session_token),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body(), 1_024)
            .await
            .unwrap()
            .as_ref(),
        content
    );

    let other_identity = NodeIdentity::random();
    let other_network = format!("objects-other-{}", Uuid::new_v4());
    seed_global_member(&pool, &other_network, &other_identity.node_id()).await;
    let other_principal = LogicalNodePrincipalClaim {
        principal_id: other_identity.node_id(),
        public_key_hex: other_identity.node_id(),
        tenant_instance_id: Some("other-content-instance".to_owned()),
    };
    let other_challenge = auth::create_challenge(
        &pool,
        &ChallengeRequest {
            network_id: other_network.clone(),
            principals: vec![other_principal.clone()],
        },
    )
    .await
    .unwrap();
    let other_proof = session_proof_message(
        &other_network,
        std::slice::from_ref(&other_principal),
        &other_challenge,
    )
    .unwrap();
    let other_session = auth::prove_session(
        &pool,
        &gateway_config,
        &SessionProofRequest {
            challenge_id: other_challenge.challenge_id,
            network_id: other_network,
            principals: vec![other_principal.clone()],
            proofs: vec![LogicalNodePrincipalProof {
                principal_id: other_principal.principal_id,
                signature_hex: other_identity.sign_bytes(&other_proof),
            }],
            delivery_policy_version: wattswarm_network_client_server::DELIVERY_POLICY_VERSION,
        },
    )
    .await
    .unwrap();
    let cross_network = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&uri)
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", other_session.session_token),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        cross_network.status(),
        StatusCode::NOT_FOUND,
        "an authenticated tenant from another network must not read this object"
    );

    tokio::fs::write(network_root.join(format!("sha256:{digest}")), b"corrupted")
        .await
        .unwrap();
    let corrupt = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&uri)
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", session.session_token),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(corrupt.status(), StatusCode::BAD_REQUEST);

    let missing_digest = hex::encode(Sha256::digest(b"missing"));
    let missing = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/objects/sha256:{missing_digest}"))
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", session.session_token),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);

    let oversized_content = vec![b'x'; 1_025];
    let oversized_digest = hex::encode(Sha256::digest(&oversized_content));
    tokio::fs::write(
        network_root.join(format!("sha256:{oversized_digest}")),
        oversized_content,
    )
    .await
    .unwrap();
    let oversized = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/objects/sha256:{oversized_digest}"))
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", session.session_token),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::BAD_REQUEST);

    let invalid = app
        .oneshot(
            Request::builder()
                .uri("/v1/objects/not-a-digest")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", session.session_token),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    tokio::fs::remove_dir_all(root).await.unwrap();
}

#[tokio::test]
#[ignore = "requires real TLS RabbitMQ and PostgreSQL; run through scripts/run-message-gateway-contract.sh"]
async fn real_membership_version_join_remove_and_binding_fence_contract() {
    let mut gateway_config = config();
    gateway_config.mailbox_message_ttl_ms = 60_000;
    gateway_config.mailbox_max_length_bytes = 1_000_000;
    let adapter = RabbitAdapter::connect(Arc::new(gateway_config.clone()))
        .await
        .unwrap();
    let pool = contract_pool().await;
    let network_id = format!("membership-{}", Uuid::new_v4());
    let group_id = format!("hive-{}", Uuid::new_v4());
    let first = NodeIdentity::random();
    let second = NodeIdentity::random();
    let outsider = NodeIdentity::random();
    seed_global_member(&pool, &network_id, &first.node_id()).await;
    seed_global_member(&pool, &network_id, &second.node_id()).await;
    seed_global_member(&pool, &network_id, &outsider.node_id()).await;
    for principal in [first.node_id(), second.node_id(), outsider.node_id()] {
        adapter
            .ensure_tenant_mailboxes(&network_id, &principal)
            .await
            .unwrap();
    }
    let first_session = VerifiedSession {
        session_id: Uuid::new_v4(),
        network_id: network_id.clone(),
        principal_id: first.node_id(),
    };
    let second_session = VerifiedSession {
        session_id: Uuid::new_v4(),
        network_id: network_id.clone(),
        principal_id: second.node_id(),
    };
    let outsider_session = VerifiedSession {
        session_id: Uuid::new_v4(),
        network_id: network_id.clone(),
        principal_id: outsider.node_id(),
    };

    let first_join_frame = subscription_frame(&first, &network_id, &group_id, true, 1);
    let first_join = service::publish(
        &pool,
        &adapter,
        &gateway_config,
        &first_session,
        &first_join_frame,
    )
    .await
    .unwrap();
    let confirmed_publish_audits: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM gateway_audit
         WHERE network_id = $1 AND principal_id = $2
           AND action = 'publish' AND outcome = 'confirmed'",
    )
    .bind(&network_id)
    .bind(first.node_id())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(confirmed_publish_audits, 1);
    assert!(
        service::publish(
            &pool,
            &adapter,
            &gateway_config,
            &outsider_session,
            &summary_frame(
                &outsider.node_id(),
                &network_id,
                &group_id,
                "unauthorized-group-summary",
            ),
        )
        .await
        .is_err(),
        "Global admission alone must not authorize a Group publish"
    );
    let second_join_frame = subscription_frame(&second, &network_id, &group_id, true, 2);
    let second_join = service::publish(
        &pool,
        &adapter,
        &gateway_config,
        &second_session,
        &second_join_frame,
    )
    .await
    .unwrap();
    assert_eq!(
        first_join.membership_version.as_deref(),
        Some(first_join_frame.record_id.as_str())
    );
    assert_eq!(
        second_join.membership_version.as_deref(),
        Some(second_join_frame.record_id.as_str()),
        "the join record is fanned out only after its binding version activates"
    );
    let active_version: String = sqlx::query_scalar(
        "SELECT active_membership_version FROM gateway_scope_versions
         WHERE network_id = $1 AND scope_label = $2",
    )
    .bind(&network_id)
    .bind(SwarmScope::Group(group_id.clone()).label().unwrap())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(active_version, second_join_frame.record_id);

    let before_remove = summary_frame(
        &first.node_id(),
        &network_id,
        &group_id,
        "summary-before-remove",
    );
    let mut published = false;
    for _ in 0..5 {
        match service::publish(
            &pool,
            &adapter,
            &gateway_config,
            &first_session,
            &before_remove,
        )
        .await
        {
            Ok(_) => {
                published = true;
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    assert!(
        published,
        "membership fanout publish must confirm after bindings activate"
    );
    let mut changed_retry = before_remove.clone();
    changed_retry.payload = OpaqueSignedRecord::new(
        serde_json::to_vec(&SummaryAnnouncement {
            summary_id: "summary-before-remove".to_owned(),
            source_node_id: first.node_id(),
            scope: SwarmScope::Group(group_id.clone()),
            summary_kind: "contract".to_owned(),
            artifact_path: None,
            payload: serde_json::json!({"contract": "changed"}),
        })
        .unwrap(),
    )
    .unwrap();
    assert!(
        service::publish(
            &pool,
            &adapter,
            &gateway_config,
            &first_session,
            &changed_retry,
        )
        .await
        .is_err(),
        "an idempotency key cannot accept a changed immutable record"
    );
    let second_page = adapter
        .pull_page(
            &network_id,
            &second.node_id(),
            DeliveryClass::Bulk,
            "before-remove",
            Uuid::new_v4(),
            8,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(
        second_page
            .deliveries
            .iter()
            .any(|delivery| delivery.record_id == "summary-before-remove")
    );
    adapter
        .commit_page(
            &second_page.page_id,
            &second.node_id(),
            DeliveryClass::Bulk,
            second_page.consumer_epoch,
        )
        .await
        .unwrap();

    let removal_frame = subscription_frame(&second, &network_id, &group_id, false, 3);
    service::publish(
        &pool,
        &adapter,
        &gateway_config,
        &second_session,
        &removal_frame,
    )
    .await
    .unwrap();
    service::publish(
        &pool,
        &adapter,
        &gateway_config,
        &first_session,
        &summary_frame(
            &first.node_id(),
            &network_id,
            &group_id,
            "summary-after-remove",
        ),
    )
    .await
    .unwrap();
    if let Some(page) = adapter
        .pull_page(
            &network_id,
            &second.node_id(),
            DeliveryClass::Bulk,
            "after-remove",
            Uuid::new_v4(),
            8,
        )
        .await
        .unwrap()
    {
        assert!(
            page.deliveries.iter().all(|delivery| {
                delivery.record_id != "summary-after-remove"
                    && delivery.record_id != removal_frame.record_id
            }),
            "removed member must not receive the removal version or later records"
        );
        adapter
            .commit_page(
                &page.page_id,
                &second.node_id(),
                DeliveryClass::Bulk,
                page.consumer_epoch,
            )
            .await
            .unwrap();
    }

    let internal = http::internal_router(http::AppState {
        pool: pool.clone(),
        config: Arc::new(gateway_config),
        rabbit: adapter,
    });
    let response = internal
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/internal/v1/observability?network_id={network_id}"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let response_body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "observability response: {}",
        String::from_utf8_lossy(&response_body)
    );
    let body: serde_json::Value = serde_json::from_slice(&response_body).unwrap();
    assert_eq!(body["backend"], "client_server");
    assert_eq!(body["cell"]["active_tenants"], 3);
    assert_eq!(body["cell"]["interactive_mailbox_queues"], 3);
    assert_eq!(body["cell"]["bulk_mailbox_queues"], 3);
    assert_eq!(body["cell"]["observed_mailbox_queues"], 6);
    assert_eq!(body["mailbox"]["missing_mailbox_queues"], 0);
    assert_eq!(body["membership"]["binding_drift"], 0);
    assert_eq!(body["membership"]["version_drift"], 0);
    assert!(body["runtime"]["binding_attempts"].as_u64().unwrap() >= 3);
    assert!(
        !body.to_string().contains("contract-password"),
        "operational diagnostics must not expose Broker or commit secrets"
    );
}

#[tokio::test]
#[ignore = "requires real TLS RabbitMQ and PostgreSQL; run through scripts/run-message-gateway-contract.sh"]
async fn real_rabbitmq_ttl_capacity_delivery_limit_and_gap_contract() {
    let adapter = RabbitAdapter::connect(Arc::new(config())).await.unwrap();
    let pool = contract_pool().await;
    let expired_principal = "principal-expired";
    let expired_route = EventTransportRoute::from_kind_label(
        SwarmScope::Node(expired_principal.to_owned()),
        PropagationLane::Messages,
        "TopicMessagePosted",
        false,
    )
    .unwrap();
    adapter
        .publish(Some(expired_principal), &record(expired_route, "expired-1"))
        .await
        .unwrap();

    let mut expired_recorded = false;
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        adapter.drain_dead_letters(&pool, 16).await.unwrap();
        let page = gaps::load_for_page(
            &pool,
            "network-contract",
            expired_principal,
            DeliveryClass::Interactive,
            "gap-expired",
            8,
            Duration::from_secs(30),
        )
        .await
        .unwrap();
        if page
            .iter()
            .any(|gap| gap.reason == wattswarm_network_transport_core::MailboxGapReason::Expired)
        {
            expired_recorded = true;
            break;
        }
    }
    assert!(expired_recorded, "expired mailbox record must become a gap");
    assert!(
        gaps::load_for_page(
            &pool,
            "network-contract",
            expired_principal,
            DeliveryClass::Interactive,
            "gap-expired-too-early",
            8,
            Duration::from_secs(30),
        )
        .await
        .unwrap()
        .is_empty(),
        "a gap assigned to an active page must not be delivered twice"
    );
    assert!(
        gaps::load_for_page(
            &pool,
            "network-contract",
            expired_principal,
            DeliveryClass::Interactive,
            "gap-expired-redelivery",
            8,
            Duration::ZERO,
        )
        .await
        .unwrap()
        .iter()
        .any(|gap| gap.reason == wattswarm_network_transport_core::MailboxGapReason::Expired),
        "a gap must be recoverable after its page owner lease expires"
    );

    let poison_principal = "principal-poison";
    let poison_route = EventTransportRoute::from_kind_label(
        SwarmScope::Node(poison_principal.to_owned()),
        PropagationLane::Messages,
        "TopicMessagePosted",
        false,
    )
    .unwrap();
    adapter
        .publish(
            Some(poison_principal),
            &record(poison_route.clone(), "poison-1"),
        )
        .await
        .unwrap();
    for attempt in 0..5 {
        let Some(page) = adapter
            .pull_page(
                "network-contract",
                poison_principal,
                DeliveryClass::Interactive,
                &format!("poison-page-{attempt}"),
                Uuid::new_v4(),
                1,
            )
            .await
            .unwrap()
        else {
            break;
        };
        adapter.abandon_page(&page.page_id).await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    let mut delivery_limit_recorded = false;
    for _ in 0..20 {
        adapter.drain_dead_letters(&pool, 16).await.unwrap();
        let page = gaps::load_for_page(
            &pool,
            "network-contract",
            poison_principal,
            DeliveryClass::Interactive,
            "gap-poison",
            8,
            Duration::from_secs(30),
        )
        .await
        .unwrap();
        if page.iter().any(|gap| {
            gap.reason == wattswarm_network_transport_core::MailboxGapReason::DeliveryLimitExceeded
        }) {
            delivery_limit_recorded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        delivery_limit_recorded,
        "delivery-limit dead letter must become a gap"
    );

    let capacity_principal = "principal-capacity";
    let capacity_route = EventTransportRoute::from_kind_label(
        SwarmScope::Node(capacity_principal.to_owned()),
        PropagationLane::Messages,
        "TopicMessagePosted",
        false,
    )
    .unwrap();
    let mut capacity_rejected = false;
    for index in 0..8 {
        let oversized = BrokerRecord {
            record: OpaqueSignedRecord::new(vec![b'x'; 16_384]).unwrap(),
            ..record(capacity_route.clone(), &format!("oversized-{index}"))
        };
        if adapter
            .publish(Some(capacity_principal), &oversized)
            .await
            .is_err()
        {
            capacity_rejected = true;
            break;
        }
    }
    assert!(capacity_rejected, "reject-publish capacity limit must nack");
}

#[tokio::test]
#[ignore = "requires real TLS RabbitMQ; run through scripts/run-message-gateway-contract.sh"]
async fn real_rabbitmq_confirm_fanout_manual_ack_and_redelivery_contract() {
    let mut gateway_config = config();
    gateway_config.delivery_owner_lease = Duration::from_millis(200);
    let adapter = RabbitAdapter::connect(Arc::new(gateway_config))
        .await
        .unwrap();
    let direct_route = EventTransportRoute::from_kind_label(
        SwarmScope::Node("principal-a".to_owned()),
        PropagationLane::Messages,
        "TopicMessagePosted",
        false,
    )
    .unwrap();
    adapter
        .ensure_tenant_mailboxes("network-isolated", "principal-a")
        .await
        .unwrap();
    adapter
        .publish(Some("principal-a"), &record(direct_route, "direct-1"))
        .await
        .unwrap();
    assert!(
        adapter
            .pull_page(
                "network-isolated",
                "principal-a",
                DeliveryClass::Interactive,
                "page-cross-network",
                Uuid::new_v4(),
                8,
            )
            .await
            .unwrap()
            .is_none(),
        "the same principal id in another network must not receive the direct delivery"
    );
    let first = adapter
        .pull_page(
            "network-contract",
            "principal-a",
            DeliveryClass::Interactive,
            "page-direct-1",
            Uuid::new_v4(),
            8,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.deliveries.len(), 1);
    assert!(adapter.abandon_page(&first.page_id).await.unwrap());
    tokio::time::sleep(Duration::from_millis(300)).await;
    let redelivered = adapter
        .pull_page(
            "network-contract",
            "principal-a",
            DeliveryClass::Interactive,
            "page-direct-2",
            Uuid::new_v4(),
            8,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        redelivered.deliveries[0].delivery_id,
        first.deliveries[0].delivery_id
    );
    assert_eq!(
        adapter
            .commit_page(
                &redelivered.page_id,
                "principal-a",
                DeliveryClass::Interactive,
                redelivered.consumer_epoch,
            )
            .await
            .unwrap(),
        Some(1)
    );

    let lease_principal = "principal-lease-expiry";
    let lease_route = EventTransportRoute::from_kind_label(
        SwarmScope::Node(lease_principal.to_owned()),
        PropagationLane::Messages,
        "TopicMessagePosted",
        false,
    )
    .unwrap();
    adapter
        .publish(
            Some(lease_principal),
            &record(lease_route, "lease-expiry-1"),
        )
        .await
        .unwrap();
    let expired_page = adapter
        .pull_page(
            "network-contract",
            lease_principal,
            DeliveryClass::Interactive,
            "page-lease-expiry-1",
            Uuid::new_v4(),
            8,
        )
        .await
        .unwrap()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(adapter.reap_expired_pages().await.unwrap(), 1);
    let lease_redelivery = adapter
        .pull_page(
            "network-contract",
            lease_principal,
            DeliveryClass::Interactive,
            "page-lease-expiry-2",
            Uuid::new_v4(),
            8,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        lease_redelivery.deliveries[0].delivery_id, expired_page.deliveries[0].delivery_id,
        "an uncommitted page must requeue when its owner lease expires"
    );
    adapter
        .commit_page(
            &lease_redelivery.page_id,
            lease_principal,
            DeliveryClass::Interactive,
            lease_redelivery.consumer_epoch,
        )
        .await
        .unwrap();

    let control_route = EventTransportRoute::from_kind_label(
        SwarmScope::Node("principal-a".to_owned()),
        PropagationLane::Events,
        "ClientServerControl",
        false,
    )
    .unwrap();
    adapter
        .publish_control(&BrokerControlRecord {
            network_id: "network-contract".to_owned(),
            correlation_id: "control-1".to_owned(),
            source_principal_id: "principal-sender".to_owned(),
            target_principal_id: "principal-a".to_owned(),
            control_kind: "contact_request".to_owned(),
            payload: OpaqueSignedRecord::new(br#"{"kind":"contact_request"}"#.to_vec()).unwrap(),
            gap_route: control_route,
            delivery_policy_version: wattswarm_network_client_server::DELIVERY_POLICY_VERSION,
            enqueued_at: 1,
            expires_at: None,
        })
        .await
        .unwrap();
    let control_page = adapter
        .pull_page(
            "network-contract",
            "principal-a",
            DeliveryClass::Interactive,
            "page-control-1",
            Uuid::new_v4(),
            8,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(control_page.controls.len(), 1);
    assert_eq!(control_page.controls[0].correlation_id, "control-1");
    adapter
        .commit_page(
            &control_page.page_id,
            "principal-a",
            DeliveryClass::Interactive,
            control_page.consumer_epoch,
        )
        .await
        .unwrap();

    let group_route = EventTransportRoute::from_kind_label(
        SwarmScope::Group("hive-1".to_owned()),
        PropagationLane::Messages,
        "TopicMessagePosted",
        false,
    )
    .unwrap();
    for principal in ["principal-a", "principal-b"] {
        adapter
            .bind_scope_member("network-contract", principal, &group_route.address, "v1")
            .await
            .unwrap();
    }
    adapter
        .bind_scope_member(
            "network-isolated",
            "principal-a",
            &group_route.address,
            "v1",
        )
        .await
        .unwrap();
    adapter
        .publish(None, &record(group_route.clone(), "group-1"))
        .await
        .unwrap();
    assert!(
        adapter
            .pull_page(
                "network-isolated",
                "principal-a",
                DeliveryClass::Interactive,
                "page-cross-network-scope",
                Uuid::new_v4(),
                8,
            )
            .await
            .unwrap()
            .is_none(),
        "the same scope/version in another network must not receive the fanout"
    );
    for principal in ["principal-a", "principal-b"] {
        let page = adapter
            .pull_page(
                "network-contract",
                principal,
                DeliveryClass::Interactive,
                &format!("page-{principal}"),
                Uuid::new_v4(),
                8,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(page.deliveries.len(), 1);
        adapter
            .commit_page(
                &page.page_id,
                principal,
                DeliveryClass::Interactive,
                page.consumer_epoch,
            )
            .await
            .unwrap();
    }

    let mut self_filtered = record(group_route.clone(), "group-self-filtered");
    self_filtered.source_principal_id = "principal-a".to_owned();
    adapter.publish(None, &self_filtered).await.unwrap();
    assert!(
        adapter
            .pull_page(
                "network-contract",
                "principal-a",
                DeliveryClass::Interactive,
                "page-self-filtered-author",
                Uuid::new_v4(),
                8,
            )
            .await
            .unwrap()
            .is_none(),
        "scope author must not receive its own logical mailbox delivery"
    );
    let recipient_page = adapter
        .pull_page(
            "network-contract",
            "principal-b",
            DeliveryClass::Interactive,
            "page-self-filtered-recipient",
            Uuid::new_v4(),
            8,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        recipient_page.deliveries[0].record_id,
        "group-self-filtered"
    );
    adapter
        .commit_page(
            &recipient_page.page_id,
            "principal-b",
            DeliveryClass::Interactive,
            recipient_page.consumer_epoch,
        )
        .await
        .unwrap();

    let unrouted = EventTransportRoute::from_kind_label(
        SwarmScope::Group("no-bindings".to_owned()),
        PropagationLane::Messages,
        "TopicMessagePosted",
        false,
    )
    .unwrap();
    assert!(
        adapter
            .publish(None, &record(unrouted, "unrouted-1"))
            .await
            .is_err()
    );
}
