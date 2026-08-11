use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;
use wattetheria_message_gateway::{auth, config::Config, db};
use wattswarm_crypto::NodeIdentity;
use wattswarm_network_client_server::{
    ChallengeRequest, HistoryStatus, LogicalNodePrincipalClaim, LogicalNodePrincipalProof,
    SessionProofRequest, session_proof_message,
};
use wattswarm_network_transport_core::DeliveryClass;

fn database_url() -> String {
    std::env::var("WATTSWARM_MESSAGE_GATEWAY_TEST_DATABASE_URL")
        .expect("real PostgreSQL contract URL is required")
}

fn config(database_url: String) -> Config {
    Config {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        database_url,
        rabbitmq_endpoint: "amqps://localhost/%2fwattswarm".to_owned(),
        rabbitmq_username: "test".to_owned(),
        rabbitmq_password: "test-password".to_owned(),
        rabbitmq_prefetch: 16,
        delivery_page_size: 8,
        mailbox_message_ttl_ms: 60_000,
        mailbox_max_length_bytes: 1_000_000,
        dead_letter_max_length_bytes: 1_000_000,
        max_delivery_attempts: 3,
        cluster_queue_limit: 1_100,
        mailbox_shard_admission_percent: 80,
        max_active_tenants: 400,
        max_fanout_recipients: 400,
        max_fanout_deliveries_per_second: 100_000,
        max_fanout_bytes_per_publish: 64 * 1024 * 1024,
        fanout_confirm_timeout: Duration::from_secs(10),
        max_global_publishes_per_second: 100,
        global_publish_burst: 20,
        global_interactive_reserved_per_second: 10,
        reserved_non_global_deliveries_per_second: 10_000,
        fanout_admission_utilization_percent: 80,
        commit_hmac_secret: vec![7; 32],
        session_ttl: Duration::from_secs(900),
        skip_grant_validation: false,
        object_store_root: Option::<PathBuf>::None,
        max_object_bytes: 64 * 1024 * 1024,
        membership_binding_timeout: Duration::from_secs(5),
        membership_mutation_window: Duration::from_secs(60),
        max_membership_mutations_per_scope_per_window: 100,
        max_membership_binding_lag: Duration::from_secs(10),
        instance_id: "contract-a".to_owned(),
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

async fn seed_global_member(
    pool: &sqlx::PgPool,
    network_id: &str,
    principal_id: &str,
    version: &str,
) {
    sqlx::query(
        "INSERT INTO gateway_scope_memberships(
             network_id, scope_label, principal_id, membership_version, state,
             authorized_at, interactive_binding_state, bulk_binding_state
         ) VALUES ($1,'global',$2,$3,'active',clock_timestamp(),'active','active')
         ON CONFLICT(network_id, scope_label, principal_id) DO UPDATE SET
             membership_version = EXCLUDED.membership_version, state = 'active', revoked_at = NULL",
    )
    .bind(network_id)
    .bind(principal_id)
    .bind(version)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO gateway_scope_versions(
             network_id, scope_label, active_membership_version, routing_fence, updated_at
         ) VALUES ($1,'global',$2,1,clock_timestamp())
         ON CONFLICT(network_id, scope_label) DO UPDATE SET
             active_membership_version = EXCLUDED.active_membership_version",
    )
    .bind(network_id)
    .bind(version)
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires the real PostgreSQL contract service"]
async fn challenge_proof_v1_membership_and_revocation_contract() {
    let pool = db::connect(&database_url()).await.unwrap();
    db::init_schema(&pool).await.unwrap();
    let identity = NodeIdentity::random();
    let principal_id = identity.node_id();
    let network_id = format!("auth-{}", Uuid::new_v4());
    seed_global_member(&pool, &network_id, &principal_id, "v1").await;
    let claim = LogicalNodePrincipalClaim {
        principal_id: principal_id.clone(),
        public_key_hex: principal_id.clone(),
        tenant_instance_id: Some("tenant-instance-a".to_owned()),
    };
    let challenge = auth::create_challenge(
        &pool,
        &ChallengeRequest {
            network_id: network_id.clone(),
            principals: vec![claim.clone()],
        },
    )
    .await
    .unwrap();
    let message =
        session_proof_message(&network_id, std::slice::from_ref(&claim), &challenge).unwrap();
    let session = auth::prove_session(
        &pool,
        &config(database_url()),
        &SessionProofRequest {
            challenge_id: challenge.challenge_id,
            network_id: network_id.clone(),
            principals: vec![claim.clone()],
            proofs: vec![LogicalNodePrincipalProof {
                principal_id: principal_id.clone(),
                signature_hex: identity.sign_bytes(&message),
            }],
            delivery_policy_version: wattswarm_network_client_server::DELIVERY_POLICY_VERSION,
        },
    )
    .await
    .unwrap();
    assert_eq!(session.history_status, HistoryStatus::CurrentMailboxOnly);
    let session_audits: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM gateway_audit
         WHERE network_id = $1 AND principal_id = $2
           AND action = 'session_proof' AND outcome = 'accepted'",
    )
    .bind(&network_id)
    .bind(&principal_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(session_audits, 1);
    assert_eq!(
        auth::verify_bearer(&pool, &session.session_token)
            .await
            .unwrap()
            .principal_id,
        principal_id
    );

    let replacement_claim = LogicalNodePrincipalClaim {
        tenant_instance_id: Some("tenant-instance-b".to_owned()),
        ..claim.clone()
    };
    let replacement_challenge = auth::create_challenge(
        &pool,
        &ChallengeRequest {
            network_id: network_id.clone(),
            principals: vec![replacement_claim.clone()],
        },
    )
    .await
    .unwrap();
    let replacement_message = session_proof_message(
        &network_id,
        std::slice::from_ref(&replacement_claim),
        &replacement_challenge,
    )
    .unwrap();
    let replacement_session = auth::prove_session(
        &pool,
        &config(database_url()),
        &SessionProofRequest {
            challenge_id: replacement_challenge.challenge_id,
            network_id: network_id.clone(),
            principals: vec![replacement_claim],
            proofs: vec![LogicalNodePrincipalProof {
                principal_id: principal_id.clone(),
                signature_hex: identity.sign_bytes(&replacement_message),
            }],
            delivery_policy_version: wattswarm_network_client_server::DELIVERY_POLICY_VERSION,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        replacement_session.history_status,
        HistoryStatus::HistoryUnavailable,
        "a new local transport state instance cannot claim unavailable mailbox history"
    );

    let second = NodeIdentity::random().node_id();
    assert!(
        auth::create_challenge(
            &pool,
            &ChallengeRequest {
                network_id: network_id.clone(),
                principals: vec![
                    claim,
                    LogicalNodePrincipalClaim {
                        principal_id: second.clone(),
                        public_key_hex: second,
                        tenant_instance_id: None,
                    },
                ],
            },
        )
        .await
        .is_err()
    );
    sqlx::query(
        "UPDATE gateway_scope_memberships SET state = 'revoked', revoked_at = clock_timestamp()
         WHERE network_id = $1 AND principal_id = $2",
    )
    .bind(&network_id)
    .bind(&principal_id)
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        auth::verify_bearer(&pool, &session.session_token)
            .await
            .is_err(),
        "membership revocation must invalidate an existing transport session"
    );
    assert!(
        auth::create_challenge(
            &pool,
            &ChallengeRequest {
                network_id: network_id.clone(),
                principals: vec![LogicalNodePrincipalClaim {
                    principal_id: principal_id.clone(),
                    public_key_hex: principal_id,
                    tenant_instance_id: Some("tenant-instance-a".to_owned()),
                }],
            },
        )
        .await
        .is_err()
    );
    sqlx::query("UPDATE gateway_challenges SET expires_at = clock_timestamp() - INTERVAL '1 second' WHERE network_id = $1")
        .bind(&network_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE gateway_sessions SET expires_at = clock_timestamp() - INTERVAL '1 second' WHERE network_id = $1")
        .bind(&network_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE gateway_audit SET created_at = clock_timestamp() - INTERVAL '2 seconds'
         WHERE network_id = $1",
    )
    .bind(&network_id)
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        db::cleanup_expired_metadata(&pool, Duration::from_secs(1))
            .await
            .unwrap()
            >= 2
    );
    let retained: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM gateway_challenges WHERE network_id = $1)
              + (SELECT COUNT(*) FROM gateway_sessions WHERE network_id = $1)",
    )
    .bind(&network_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(retained, 0);
    let retained_audit: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM gateway_audit WHERE network_id = $1")
            .bind(&network_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(retained_audit, 0);
}

#[tokio::test]
#[ignore = "requires the real PostgreSQL contract service"]
async fn token_bucket_is_shared_across_instances_and_reserves_interactive_capacity() {
    let first = db::connect(&database_url()).await.unwrap();
    let second = db::connect(&database_url()).await.unwrap();
    db::init_schema(&first).await.unwrap();
    let network_id = format!("rate-{}", Uuid::new_v4());
    let first = Arc::new(first);
    let second = Arc::new(second);
    let mut tasks = Vec::new();
    for index in 0..24 {
        let pool = if index % 2 == 0 {
            Arc::clone(&first)
        } else {
            Arc::clone(&second)
        };
        let network_id = network_id.clone();
        tasks.push(tokio::spawn(async move {
            db::acquire_global_token(
                &pool,
                &network_id,
                "cell-0",
                DeliveryClass::Interactive,
                0,
                0,
                10,
                1,
            )
            .await
            .unwrap()
        }));
    }
    let mut allowed = 0;
    for task in tasks {
        allowed += usize::from(task.await.unwrap());
    }
    assert_eq!(
        allowed, 10,
        "the cell budget must not multiply by instance count"
    );

    let reserve_network = format!("reserve-{}", Uuid::new_v4());
    for _ in 0..3 {
        assert!(
            db::acquire_global_token(
                &first,
                &reserve_network,
                "cell-0",
                DeliveryClass::Bulk,
                0,
                0,
                4,
                1,
            )
            .await
            .unwrap()
        );
    }
    assert!(
        !db::acquire_global_token(
            &second,
            &reserve_network,
            "cell-0",
            DeliveryClass::Bulk,
            0,
            0,
            4,
            1,
        )
        .await
        .unwrap()
    );
    assert!(
        db::acquire_global_token(
            &second,
            &reserve_network,
            "cell-0",
            DeliveryClass::Interactive,
            0,
            0,
            4,
            1,
        )
        .await
        .unwrap()
    );

    let non_global_network = format!("non-global-{}", Uuid::new_v4());
    assert!(
        db::acquire_non_global_delivery_tokens(&first, &non_global_network, "cell-0", 6, 10, 1,)
            .await
            .unwrap()
    );
    assert!(
        !db::acquire_non_global_delivery_tokens(&second, &non_global_network, "cell-0", 5, 10, 1,)
            .await
            .unwrap(),
        "non-Global delivery capacity must be shared across Gateway instances"
    );

    let admission_network = format!("admission-{}", Uuid::new_v4());
    let mut admission_config = config(database_url());
    admission_config.max_active_tenants = 3;
    admission_config.max_fanout_recipients = 3;
    admission_config.max_global_publishes_per_second = 1;
    admission_config.reserved_non_global_deliveries_per_second = 1;
    for index in 0..3 {
        sqlx::query(
            "INSERT INTO gateway_scope_memberships(
                 network_id, scope_label, principal_id, membership_version, state,
                 authorized_at, interactive_binding_state, bulk_binding_state
             ) VALUES ($1,'global',$2,'global-v1','active',clock_timestamp(),'active','active')",
        )
        .bind(&admission_network)
        .bind(format!("principal-{index}"))
        .execute(&*first)
        .await
        .unwrap();
    }
    assert_eq!(
        db::validate_active_tenant_admission(&first, &admission_config, &admission_network)
            .await
            .unwrap(),
        3
    );
    sqlx::query(
        "INSERT INTO gateway_scope_memberships(
             network_id, scope_label, principal_id, membership_version, state,
             authorized_at, interactive_binding_state, bulk_binding_state
         ) VALUES ($1,'global','principal-overflow','global-v1','active',clock_timestamp(),'active','active')",
    )
    .bind(&admission_network)
    .execute(&*second)
    .await
    .unwrap();
    assert!(
        db::validate_active_tenant_admission(&second, &admission_config, &admission_network)
            .await
            .is_err(),
        "admission must fail before a fourth tenant can allocate two more mailboxes"
    );

    let mutation_network = format!("mutation-{}", Uuid::new_v4());
    let mut mutation_config = config(database_url());
    mutation_config.max_membership_mutations_per_scope_per_window = 1;
    let mut mutation_tx = first.begin().await.unwrap();
    db::record_membership_mutation(
        &mut mutation_tx,
        &mutation_config,
        &mutation_network,
        "group.contract",
        "version-1",
    )
    .await
    .unwrap();
    db::record_membership_mutation(
        &mut mutation_tx,
        &mutation_config,
        &mutation_network,
        "group.contract",
        "version-1",
    )
    .await
    .unwrap();
    assert!(
        db::record_membership_mutation(
            &mut mutation_tx,
            &mutation_config,
            &mutation_network,
            "group.contract",
            "version-2",
        )
        .await
        .is_err(),
        "identical retries are coalesced but a distinct mutation consumes the window budget"
    );
    mutation_tx.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires the real PostgreSQL contract service"]
async fn delivery_owner_lease_and_database_fail_closed_contract() {
    let pool = db::connect(&database_url()).await.unwrap();
    db::init_schema(&pool).await.unwrap();
    let network_id = format!("owner-{}", Uuid::new_v4());
    let principal = "principal";
    let first_epoch = Uuid::new_v4();
    assert!(
        db::try_acquire_delivery_owner(
            &pool,
            &network_id,
            principal,
            DeliveryClass::Bulk,
            "gateway-a",
            first_epoch,
            Some("https://gateway-a.internal"),
            Duration::from_secs(30),
        )
        .await
        .unwrap()
    );
    assert!(
        !db::try_acquire_delivery_owner(
            &pool,
            &network_id,
            principal,
            DeliveryClass::Bulk,
            "gateway-b",
            Uuid::new_v4(),
            Some("https://gateway-b.internal"),
            Duration::from_secs(30),
        )
        .await
        .unwrap()
    );
    assert!(
        !db::try_acquire_delivery_owner(
            &pool,
            &network_id,
            principal,
            DeliveryClass::Bulk,
            "gateway-a",
            Uuid::new_v4(),
            Some("https://gateway-a.internal"),
            Duration::from_secs(30),
        )
        .await
        .unwrap(),
        "the same instance must not replace an active consumer epoch"
    );
    assert!(
        !db::release_delivery_owner(
            &pool,
            &network_id,
            principal,
            DeliveryClass::Bulk,
            "gateway-a",
            Uuid::new_v4(),
        )
        .await
        .unwrap()
    );
    assert!(
        db::release_delivery_owner(
            &pool,
            &network_id,
            principal,
            DeliveryClass::Bulk,
            "gateway-a",
            first_epoch,
        )
        .await
        .unwrap()
    );

    let unavailable = PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(100))
        .connect_lazy("postgres://wattswarm:bad@127.0.0.1:1/unavailable")
        .unwrap();
    assert!(
        db::acquire_global_token(
            &unavailable,
            "network",
            "cell-0",
            DeliveryClass::Interactive,
            1,
            1,
            1,
            1,
        )
        .await
        .is_err()
    );
}
