use crate::config::Config;
use crate::db;
use anyhow::{Context, Result, bail};
use chrono::{Duration, Utc};
use rand::RngCore;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use uuid::Uuid;
use wattswarm_network_client_server::{
    ChallengeRequest, ChallengeResponse, HistoryStatus, SessionProofRequest, SessionResponse,
    session_proof_message,
};

#[derive(Debug, Clone)]
pub struct VerifiedSession {
    pub session_id: Uuid,
    pub network_id: String,
    pub principal_id: String,
}

pub async fn create_challenge(
    pool: &PgPool,
    request: &ChallengeRequest,
) -> Result<ChallengeResponse> {
    if request.principals.len() != 1 {
        bail!("Message Gateway V1 accepts exactly one principal");
    }
    let claim = &request.principals[0];
    if claim.principal_id != claim.public_key_hex {
        bail!("principal id must match its Ed25519 public key");
    }
    if claim
        .tenant_instance_id
        .as_ref()
        .is_some_and(|value| value.trim().is_empty() || value.len() > 128)
    {
        bail!("tenant instance id must be non-empty and at most 128 bytes");
    }
    if !db::principal_is_admitted(pool, &request.network_id, &claim.principal_id).await? {
        bail!("principal is not an active network member");
    }
    let challenge_id = Uuid::new_v4();
    let mut nonce = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    let expires_at = Utc::now() + Duration::minutes(2);
    sqlx::query(
        "INSERT INTO gateway_challenges(
             challenge_id, network_id, principals_json, nonce, expires_at
         ) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(challenge_id)
    .bind(&request.network_id)
    .bind(serde_json::to_value(&request.principals)?)
    .bind(hex::encode(nonce))
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(ChallengeResponse {
        challenge_id: challenge_id.to_string(),
        nonce: hex::encode(nonce),
        expires_at: expires_at.timestamp_millis() as u64,
    })
}

pub async fn prove_session(
    pool: &PgPool,
    config: &Config,
    request: &SessionProofRequest,
) -> Result<SessionResponse> {
    if request.principals.len() != 1 || request.proofs.len() != 1 {
        bail!("Message Gateway V1 requires one complete principal proof");
    }
    if request.delivery_policy_version != wattswarm_network_client_server::DELIVERY_POLICY_VERSION {
        bail!("delivery policy version mismatch");
    }
    let challenge_id = Uuid::parse_str(&request.challenge_id)?;
    let mut tx = pool.begin().await?;
    let row = sqlx::query(
        "SELECT network_id, principals_json, nonce, expires_at
         FROM gateway_challenges
         WHERE challenge_id = $1 AND consumed_at IS NULL
         FOR UPDATE",
    )
    .bind(challenge_id)
    .fetch_one(&mut *tx)
    .await
    .context("unknown or consumed challenge")?;
    let network_id: String = row.try_get("network_id")?;
    let principals_json: Value = row.try_get("principals_json")?;
    let nonce: String = row.try_get("nonce")?;
    let expires_at: chrono::DateTime<Utc> = row.try_get("expires_at")?;
    if network_id != request.network_id
        || principals_json != serde_json::to_value(&request.principals)?
        || expires_at <= Utc::now()
    {
        bail!("challenge binding or expiry validation failed");
    }
    let claim = &request.principals[0];
    let proof = &request.proofs[0];
    if proof.principal_id != claim.principal_id
        || !db::principal_is_admitted(pool, &network_id, &claim.principal_id).await?
    {
        bail!("principal proof is not admitted");
    }
    let challenge = ChallengeResponse {
        challenge_id: challenge_id.to_string(),
        nonce,
        expires_at: expires_at.timestamp_millis() as u64,
    };
    let message = session_proof_message(&network_id, &request.principals, &challenge)?;
    wattswarm_crypto::verify_signature(&claim.public_key_hex, &message, &proof.signature_hex)?;
    let history_status = match claim.tenant_instance_id.as_deref() {
        Some(instance_id) => {
            if db::register_principal_instance(
                &mut tx,
                &network_id,
                &claim.principal_id,
                instance_id,
            )
            .await?
            {
                HistoryStatus::HistoryUnavailable
            } else {
                HistoryStatus::CurrentMailboxOnly
            }
        }
        None => HistoryStatus::CurrentMailboxOnly,
    };
    sqlx::query(
        "UPDATE gateway_challenges SET consumed_at = clock_timestamp() WHERE challenge_id = $1",
    )
    .bind(challenge_id)
    .execute(&mut *tx)
    .await?;
    let session_id = Uuid::new_v4();
    let token = format!("{}.{}", session_id, Uuid::new_v4());
    let token_hash = hash_token(&token);
    let session_expires = Utc::now()
        + Duration::from_std(config.session_ttl).context("session TTL outside chrono range")?;
    sqlx::query(
        "INSERT INTO gateway_sessions(session_id, token_hash, network_id, expires_at)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(session_id)
    .bind(token_hash)
    .bind(&network_id)
    .bind(session_expires)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO gateway_session_principals(
             session_id, principal_id, verified_at, expires_at
         ) VALUES ($1, $2, clock_timestamp(), $3)",
    )
    .bind(session_id)
    .bind(&claim.principal_id)
    .bind(session_expires)
    .execute(&mut *tx)
    .await?;
    db::record_audit(
        &mut tx,
        Some(&network_id),
        Some(&claim.principal_id),
        "session_proof",
        "accepted",
        serde_json::json!({
            "delivery_policy_version": request.delivery_policy_version,
            "history_status": history_status,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(SessionResponse {
        session_token: token,
        network_id,
        principal_id: claim.principal_id.clone(),
        delivery_policy_version: request.delivery_policy_version,
        history_status,
        expires_at: session_expires.timestamp_millis() as u64,
    })
}

pub async fn verify_bearer(pool: &PgPool, token: &str) -> Result<VerifiedSession> {
    if token.trim().is_empty() {
        bail!("missing bearer token");
    }
    let row = sqlx::query(
        "SELECT s.session_id, s.network_id, p.principal_id
         FROM gateway_sessions s
         JOIN gateway_session_principals p ON p.session_id = s.session_id
         WHERE s.token_hash = $1 AND s.expires_at > clock_timestamp()
           AND p.expires_at > clock_timestamp()",
    )
    .bind(hash_token(token))
    .fetch_one(pool)
    .await
    .context("invalid or expired session")?;
    let session = VerifiedSession {
        session_id: row.try_get("session_id")?,
        network_id: row.try_get("network_id")?,
        principal_id: row.try_get("principal_id")?,
    };
    if !db::principal_is_admitted(pool, &session.network_id, &session.principal_id).await? {
        bail!("session principal is no longer admitted");
    }
    Ok(session)
}

fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}
