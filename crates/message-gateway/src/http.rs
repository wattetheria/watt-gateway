use crate::auth;
use crate::commit_token::{CommitClaims, issue, verify};
use crate::config::Config;
use crate::gaps;
use crate::rabbit::RabbitAdapter;
use crate::service;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use wattswarm_network_client_server::{
    ChallengeRequest, ChallengeResponse, CommitRequest, ControlAcceptance, ControlFrame,
    PublishAcceptance, PublishFrame, SessionProofRequest, SessionResponse,
};
use wattswarm_network_transport_core::MailboxBinding;
use wattswarm_network_transport_core::{DeliveryClass, DeliveryPage};

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Arc<Config>,
    pub rabbit: RabbitAdapter,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        // Temporarily disabled until the Wattswarm Grant API is published at
        // the pinned revision used by the production Docker build. Keep the
        // implementation below for re-enabling with the matching revision.
        .route("/v1/session/challenge", post(challenge))
        .route("/v1/session/proof", post(proof))
        .route("/v1/publish", post(publish))
        .route("/v1/control", post(send_control))
        .route("/v1/mailbox/page", get(pull_page))
        .route("/v1/mailbox/commit", post(commit_page))
        .route("/v1/objects/{digest}", get(fetch_object))
        .with_state(state)
}

pub fn internal_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/internal/v1/observability", get(observability))
        .route("/internal/v1/mailbox/commit", post(commit_owned_page))
        .with_state(state)
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({"ok": true, "service": "wattswarm-message-gateway"}))
}

/*
 * Temporarily disabled: this endpoint depends on NetworkMembershipGrant types
 * that are not available in the Wattswarm revision pinned by the production
 * Docker build. Do not remove; re-enable after the Wattswarm Grant changes are
 * published and the Docker pin is advanced.
async fn admit_grant(
    State(state): State<AppState>,
    Json(request): Json<GrantAdmissionRequest>,
) -> ApiResult<Json<GrantAdmissionResponse>> {
    Ok(Json(
        service::admit_grant(&state.pool, &state.rabbit, &state.config, &request).await?,
    ))
}
*/

async fn challenge(
    State(state): State<AppState>,
    Json(request): Json<ChallengeRequest>,
) -> ApiResult<Json<ChallengeResponse>> {
    let principal = request
        .principals
        .first()
        .ok_or_else(|| ApiError::bad_request("one principal is required"))?;
    service::ensure_tenant_transport_admission(
        &state.pool,
        &state.rabbit,
        &state.config,
        &request.network_id,
        &principal.principal_id,
    )
    .await?;
    Ok(Json(auth::create_challenge(&state.pool, &request).await?))
}

async fn proof(
    State(state): State<AppState>,
    Json(request): Json<SessionProofRequest>,
) -> ApiResult<Json<SessionResponse>> {
    db_admission(&state, &request.network_id).await?;
    let result = auth::prove_session(&state.pool, &state.config, &request).await;
    state.rabbit.observability().record_session(result.is_ok());
    Ok(Json(result?))
}

#[derive(Debug, Deserialize)]
struct ObservabilityQuery {
    network_id: String,
}

async fn observability(
    State(state): State<AppState>,
    Query(query): Query<ObservabilityQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    if query.network_id.trim().is_empty() {
        return Err(ApiError::bad_request("network_id is required"));
    }
    Ok(Json(
        crate::observability::operational_snapshot(
            &state.pool,
            &state.config,
            &state.rabbit,
            &query.network_id,
        )
        .await?,
    ))
}

async fn db_admission(state: &AppState, network_id: &str) -> ApiResult<()> {
    crate::db::validate_active_tenant_admission(&state.pool, &state.config, network_id).await?;
    Ok(())
}

async fn publish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(frame): Json<PublishFrame>,
) -> ApiResult<Json<PublishAcceptance>> {
    let session = session(&state, &headers).await?;
    let result =
        service::publish(&state.pool, &state.rabbit, &state.config, &session, &frame).await;
    if result
        .as_ref()
        .err()
        .is_some_and(|error| error.to_string().contains("membership version"))
    {
        state
            .rabbit
            .observability()
            .record_old_membership_version_rejection();
    }
    Ok(Json(result?))
}

async fn send_control(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(frame): Json<ControlFrame>,
) -> ApiResult<Json<ControlAcceptance>> {
    let session = session(&state, &headers).await?;
    Ok(Json(
        service::send_control(&state.pool, &state.rabbit, &state.config, &session, &frame).await?,
    ))
}

#[derive(Debug, Deserialize)]
struct PageQuery {
    delivery_class: DeliveryClass,
    limit: Option<usize>,
}

async fn pull_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> ApiResult<Response> {
    let session = session(&state, &headers).await?;
    let limit = query
        .limit
        .unwrap_or(state.config.delivery_page_size)
        .min(state.config.delivery_page_size);
    let page_id = Uuid::new_v4().to_string();
    let consumer_epoch = Uuid::new_v4();
    let acquired = crate::db::try_acquire_delivery_owner(
        &state.pool,
        &session.network_id,
        &session.principal_id,
        query.delivery_class,
        &state.config.instance_id,
        consumer_epoch,
        state.config.internal_route.as_deref(),
        state.config.delivery_owner_lease,
    )
    .await?;
    let (page, gaps) = if acquired {
        let page = state
            .rabbit
            .pull_page(
                &session.network_id,
                &session.principal_id,
                query.delivery_class,
                &page_id,
                consumer_epoch,
                limit,
            )
            .await?;
        let gaps = gaps::load_for_page(
            &state.pool,
            &session.network_id,
            &session.principal_id,
            query.delivery_class,
            &page_id,
            limit,
            state.config.delivery_owner_lease,
        )
        .await?;
        if page.is_none() && gaps.is_empty() {
            crate::db::release_delivery_owner(
                &state.pool,
                &session.network_id,
                &session.principal_id,
                query.delivery_class,
                &state.config.instance_id,
                consumer_epoch,
            )
            .await?;
        }
        (page, gaps)
    } else {
        (None, Vec::new())
    };
    if page.is_none() && gaps.is_empty() {
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    let consumer_epoch = page
        .as_ref()
        .map(|page| page.consumer_epoch)
        .unwrap_or(consumer_epoch);
    let commit_token = issue(
        &state.config.commit_hmac_secret,
        &CommitClaims {
            page_id: page_id.clone(),
            network_id: session.network_id.clone(),
            principal_id: session.principal_id.clone(),
            delivery_class: query.delivery_class,
            owner_instance_id: state.config.instance_id.clone(),
            consumer_epoch,
            expires_at: now_ms().saturating_add(
                u64::try_from(state.config.delivery_owner_lease.as_millis()).unwrap_or(u64::MAX),
            ),
        },
    )?;
    let binding = page
        .as_ref()
        .map(|page| page.binding.clone())
        .unwrap_or(MailboxBinding {
            network_id: session.network_id.clone(),
            recipient_principal_id: session.principal_id.clone(),
            delivery_class: query.delivery_class,
        });
    let (deliveries, controls) = page
        .map(|page| (page.deliveries, page.controls))
        .unwrap_or_default();
    let response = DeliveryPage {
        page_id,
        binding,
        deliveries,
        controls,
        gaps,
        commit_token,
    };
    response.validate()?;
    Ok(Json(response).into_response())
}

async fn commit_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CommitRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let session = session(&state, &headers).await?;
    let claims = verify(
        &state.config.commit_hmac_secret,
        &request.commit_token,
        now_ms(),
    )?;
    if claims.page_id != request.page_id
        || claims.network_id != session.network_id
        || claims.principal_id != session.principal_id
        || claims.delivery_class != request.delivery_class
    {
        return Err(ApiError::bad_request("commit token binding mismatch"));
    }
    let commit_started = std::time::Instant::now();
    let forwarded = claims.owner_instance_id != state.config.instance_id;
    let commit_result = if !forwarded {
        commit_local_deliveries(&state, &claims).await
    } else {
        forward_commit_to_owner(&state, &request, &claims).await
    };
    state
        .rabbit
        .observability()
        .record_commit(commit_started, forwarded, commit_result.is_ok());
    let committed_deliveries = commit_result?;
    let committed_gaps = gaps::acknowledge_page(
        &state.pool,
        &session.network_id,
        &session.principal_id,
        request.delivery_class,
        &request.page_id,
    )
    .await?;
    if committed_gaps > 0 {
        crate::db::release_delivery_owner(
            &state.pool,
            &claims.network_id,
            &claims.principal_id,
            claims.delivery_class,
            &claims.owner_instance_id,
            claims.consumer_epoch,
        )
        .await?;
    }
    if committed_deliveries.is_none() && committed_gaps == 0 {
        return Err(ApiError::bad_request(
            "page owner is gone or already committed",
        ));
    }
    Ok(Json(json!({
        "ok": true,
        "committed_deliveries": committed_deliveries.unwrap_or_default(),
        "committed_gaps": committed_gaps,
    })))
}

async fn commit_owned_page(
    State(state): State<AppState>,
    Json(request): Json<CommitRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let commit_started = std::time::Instant::now();
    let claims = verify(
        &state.config.commit_hmac_secret,
        &request.commit_token,
        now_ms(),
    )?;
    if claims.page_id != request.page_id
        || claims.delivery_class != request.delivery_class
        || claims.owner_instance_id != state.config.instance_id
    {
        return Err(ApiError::bad_request(
            "internal commit owner binding mismatch",
        ));
    }
    let committed = commit_local_deliveries(&state, &claims).await;
    state
        .rabbit
        .observability()
        .record_commit(commit_started, false, committed.is_ok());
    let committed = committed?;
    Ok(Json(json!({"committed_deliveries": committed})))
}

async fn commit_local_deliveries(
    state: &AppState,
    claims: &CommitClaims,
) -> ApiResult<Option<usize>> {
    let owner = crate::db::load_delivery_owner(
        &state.pool,
        &claims.network_id,
        &claims.principal_id,
        claims.delivery_class,
    )
    .await?
    .ok_or_else(|| ApiError::bad_request("delivery owner lease is gone; page will requeue"))?;
    if owner.instance_id != claims.owner_instance_id
        || owner.consumer_epoch != claims.consumer_epoch
        || owner.instance_id != state.config.instance_id
    {
        return Err(ApiError::bad_request(
            "delivery owner epoch changed; old commit token is invalid",
        ));
    }
    let committed = state
        .rabbit
        .commit_page(
            &claims.page_id,
            &claims.principal_id,
            claims.delivery_class,
            claims.consumer_epoch,
        )
        .await?;
    if committed.is_some() {
        crate::db::release_delivery_owner(
            &state.pool,
            &claims.network_id,
            &claims.principal_id,
            claims.delivery_class,
            &claims.owner_instance_id,
            claims.consumer_epoch,
        )
        .await?;
    }
    Ok(committed)
}

async fn forward_commit_to_owner(
    state: &AppState,
    request: &CommitRequest,
    claims: &CommitClaims,
) -> ApiResult<Option<usize>> {
    let owner = crate::db::load_delivery_owner(
        &state.pool,
        &claims.network_id,
        &claims.principal_id,
        claims.delivery_class,
    )
    .await?
    .ok_or_else(|| ApiError::bad_request("delivery owner lease is gone; page will requeue"))?;
    if owner.instance_id != claims.owner_instance_id
        || owner.consumer_epoch != claims.consumer_epoch
        || owner.owner_route.is_empty()
    {
        return Err(ApiError::bad_request(
            "delivery owner epoch changed; old commit token is invalid",
        ));
    }
    let identity = state
        .config
        .internal_mtls_identity_pem
        .as_deref()
        .ok_or_else(|| ApiError::bad_request("owner forwarding mTLS identity is unavailable"))?;
    let ca = state
        .config
        .internal_mtls_ca_pem
        .as_deref()
        .ok_or_else(|| ApiError::bad_request("owner forwarding mTLS CA is unavailable"))?;
    let response = reqwest::Client::builder()
        .timeout(state.config.delivery_commit_forward_timeout)
        .identity(reqwest::Identity::from_pem(identity)?)
        .add_root_certificate(reqwest::Certificate::from_pem(ca)?)
        .build()?
        .post(format!(
            "{}/internal/v1/mailbox/commit",
            owner.owner_route.trim_end_matches('/')
        ))
        .json(request)
        .send()
        .await?
        .error_for_status()?;
    let body: serde_json::Value = response.json().await?;
    Ok(body
        .get("committed_deliveries")
        .and_then(serde_json::Value::as_u64)
        .map(|count| count as usize))
}

async fn fetch_object(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(digest): AxumPath<String>,
) -> ApiResult<Response> {
    let session = session(&state, &headers).await?;
    let expected = digest.strip_prefix("sha256:").unwrap_or(&digest);
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ApiError::bad_request("invalid SHA-256 object digest"));
    }
    let Some(root) = state.config.object_store_root.as_ref() else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    let network_root = hex::encode(Sha256::digest(session.network_id.as_bytes()));
    let path = root.join(network_root).join(&digest);
    let metadata = match tokio::fs::metadata(&path).await {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(_) | Err(_) => return Ok(StatusCode::NOT_FOUND.into_response()),
    };
    if metadata.len() > state.config.max_object_bytes {
        return Err(ApiError::bad_request(
            "object exceeds configured read limit",
        ));
    }
    let bytes = tokio::fs::read(path).await?;
    if hex::encode(Sha256::digest(&bytes)) != expected.to_ascii_lowercase() {
        return Err(ApiError::bad_request("stored object digest mismatch"));
    }
    Ok((
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "application/octet-stream"),
            (
                axum::http::header::CACHE_CONTROL,
                "private, immutable, max-age=31536000",
            ),
        ],
        bytes,
    )
        .into_response())
}

async fn session(state: &AppState, headers: &HeaderMap) -> ApiResult<auth::VerifiedSession> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::unauthorized("missing bearer token"))?;
    auth::verify_bearer(&state.pool, value)
        .await
        .map_err(|_| ApiError::unauthorized("invalid or expired session"))
}

type ApiResult<T> = std::result::Result<T, ApiError>;

pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn unauthorized(message: &str) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.to_owned(),
        }
    }

    fn bad_request(message: &str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.to_owned(),
        }
    }
}

impl<E> From<E> for ApiError
where
    E: Into<anyhow::Error>,
{
    fn from(error: E) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: format!("{:#}", error.into()),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({"ok": false, "error": self.message})),
        )
            .into_response()
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
