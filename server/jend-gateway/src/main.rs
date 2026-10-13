#![forbid(unsafe_code)]

mod repository;
mod secrets;

use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, OriginalUri, State},
    body::Bytes,
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use jend_admission::{AdmissionIssuer, AdmissionVerifier, RateKey, RegistrationChallenge, RiskSignals};
use jend_auth::{AuthServer, Username};
use jend_capability::{CapabilityIssuer, Permissions, SignedCapability};
use jend_gateway_core::{AccountRecord, RegistrationAdmission};
use jend_jreq::{Proof as JreqProof, Request as JreqRequest};
use jend_sync::{AccountId, DeviceSessionChallenge, DeviceSessionProof, SignedDeviceSet, SyncDeviceId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use tower_http::{limit::RequestBodyLimitLayer, timeout::TimeoutLayer, trace::TraceLayer};
use zeroize::Zeroizing;

const MAX_AUTH_BODY: usize = 64 * 1024;
const MAX_WIRE_FIELD: usize = 48 * 1024;
const ACCOUNT_CAPABILITY_MS: i64 = 5 * 60 * 1000;
const LOGIN_TICKET_DIGEST_DOMAIN: &[u8] = b"JEND/LOGIN-TICKET-DIGEST/V1";
const DEVICE_BIND_DIGEST_DOMAIN: &[u8] = b"JEND/DEVICE-BIND-CHALLENGE-DIGEST/V1";
const DEVICE_SESSION_DIGEST_DOMAIN: &[u8] = b"JEND/DEVICE-SESSION-CHALLENGE-DIGEST/V1";
const DEVICE_SESSION_MAC_DOMAIN: &[u8] = b"JEND/DEVICE-SESSION-CHALLENGE-MAC/V1";
const DEVICE_CAPABILITY_MS: i64 = 15 * 60 * 1000;
const REGISTRATION_BOOTSTRAP_MS: i64 = 10 * 60 * 1000;
const REGISTRATION_BOOTSTRAP_DIGEST_DOMAIN: &[u8] = b"JEND/REGISTRATION-DEVICE-BOOTSTRAP-DIGEST/V1";
const JREQ_HEADER: &str = "jend-request-proof";
const REQUIRED_MIGRATION_VERSION: i64 = 6;

const REQUIRED_COLUMNS_QUERY: &str = concat!(
    "SELECT COUNT(*) = 21 FROM information_schema.columns ",
    "WHERE table_schema='public' AND (table_name,column_name,udt_name) IN (",
    "('accounts','account_id','uuid'),",
    "('accounts','username','text'),",
    "('accounts','opaque_password_file','bytea'),",
    "('accounts','auth_epoch','int8'),",
    "('accounts','status','int2'),",
    "('device_sets','account_id','uuid'),",
    "('device_sets','epoch','int8'),",
    "('device_sets','signed_device_set','bytea'),",
    "('admission_buckets','bucket_key','bytea'),",
    "('admission_used_challenges','challenge_id','bytea'),",
    "('login_ip_buckets','bucket_key','bytea'),",
    "('login_account_buckets','bucket_key','bytea'),",
    "('consumed_login_tickets','ticket_digest','bytea'),",
    "('registration_device_bootstraps','bootstrap_digest','bytea'),",
    "('registration_device_bootstraps','account_id','uuid'),",
    "('consumed_device_binding_challenges','challenge_digest','bytea'),",
    "('consumed_jreq_nonces','account_id','uuid'),",
    "('consumed_jreq_nonces','device_id','bytea'),",
    "('consumed_jreq_nonces','nonce','bytea'),",
    "('device_sets','updated_at','timestamptz'),",
    "('accounts','created_at','timestamptz')",
    ")"
);

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
struct AppState {
    pool: PgPool,
    auth: Arc<AuthServer>,
    capability: Arc<CapabilityIssuer>,
    registration_admission: Arc<Mutex<RegistrationAdmission>>,
    admission_verifier: AdmissionVerifier,
    rate_hmac: Arc<Zeroizing<[u8; 32]>>,
    device_session_hmac: Arc<Zeroizing<[u8; 32]>>,
}

#[derive(Serialize)]
struct Health { status: &'static str, service: &'static str }

#[derive(Serialize)]
struct ApiErrorBody { error: &'static str }

struct ApiError(StatusCode, &'static str);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(ApiErrorBody { error: self.1 })).into_response()
    }
}

type ApiResult<T> = Result<Json<T>, ApiError>;

#[derive(Deserialize)]
struct AdmissionRequest { username: String }
#[derive(Serialize)]
struct AdmissionResponse { challenge: String, difficulty_bits: u8, expires_unix_ms: i64 }

#[derive(Deserialize)]
struct RegistrationStartRequest {
    username: String,
    challenge: String,
    solution: u64,
    opaque_request: String,
}
#[derive(Serialize)]
struct OpaqueStartResponse { opaque_response: String, ticket: String }

#[derive(Deserialize)]
struct RegistrationFinishRequest { username: String, ticket: String, upload: String }
#[derive(Serialize)]
struct RegistrationFinishResponse {
    registered: bool,
    account_id: String,
    device_bootstrap: String,
    bootstrap_expires_unix_ms: i64,
}

#[derive(Deserialize)]
struct LoginStartRequest { username: String, opaque_request: String }

#[derive(Deserialize)]
struct LoginFinishRequest { ticket: String, finalization: String }
#[derive(Serialize)]
struct LoginFinishResponse { capability: String, expires_unix_ms: i64 }

#[derive(Serialize)]
struct DeviceBindingBeginResponse { challenge: String, expires_unix_ms: i64 }
#[derive(Deserialize)]
struct DeviceBindingFinishRequest { challenge: String, proof: String }
#[derive(Serialize)]
struct DeviceBindingFinishResponse { capability: String, expires_unix_ms: i64 }
#[derive(Serialize)]
struct DeviceSetResponse { device_set: String, epoch: u64 }
#[derive(Deserialize)]
struct DeviceSetSubmitRequest { device_set: String, expected_epoch: Option<u64> }
#[derive(Serialize)]
struct DeviceSetSubmitResponse { accepted: bool, epoch: u64 }
#[derive(Deserialize)]
struct DeviceGenesisRequest { account_id: String, device_bootstrap: String, device_set: String }
#[derive(Serialize)]
struct DeviceGenesisResponse { activated: bool, epoch: u64 }

#[derive(Deserialize)]
struct DeviceSessionStartRequest { account_id: String }
#[derive(Serialize)]
struct DeviceSessionStartResponse {
    challenge: String,
    challenge_mac: String,
    expires_unix_ms: i64,
}
#[derive(Deserialize)]
struct DeviceSessionFinishRequest {
    challenge: String,
    challenge_mac: String,
    proof: String,
}

async fn health() -> Json<Health> {
    Json(Health { status: "ok", service: "jend-gateway" })
}

const REQUIRED_SCHEMA_QUERY: &str = concat!(
    "SELECT ",
    "to_regclass('public.accounts') IS NOT NULL AND ",
    "to_regclass('public.device_sets') IS NOT NULL AND ",
    "to_regclass('public.admission_buckets') IS NOT NULL AND ",
    "to_regclass('public.admission_used_challenges') IS NOT NULL AND ",
    "to_regclass('public.login_ip_buckets') IS NOT NULL AND ",
    "to_regclass('public.login_account_buckets') IS NOT NULL AND ",
    "to_regclass('public.consumed_login_tickets') IS NOT NULL AND ",
    "to_regclass('public.registration_device_bootstraps') IS NOT NULL AND ",
    "to_regclass('public.consumed_device_binding_challenges') IS NOT NULL AND ",
    "to_regclass('public.consumed_jreq_nonces') IS NOT NULL"
);

async fn database_schema_ready(pool: &PgPool) -> Result<bool, sqlx::Error> {
    let tables_ready = sqlx::query_scalar::<_, bool>(REQUIRED_SCHEMA_QUERY)
        .fetch_one(pool)
        .await?;
    if !tables_ready {
        return Ok(false);
    }

    let columns_ready = sqlx::query_scalar::<_, bool>(REQUIRED_COLUMNS_QUERY)
        .fetch_one(pool)
        .await?;
    if !columns_ready {
        return Ok(false);
    }

    let migration_table_exists = sqlx::query_scalar::<_, bool>(
        "SELECT to_regclass('public._sqlx_migrations') IS NOT NULL"
    ).fetch_one(pool).await?;
    if !migration_table_exists {
        return Ok(false);
    }

    let latest_successful = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT MAX(version) FROM _sqlx_migrations WHERE success"
    ).fetch_one(pool).await?;
    let has_failed = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE NOT success)"
    ).fetch_one(pool).await?;

    Ok(!has_failed && latest_successful == Some(REQUIRED_MIGRATION_VERSION))
}

async fn ready(State(state): State<AppState>) -> Result<Json<Health>, ApiError> {
    let schema_ready = database_schema_ready(&state.pool).await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "not_ready"))?;
    if !schema_ready {
        return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "not_ready"));
    }
    Ok(Json(Health { status: "ready", service: "jend-gateway" }))
}

async fn registration_admission(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<AdmissionRequest>,
) -> ApiResult<AdmissionResponse> {
    let username = Username::parse(&req.username)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_request"))?;
    let rate_key = derive_ip_rate_key(&state.rate_hmac, peer.ip(), b"register-issue");
    let now = now_ms()?;
    let mut admission = state.registration_admission.lock().await;
    let challenge = admission.issue_challenge(&username, &[rate_key], RiskSignals::default(), now)
        .map_err(|e| match e {
            jend_gateway_core::GatewayError::Admission(jend_admission::AdmissionError::RateLimited) =>
                ApiError(StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            _ => ApiError(StatusCode::SERVICE_UNAVAILABLE, "admission_failed"),
        })?;
    Ok(Json(AdmissionResponse {
        challenge: URL_SAFE_NO_PAD.encode(challenge.encode()),
        difficulty_bits: challenge.difficulty_bits,
        expires_unix_ms: challenge.expires_unix_ms,
    }))
}

async fn registration_start(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<RegistrationStartRequest>,
) -> ApiResult<OpaqueStartResponse> {
    let username = Username::parse(&req.username)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_request"))?;
    let challenge_bytes = decode_field(&req.challenge)?;
    let challenge = RegistrationChallenge::decode(&challenge_bytes)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_challenge"))?;
    let now = now_ms()?;
    state.admission_verifier.verify(&challenge, username.as_str(), req.solution, now)
        .map_err(|_| ApiError(StatusCode::FORBIDDEN, "invalid_challenge"))?;

    let rate_key = derive_ip_rate_key(&state.rate_hmac, peer.ip(), b"register-consume");
    let admitted = repository::consume_admission(
        &state.pool, rate_key.0, challenge.challenge_id, challenge.expires_unix_ms,
    ).await.map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "repository_unavailable"))?;
    if !admitted { return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "admission_rejected")); }

    if repository::username_exists(&state.pool, &username).await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "repository_unavailable"))?
    {
        return Err(ApiError(StatusCode::CONFLICT, "username_unavailable"));
    }

    let opaque_request = decode_field(&req.opaque_request)?;
    let started = state.auth.registration_start(&username, &opaque_request, now)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_opaque_message"))?;
    Ok(Json(OpaqueStartResponse {
        opaque_response: URL_SAFE_NO_PAD.encode(started.response),
        ticket: URL_SAFE_NO_PAD.encode(started.ticket),
    }))
}

async fn registration_finish(
    State(state): State<AppState>,
    Json(req): Json<RegistrationFinishRequest>,
) -> ApiResult<RegistrationFinishResponse> {
    let username = Username::parse(&req.username)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_request"))?;
    let ticket = decode_field(&req.ticket)?;
    let upload = decode_field(&req.upload)?;
    let now = now_ms()?;
    let password_file = Zeroizing::new(
        state.auth.registration_finish(&username, &ticket, &upload, now)
            .map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "registration_failed"))?
    );
    let account_id = AccountId::generate()
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "random_unavailable"))?;
    let mut bootstrap = [0u8; 32];
    getrandom::fill(&mut bootstrap)
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "random_unavailable"))?;
    let bootstrap_expires_unix_ms = now.checked_add(REGISTRATION_BOOTSTRAP_MS)
        .ok_or(ApiError(StatusCode::SERVICE_UNAVAILABLE, "clock_unavailable"))?;
    let bootstrap_digest = registration_bootstrap_digest(&bootstrap);
    let inserted = repository::insert_registered_account_with_bootstrap(
        &state.pool, account_id, &username, password_file.as_slice(), bootstrap_digest, bootstrap_expires_unix_ms,
    ).await.map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "repository_unavailable"))?;
    if !inserted { return Err(ApiError(StatusCode::CONFLICT, "username_unavailable")); }
    Ok(Json(RegistrationFinishResponse {
        registered: true,
        account_id: URL_SAFE_NO_PAD.encode(account_id.0),
        device_bootstrap: URL_SAFE_NO_PAD.encode(bootstrap),
        bootstrap_expires_unix_ms,
    }))
}

async fn login_start(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<LoginStartRequest>,
) -> ApiResult<OpaqueStartResponse> {
    let username = Username::parse(&req.username)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_request"))?;
    let ip_key = derive_ip_rate_key(&state.rate_hmac, peer.ip(), b"login-ip");
    let account_key = derive_username_rate_key(&state.rate_hmac, &username, b"login-account");
    let allowed = repository::charge_login_start(&state.pool, ip_key.0, account_key)
        .await.map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "repository_unavailable"))?;
    if !allowed { return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "rate_limited")); }

    let record = repository::account_by_username(&state.pool, &username).await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "repository_unavailable"))?;
    let opaque_request = decode_field(&req.opaque_request)?;
    let now = now_ms()?;
    // Passing None for an unknown account preserves the OPAQUE fake-record path
    // instead of returning a username-existence oracle from this endpoint.
    let started = state.auth.login_start(
        &username,
        record.as_ref().map(|r| r.opaque_password_file.as_slice()),
        &opaque_request,
        now,
    ).map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "authentication_failed"))?;
    Ok(Json(OpaqueStartResponse {
        opaque_response: URL_SAFE_NO_PAD.encode(started.response),
        ticket: URL_SAFE_NO_PAD.encode(started.ticket),
    }))
}

async fn login_finish(
    State(state): State<AppState>,
    Json(req): Json<LoginFinishRequest>,
) -> ApiResult<LoginFinishResponse> {
    let ticket = decode_field(&req.ticket)?;
    let finalization = decode_field(&req.finalization)?;
    let now = now_ms()?;
    let finished = state.auth.login_finish(&ticket, &finalization, now)
        .map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "authentication_failed"))?;

    let ticket_digest = login_ticket_digest(&ticket);
    let first_use = repository::consume_login_ticket(
        &state.pool, ticket_digest, finished.ticket_expires_unix_ms,
    ).await.map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "repository_unavailable"))?;
    if !first_use { return Err(ApiError(StatusCode::UNAUTHORIZED, "authentication_failed")); }

    let record = repository::account_by_username(&state.pool, &finished.username).await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "repository_unavailable"))?
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "authentication_failed"))?;
    let permissions = Permissions::ACCOUNT_MANAGE
        .union(Permissions::DEVICE_ENROLL)
        .union(Permissions::MODEL_CATALOG);
    let capability = state.capability.issue(
        record.account_id, record.auth_epoch, None, permissions, now, ACCOUNT_CAPABILITY_MS,
    ).map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "capability_unavailable"))?;
    let expires = capability.claims.expires_unix_ms;
    Ok(Json(LoginFinishResponse {
        capability: URL_SAFE_NO_PAD.encode(capability.encode()),
        expires_unix_ms: expires,
    }))
}


fn bearer_capability_bytes(headers: &HeaderMap) -> Result<(SignedCapability, Vec<u8>), ApiError> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let raw = values.next()
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "missing_authorization"))?;
    if values.next().is_some() {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "ambiguous_authorization"));
    }
    let token = raw.strip_prefix("Bearer ")
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid_authorization"))?;
    if token.len() > 4096 {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid_authorization"));
    }
    let bytes = URL_SAFE_NO_PAD.decode(token.as_bytes())
        .map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "invalid_authorization"))?;
    let capability = SignedCapability::decode(&bytes)
        .map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "invalid_authorization"))?;
    Ok((capability, bytes))
}

fn bearer_capability(headers: &HeaderMap) -> Result<SignedCapability, ApiError> {
    bearer_capability_bytes(headers).map(|(capability, _)| capability)
}

struct VerifiedJreq {
    capability: SignedCapability,
    account: AccountRecord,
    device_id: SyncDeviceId,
    nonce: [u8; 32],
}

async fn verify_device_jreq(
    state: &AppState,
    headers: &HeaderMap,
    method: &'static str,
    uri: &axum::http::Uri,
    body: &[u8],
    required: Permissions,
) -> Result<VerifiedJreq, ApiError> {
    let (capability, capability_bytes) = bearer_capability_bytes(headers)?;
    let device_id = capability.claims.device_id
        .ok_or(ApiError(StatusCode::FORBIDDEN, "device_capability_required"))?;
    let now = now_ms()?;
    let account = repository::account_by_id(&state.pool, capability.claims.account_id).await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "repository_unavailable"))?
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid_authorization"))?;
    state.capability.verifier().verify(
        &capability, now, required, Some(device_id), Some(account.auth_epoch),
    ).map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "invalid_authorization"))?;

    let mut proof_values = headers.get_all(JREQ_HEADER).iter();
    let proof_value = proof_values.next()
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "missing_request_proof"))?;
    if proof_values.next().is_some() {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "ambiguous_request_proof"));
    }
    let proof_bytes = URL_SAFE_NO_PAD.decode(proof_value.as_bytes())
        .map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "invalid_request_proof"))?;
    let proof = JreqProof::decode(&proof_bytes)
        .map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "invalid_request_proof"))?;
    if proof.device_id != device_id.0 {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid_request_proof"));
    }

    let set = repository::current_device_set(&state.pool, account.account_id).await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "repository_unavailable"))?
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "device_set_missing"))?;
    let device = set.set.get(device_id)
        .ok_or(ApiError(StatusCode::FORBIDDEN, "untrusted_device"))?;

    let target = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or(uri.path());
    let now_u64 = u64::try_from(now)
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "clock_unavailable"))?;
    let request = JreqRequest {
        method,
        path_and_query: target,
        body,
        capability_digest: jend_jreq::sha256(&capability_bytes),
        device_id: proof.device_id,
        nonce: proof.nonce,
        timestamp_ms: proof.timestamp_ms,
    };
    jend_jreq::verify(&request, &proof.signature, device, now_u64)
        .map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "invalid_request_proof"))?;

    Ok(VerifiedJreq { capability, account, device_id, nonce: proof.nonce })
}

async fn device_binding_begin(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<DeviceBindingBeginResponse> {
    let capability = bearer_capability(&headers)?;
    let now = now_ms()?;
    let account = repository::account_by_id(&state.pool, capability.claims.account_id).await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "repository_unavailable"))?
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid_authorization"))?;
    // Binding is intentionally started only from a post-OPAQUE unbound account
    // capability. Already bound capabilities use their own device identity.
    if capability.claims.device_id.is_some() {
        return Err(ApiError(StatusCode::FORBIDDEN, "account_capability_required"));
    }
    state.capability.verifier().verify(
        &capability, now, Permissions::DEVICE_ENROLL, None, Some(account.auth_epoch),
    ).map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "invalid_authorization"))?;
    let challenge = DeviceSessionChallenge::generate(
        account.account_id, capability.claims.nonce, now,
    ).map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "challenge_unavailable"))?;
    Ok(Json(DeviceBindingBeginResponse {
        challenge: URL_SAFE_NO_PAD.encode(challenge.encode()),
        expires_unix_ms: challenge.expires_unix_ms,
    }))
}

async fn device_binding_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DeviceBindingFinishRequest>,
) -> ApiResult<DeviceBindingFinishResponse> {
    let capability = bearer_capability(&headers)?;
    let challenge = DeviceSessionChallenge::decode(&decode_field(&req.challenge)?)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_challenge"))?;
    let proof = DeviceSessionProof::decode(&decode_field(&req.proof)?)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_device_proof"))?;
    let now = now_ms()?;
    let account = repository::account_by_id(&state.pool, capability.claims.account_id).await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "repository_unavailable"))?
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid_authorization"))?;
    if capability.claims.device_id.is_some() {
        return Err(ApiError(StatusCode::FORBIDDEN, "account_capability_required"));
    }
    state.capability.verifier().verify(
        &capability, now, Permissions::DEVICE_ENROLL, None, Some(account.auth_epoch),
    ).map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "invalid_authorization"))?;
    if challenge.account_id != account.account_id
        || challenge.session_binding != capability.claims.nonce
    {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid_device_proof"));
    }
    let set = repository::current_device_set(&state.pool, account.account_id).await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "repository_unavailable"))?
        .ok_or(ApiError(StatusCode::CONFLICT, "device_set_missing"))?;
    let device = set.set.get(proof.device_id)
        .ok_or(ApiError(StatusCode::FORBIDDEN, "untrusted_device"))?;
    proof.verify(&challenge, device, now)
        .map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "invalid_device_proof"))?;

    let digest = device_binding_digest(&challenge);
    let first_use = repository::consume_device_binding_challenge(
        &state.pool, digest, challenge.expires_unix_ms,
    ).await.map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "repository_unavailable"))?;
    if !first_use {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "device_proof_replayed"));
    }

    let permissions = Permissions::SYNC_RELAY
        .union(Permissions::MODEL_CATALOG)
        .union(Permissions::MODEL_DOWNLOAD)
        .union(Permissions::ACCOUNT_MANAGE)
        .union(Permissions::DEVICE_ENROLL);
    let issued = state.capability.issue(
        account.account_id, account.auth_epoch, Some(proof.device_id), permissions, now, DEVICE_CAPABILITY_MS,
    ).map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "capability_unavailable"))?;
    Ok(Json(DeviceBindingFinishResponse {
        expires_unix_ms: issued.claims.expires_unix_ms,
        capability: URL_SAFE_NO_PAD.encode(issued.encode()),
    }))
}

async fn current_device_set(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> ApiResult<DeviceSetResponse> {
    let verified = verify_device_jreq(
        &state, &headers, "GET", &uri, b"", Permissions::DEVICE_ENROLL,
    ).await?;
    let first_use = repository::consume_jreq_nonce(
        &state.pool, verified.account.account_id, verified.device_id.0, verified.nonce,
    ).await.map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "repository_unavailable"))?;
    if !first_use {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "request_replayed"));
    }
    let set = repository::current_device_set(&state.pool, verified.account.account_id).await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "repository_unavailable"))?
        .ok_or(ApiError(StatusCode::NOT_FOUND, "device_set_missing"))?;
    let encoded = set.encode()
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "device_set_invalid"))?;
    Ok(Json(DeviceSetResponse {
        device_set: URL_SAFE_NO_PAD.encode(encoded),
        epoch: set.set.epoch,
    }))
}

async fn submit_device_set(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<DeviceSetSubmitResponse> {
    let verified = verify_device_jreq(
        &state, &headers, "POST", &uri, &body, Permissions::DEVICE_ENROLL,
    ).await?;
    let req: DeviceSetSubmitRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_json"))?;
    let expected_epoch = req.expected_epoch
        .ok_or(ApiError(StatusCode::FORBIDDEN, "genesis_requires_registration_bootstrap"))?;
    let next = SignedDeviceSet::decode(&decode_field(&req.device_set)?)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_device_set"))?;
    if next.set.account_id != verified.account.account_id || next.author != verified.device_id {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid_device_set"));
    }

    use repository::JreqDeviceSetOutcome;
    match repository::compare_and_swap_device_set_with_jreq(
        &state.pool,
        verified.account.account_id,
        verified.device_id,
        verified.nonce,
        expected_epoch,
        &next,
    ).await.map_err(|e| match e {
        jend_gateway_core::GatewayError::Repository =>
            ApiError(StatusCode::SERVICE_UNAVAILABLE, "repository_unavailable"),
        _ => ApiError(StatusCode::BAD_REQUEST, "invalid_device_set"),
    })? {
        JreqDeviceSetOutcome::Applied =>
            Ok(Json(DeviceSetSubmitResponse { accepted: true, epoch: next.set.epoch })),
        JreqDeviceSetOutcome::Replay =>
            Err(ApiError(StatusCode::UNAUTHORIZED, "request_replayed")),
        JreqDeviceSetOutcome::Conflict =>
            Err(ApiError(StatusCode::CONFLICT, "device_set_conflict")),
    }
}


#[derive(Serialize)]
struct DeviceCapabilityRefreshResponse { capability: String, expires_unix_ms: i64 }

async fn refresh_device_capability(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<DeviceCapabilityRefreshResponse> {
    if !body.is_empty() {
        return Err(ApiError(StatusCode::BAD_REQUEST, "body_must_be_empty"));
    }
    let verified = verify_device_jreq(
        &state, &headers, "POST", &uri, &body, Permissions::DEVICE_ENROLL,
    ).await?;
    let first_use = repository::consume_jreq_nonce(
        &state.pool, verified.account.account_id, verified.device_id.0, verified.nonce,
    ).await.map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "repository_unavailable"))?;
    if !first_use {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "request_replayed"));
    }

    let now = now_ms()?;
    // Never expand permissions during refresh.
    let issued = state.capability.issue(
        verified.account.account_id,
        verified.account.auth_epoch,
        Some(verified.device_id),
        verified.capability.claims.permissions,
        now,
        DEVICE_CAPABILITY_MS,
    ).map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "capability_unavailable"))?;
    Ok(Json(DeviceCapabilityRefreshResponse {
        expires_unix_ms: issued.claims.expires_unix_ms,
        capability: URL_SAFE_NO_PAD.encode(issued.encode()),
    }))
}



async fn device_session_start(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<DeviceSessionStartRequest>,
) -> ApiResult<DeviceSessionStartResponse> {
    let account_raw = decode_field(&req.account_id)?;
    let account_bytes: [u8; 16] = account_raw.try_into()
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_account_id"))?;
    let account_id = AccountId(account_bytes);

    // Rate-limit without looking the account up, avoiding an account-id oracle.
    let ip_key = derive_ip_rate_key(&state.rate_hmac, peer.ip(), b"device-session-ip");
    let account_key = derive_account_id_rate_key(
        &state.rate_hmac, account_id, b"device-session-account",
    );
    let allowed = repository::charge_login_start(&state.pool, ip_key.0, account_key)
        .await.map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "repository_unavailable"))?;
    if !allowed {
        return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "rate_limited"));
    }

    let mut binding = [0u8; 16];
    getrandom::fill(&mut binding)
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "random_unavailable"))?;
    let now = now_ms()?;
    let challenge = DeviceSessionChallenge::generate(account_id, binding, now)
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "challenge_unavailable"))?;
    let challenge_mac = device_session_challenge_mac(&state.device_session_hmac, &challenge);
    Ok(Json(DeviceSessionStartResponse {
        challenge: URL_SAFE_NO_PAD.encode(challenge.encode()),
        challenge_mac: URL_SAFE_NO_PAD.encode(challenge_mac),
        expires_unix_ms: challenge.expires_unix_ms,
    }))
}

async fn device_session_finish(
    State(state): State<AppState>,
    Json(req): Json<DeviceSessionFinishRequest>,
) -> ApiResult<DeviceBindingFinishResponse> {
    let challenge = DeviceSessionChallenge::decode(&decode_field(&req.challenge)?)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_challenge"))?;
    let now = now_ms()?;
    verify_fresh_device_session_challenge(
        &state.device_session_hmac,
        &challenge,
        &decode_field(&req.challenge_mac)?,
        now,
    )?;
    let proof = DeviceSessionProof::decode(&decode_field(&req.proof)?)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_device_proof"))?;
    let account = repository::account_by_id(&state.pool, challenge.account_id).await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "repository_unavailable"))?
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid_device_proof"))?;
    let set = repository::current_device_set(&state.pool, account.account_id).await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "repository_unavailable"))?
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid_device_proof"))?;
    let device = set.set.get(proof.device_id)
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid_device_proof"))?;
    proof.verify(&challenge, device, now)
        .map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "invalid_device_proof"))?;

    let digest = device_session_digest(&challenge);
    let first_use = repository::consume_device_binding_challenge(
        &state.pool, digest, challenge.expires_unix_ms,
    ).await.map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "repository_unavailable"))?;
    if !first_use {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "device_proof_replayed"));
    }

    let permissions = Permissions::SYNC_RELAY
        .union(Permissions::MODEL_CATALOG)
        .union(Permissions::MODEL_DOWNLOAD)
        .union(Permissions::ACCOUNT_MANAGE)
        .union(Permissions::DEVICE_ENROLL);
    let issued = state.capability.issue(
        account.account_id,
        account.auth_epoch,
        Some(proof.device_id),
        permissions,
        now,
        DEVICE_CAPABILITY_MS,
    ).map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "capability_unavailable"))?;
    Ok(Json(DeviceBindingFinishResponse {
        expires_unix_ms: issued.claims.expires_unix_ms,
        capability: URL_SAFE_NO_PAD.encode(issued.encode()),
    }))
}


async fn device_genesis(
    State(state): State<AppState>,
    Json(req): Json<DeviceGenesisRequest>,
) -> ApiResult<DeviceGenesisResponse> {
    let account_raw = decode_field(&req.account_id)?;
    let account_bytes: [u8; 16] = account_raw.try_into()
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_account_id"))?;
    let account_id = AccountId(account_bytes);
    let bootstrap_raw = decode_field(&req.device_bootstrap)?;
    let bootstrap: [u8; 32] = bootstrap_raw.try_into()
        .map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "invalid_bootstrap"))?;
    let genesis = SignedDeviceSet::decode(&decode_field(&req.device_set)?)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_device_set"))?;
    if genesis.set.account_id != account_id || genesis.set.epoch != 0 {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid_device_set"));
    }
    let accepted = repository::consume_registration_bootstrap_and_set_genesis(
        &state.pool, account_id, registration_bootstrap_digest(&bootstrap), &genesis,
    ).await.map_err(|e| match e {
        jend_gateway_core::GatewayError::Repository => ApiError(StatusCode::SERVICE_UNAVAILABLE, "repository_unavailable"),
        _ => ApiError(StatusCode::BAD_REQUEST, "invalid_device_set"),
    })?;
    if !accepted {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid_or_expired_bootstrap"));
    }
    Ok(Json(DeviceGenesisResponse { activated: true, epoch: 0 }))
}

fn registration_bootstrap_digest(bootstrap: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(REGISTRATION_BOOTSTRAP_DIGEST_DOMAIN);
    h.update(bootstrap);
    h.finalize().into()
}

fn device_binding_digest(challenge: &DeviceSessionChallenge) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DEVICE_BIND_DIGEST_DOMAIN);
    h.update(challenge.encode());
    h.finalize().into()
}

fn device_session_digest(challenge: &DeviceSessionChallenge) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DEVICE_SESSION_DIGEST_DOMAIN);
    h.update(challenge.encode());
    h.finalize().into()
}

fn device_session_challenge_mac(
    secret: &[u8; 32],
    challenge: &DeviceSessionChallenge,
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(DEVICE_SESSION_MAC_DOMAIN);
    mac.update(&challenge.encode());
    mac.finalize().into_bytes().into()
}

fn verify_device_session_challenge_mac(
    secret: &[u8; 32],
    challenge: &DeviceSessionChallenge,
    received: &[u8],
) -> Result<(), ApiError> {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(DEVICE_SESSION_MAC_DOMAIN);
    mac.update(&challenge.encode());
    mac.verify_slice(received)
        .map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "invalid_device_session_challenge"))
}

fn verify_fresh_device_session_challenge(
    secret: &[u8; 32],
    challenge: &DeviceSessionChallenge,
    received: &[u8],
    now_unix_ms: i64,
) -> Result<(), ApiError> {
    verify_device_session_challenge_mac(secret, challenge, received)?;
    challenge
        .validate_time(now_unix_ms)
        .map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "invalid_device_session_challenge"))
}

fn decode_field(value: &str) -> Result<Vec<u8>, ApiError> {
    if value.len() > MAX_WIRE_FIELD {
        return Err(ApiError(StatusCode::PAYLOAD_TOO_LARGE, "field_too_large"));
    }
    URL_SAFE_NO_PAD.decode(value.as_bytes())
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_encoding"))
}

fn derive_ip_rate_key(secret: &[u8; 32], ip: IpAddr, domain: &[u8]) -> RateKey {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(b"JEND/RATE/IP/V1");
    mac.update(domain);
    match ip {
        IpAddr::V4(v4) => { mac.update(&[4]); mac.update(&v4.octets()); }
        IpAddr::V6(v6) => { mac.update(&[6]); mac.update(&v6.octets()); }
    }
    RateKey(mac.finalize().into_bytes().into())
}

fn derive_username_rate_key(secret: &[u8; 32], username: &Username, domain: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(b"JEND/RATE/USERNAME/V1");
    mac.update(domain);
    mac.update(username.as_bytes());
    mac.finalize().into_bytes().into()
}

fn derive_account_id_rate_key(
    secret: &[u8; 32],
    account_id: AccountId,
    domain: &[u8],
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(b"JEND/RATE/ACCOUNT-ID/V1");
    mac.update(domain);
    mac.update(&account_id.0);
    mac.finalize().into_bytes().into()
}

fn login_ticket_digest(ticket: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(LOGIN_TICKET_DIGEST_DOMAIN);
    h.update(ticket);
    h.finalize().into()
}

fn now_ms() -> Result<i64, ApiError> {
    let millis = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "clock_unavailable"))?
        .as_millis();
    i64::try_from(millis).map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "clock_unavailable"))
}

fn validate_bind_address(addr: SocketAddr, allow_insecure_http: bool) -> std::io::Result<()> {
    if !addr.ip().is_loopback() && !allow_insecure_http {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "refusing non-loopback plain-HTTP bind; terminate TLS locally or set JEND_ALLOW_INSECURE_HTTP=1 for an explicitly isolated development network",
        ));
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let database_url = std::env::var("DATABASE_URL")?;
    let pool = PgPoolOptions::new()
        .max_connections(20)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url).await?;
    if !database_schema_ready(&pool).await? {
        return Err("database schema incomplete; run jend-migrate before jend-gateway".into());
    }

    let secret_dir = PathBuf::from(std::env::var("JEND_SECRET_DIR")?);
    let mut loaded = secrets::LoadedSecrets::load(&secret_dir)?;
    let auth = Arc::new(AuthServer::from_serialized_setup(
        loaded.opaque_setup.as_slice(), &mut *loaded.auth_ticket,
    )?);
    let capability = Arc::new(CapabilityIssuer::from_secret_bytes(&mut *loaded.capability));
    let admission_issuer = AdmissionIssuer::from_secret_bytes(&mut *loaded.admission);
    let registration_admission_service = RegistrationAdmission::new(admission_issuer);
    let admission_verifier = registration_admission_service.verifier();
    let rate_hmac = Arc::new(Zeroizing::new(*loaded.rate_hmac));
    let device_session_hmac = Arc::new(Zeroizing::new(*loaded.device_session_hmac));
    drop(loaded);

    let state = AppState {
        pool,
        auth,
        capability,
        registration_admission: Arc::new(Mutex::new(registration_admission_service)),
        admission_verifier,
        rate_hmac,
        device_session_hmac,
    };

    let app = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/v1/registration/admission", post(registration_admission))
        .route("/v1/auth/register/start", post(registration_start))
        .route("/v1/auth/register/finish", post(registration_finish))
        .route("/v1/auth/login/start", post(login_start))
        .route("/v1/auth/login/finish", post(login_finish))
        .route("/v1/devices/genesis", post(device_genesis))
        .route("/v1/devices/bind/start", post(device_binding_begin))
        .route("/v1/devices/bind/finish", post(device_binding_finish))
        .route("/v1/devices/current", get(current_device_set))
        .route("/v1/devices/set", post(submit_device_set))
        .route("/v1/auth/device/refresh", post(refresh_device_capability))
        .route("/v1/auth/device/session/start", post(device_session_start))
        .route("/v1/auth/device/session/finish", post(device_session_finish))
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAX_AUTH_BODY))
        .layer(RequestBodyLimitLayer::new(MAX_AUTH_BODY))
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, Duration::from_secs(15)))
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = std::env::var("JEND_GATEWAY_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".into()).parse()?;
    let allow_insecure_http = std::env::var("JEND_ALLOW_INSECURE_HTTP")
        .map(|value| value == "1")
        .unwrap_or(false);
    validate_bind_address(addr, allow_insecure_http)?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "jend gateway listening");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async { let _ = tokio::signal::ctrl_c().await; })
        .await?;
    Ok(())
}


#[cfg(test)]
mod gateway_security_tests {
    use super::*;

    #[test]
    fn public_plain_http_bind_is_fail_closed() {
        let loopback: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let public: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        assert!(validate_bind_address(loopback, false).is_ok());
        assert!(validate_bind_address(public, false).is_err());
        assert!(validate_bind_address(public, true).is_ok());
    }

    #[test]
    fn readiness_contract_covers_gateway_state_tables() {
        for table in [
            "accounts",
            "device_sets",
            "admission_buckets",
            "admission_used_challenges",
            "login_ip_buckets",
            "login_account_buckets",
            "consumed_login_tickets",
            "registration_device_bootstraps",
            "consumed_device_binding_challenges",
            "consumed_jreq_nonces",
        ] {
            assert!(REQUIRED_SCHEMA_QUERY.contains(table), "missing readiness table: {table}");
        }
        assert_eq!(REQUIRED_MIGRATION_VERSION, 6);
        for column in [
            "opaque_password_file", "auth_epoch", "status", "signed_device_set",
            "bootstrap_digest", "challenge_digest", "device_id", "nonce",
        ] {
            assert!(REQUIRED_COLUMNS_QUERY.contains(column), "missing readiness column: {column}");
        }
    }

    #[test]
    fn device_session_mac_is_server_bound() {
        let secret = [7u8; 32];
        let account = AccountId([3u8; 16]);
        let challenge = DeviceSessionChallenge::generate(account, [4u8; 16], 1_000).unwrap();
        let tag = device_session_challenge_mac(&secret, &challenge);
        assert!(verify_device_session_challenge_mac(&secret, &challenge, &tag).is_ok());

        let mut forged = challenge.clone();
        forged.nonce[0] ^= 1;
        assert!(verify_device_session_challenge_mac(&secret, &forged, &tag).is_err());

        let wrong_secret = [8u8; 32];
        assert!(verify_device_session_challenge_mac(&wrong_secret, &challenge, &tag).is_err());

        assert!(verify_fresh_device_session_challenge(
            &secret,
            &challenge,
            &tag,
            challenge.expires_unix_ms,
        ).is_ok());
        assert!(verify_fresh_device_session_challenge(
            &secret,
            &challenge,
            &tag,
            challenge.expires_unix_ms + 1,
        ).is_err());
    }
}
