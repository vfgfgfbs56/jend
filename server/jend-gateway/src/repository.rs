use jend_auth::Username;
use jend_gateway_core::{AccountRecord, GatewayError, Result};
use jend_sync::{AccountId, SignedDeviceSet};
use sqlx::{PgPool, Row};

pub async fn account_by_username(pool: &PgPool, username: &Username) -> Result<Option<AccountRecord>> {
    let row = sqlx::query(
        "SELECT account_id::text AS account_id_text, username, opaque_password_file, auth_epoch \
         FROM accounts WHERE username=$1 AND status=0"
    ).bind(username.as_str()).fetch_optional(pool).await.map_err(|_| GatewayError::Repository)?;
    row.map(decode_account).transpose()
}

pub async fn username_exists(pool: &PgPool, username: &Username) -> Result<bool> {
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM accounts WHERE username=$1)"
    ).bind(username.as_str()).fetch_one(pool).await.map_err(|_| GatewayError::Repository)?;
    Ok(exists)
}

pub async fn account_by_id(pool: &PgPool, account_id: AccountId) -> Result<Option<AccountRecord>> {
    let id = account_id_uuid(account_id);
    let row = sqlx::query(
        "SELECT account_id::text AS account_id_text, username, opaque_password_file, auth_epoch \
         FROM accounts WHERE account_id=$1::uuid AND status=0"
    ).bind(id).fetch_optional(pool).await.map_err(|_| GatewayError::Repository)?;
    row.map(decode_account).transpose()
}

/// Persists only an OPAQUE password file returned by AuthServer::registration_finish.
/// The database uniqueness constraint is the final username race barrier.
pub async fn insert_registered_account_with_bootstrap(
    pool: &PgPool,
    account_id: AccountId,
    username: &Username,
    opaque_file: &[u8],
    bootstrap_digest: [u8; 32],
    bootstrap_expires_unix_ms: i64,
) -> Result<bool> {
    if opaque_file.is_empty() || opaque_file.len() > 65_536 {
        return Err(GatewayError::Repository);
    }
    let mut tx = pool.begin().await.map_err(|_| GatewayError::Repository)?;
    // status=1: password exists, but the account is intentionally unusable until
    // the registering client commits its signed first-device trust root.
    let inserted = sqlx::query(
        "INSERT INTO accounts(account_id,username,opaque_password_file,status) \
         VALUES($1::uuid,$2,$3,1) ON CONFLICT(username) DO NOTHING"
    ).bind(account_id_uuid(account_id)).bind(username.as_str()).bind(opaque_file)
     .execute(&mut *tx).await.map_err(|_| GatewayError::Repository)?;
    if inserted.rows_affected() != 1 { return Ok(false); }
    sqlx::query(
        "INSERT INTO registration_device_bootstraps(bootstrap_digest,account_id,expires_at) \
         VALUES($1,$2::uuid,to_timestamp($3::double precision/1000.0))"
    ).bind(bootstrap_digest.to_vec()).bind(account_id_uuid(account_id)).bind(bootstrap_expires_unix_ms)
     .execute(&mut *tx).await.map_err(|_| GatewayError::Repository)?;
    tx.commit().await.map_err(|_| GatewayError::Repository)?;
    Ok(true)
}

fn decode_account(row: sqlx::postgres::PgRow) -> Result<AccountRecord> {
    let id_text: String = row.try_get("account_id_text").map_err(|_| GatewayError::Repository)?;
    let mut id = [0u8; 16];
    let hex_id: String = id_text.chars().filter(|c| *c != '-').collect();
    hex::decode_to_slice(hex_id, &mut id).map_err(|_| GatewayError::Repository)?;
    let username: String = row.try_get("username").map_err(|_| GatewayError::Repository)?;
    let auth_epoch_i64: i64 = row.try_get("auth_epoch").map_err(|_| GatewayError::Repository)?;
    let auth_epoch = u64::try_from(auth_epoch_i64).map_err(|_| GatewayError::Repository)?;
    Ok(AccountRecord {
        account_id: AccountId(id),
        username: Username::parse(&username)?,
        opaque_password_file: row.try_get("opaque_password_file").map_err(|_| GatewayError::Repository)?,
        auth_epoch,
    })
}

pub fn account_id_uuid(id: AccountId) -> String {
    let h = hex::encode(id.0);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

/// Registration shared quota + replay backstop. The signed challenge is verified
/// before this method. A reused challenge rolls back its quota charge.
pub async fn consume_admission(
    pool: &PgPool,
    bucket_key: [u8; 32],
    challenge_id: [u8; 16],
    expires_unix_ms: i64,
) -> Result<bool> {
    let mut tx = pool.begin().await.map_err(|_| GatewayError::Repository)?;
    sqlx::query(
        "INSERT INTO admission_buckets(bucket_key,tokens,window_start) VALUES($1,5,now()) \
         ON CONFLICT(bucket_key) DO NOTHING"
    ).bind(bucket_key.to_vec()).execute(&mut *tx).await.map_err(|_| GatewayError::Repository)?;
    let charged = sqlx::query(
        "UPDATE admission_buckets SET \
           tokens=CASE WHEN window_start < now()-interval '60 seconds' THEN 4 ELSE tokens-1 END, \
           window_start=CASE WHEN window_start < now()-interval '60 seconds' THEN now() ELSE window_start END \
         WHERE bucket_key=$1 AND (tokens>0 OR window_start < now()-interval '60 seconds')"
    ).bind(bucket_key.to_vec()).execute(&mut *tx).await.map_err(|_| GatewayError::Repository)?;
    if charged.rows_affected() != 1 { return Ok(false); }
    let used = sqlx::query(
        "INSERT INTO admission_used_challenges(challenge_id,expires_at) \
         VALUES($1,to_timestamp($2::double precision/1000.0)) ON CONFLICT DO NOTHING"
    ).bind(challenge_id.to_vec()).bind(expires_unix_ms)
     .execute(&mut *tx).await.map_err(|_| GatewayError::Repository)?;
    if used.rows_affected() != 1 { return Ok(false); }
    tx.commit().await.map_err(|_| GatewayError::Repository)?;
    Ok(true)
}

/// Charges both a per-network and per-account login window atomically. The
/// opaque keys are HMAC-derived outside this module; no raw address is stored.
pub async fn charge_login_start(
    pool: &PgPool,
    ip_key: [u8; 32],
    account_key: [u8; 32],
) -> Result<bool> {
    let mut tx = pool.begin().await.map_err(|_| GatewayError::Repository)?;
    if !charge_bucket(&mut tx, "login_ip_buckets", &ip_key, 30).await? { return Ok(false); }
    if !charge_bucket(&mut tx, "login_account_buckets", &account_key, 10).await? { return Ok(false); }
    tx.commit().await.map_err(|_| GatewayError::Repository)?;
    Ok(true)
}

async fn charge_bucket(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    table: &'static str,
    key: &[u8; 32],
    capacity: i32,
) -> Result<bool> {
    // `table` is never user-controlled; keep the finite allowlist explicit.
    let (insert_sql, update_sql) = match table {
        "login_ip_buckets" => (
            "INSERT INTO login_ip_buckets(bucket_key,tokens,window_start) VALUES($1,$2,now()) ON CONFLICT(bucket_key) DO NOTHING",
            "UPDATE login_ip_buckets SET tokens=CASE WHEN window_start<now()-interval '60 seconds' THEN $2-1 ELSE tokens-1 END, window_start=CASE WHEN window_start<now()-interval '60 seconds' THEN now() ELSE window_start END WHERE bucket_key=$1 AND (tokens>0 OR window_start<now()-interval '60 seconds')",
        ),
        "login_account_buckets" => (
            "INSERT INTO login_account_buckets(bucket_key,tokens,window_start) VALUES($1,$2,now()) ON CONFLICT(bucket_key) DO NOTHING",
            "UPDATE login_account_buckets SET tokens=CASE WHEN window_start<now()-interval '60 seconds' THEN $2-1 ELSE tokens-1 END, window_start=CASE WHEN window_start<now()-interval '60 seconds' THEN now() ELSE window_start END WHERE bucket_key=$1 AND (tokens>0 OR window_start<now()-interval '60 seconds')",
        ),
        _ => return Err(GatewayError::Repository),
    };
    sqlx::query(insert_sql).bind(key.to_vec()).bind(capacity)
        .execute(&mut **tx).await.map_err(|_| GatewayError::Repository)?;
    let charged = sqlx::query(update_sql).bind(key.to_vec()).bind(capacity)
        .execute(&mut **tx).await.map_err(|_| GatewayError::Repository)?;
    Ok(charged.rows_affected() == 1)
}

/// One-time barrier for a successfully verified OPAQUE login ticket.
pub async fn consume_login_ticket(
    pool: &PgPool,
    ticket_digest: [u8; 32],
    expires_unix_ms: i64,
) -> Result<bool> {
    let inserted = sqlx::query(
        "INSERT INTO consumed_login_tickets(ticket_digest,expires_at) \
         VALUES($1,to_timestamp($2::double precision/1000.0)) ON CONFLICT DO NOTHING"
    ).bind(ticket_digest.to_vec()).bind(expires_unix_ms)
     .execute(pool).await.map_err(|_| GatewayError::Repository)?;
    Ok(inserted.rows_affected() == 1)
}



/// Consumes the registration-only secret and commits the first signed trust root.
/// No generic account/login capability is allowed to create genesis.
pub async fn consume_registration_bootstrap_and_set_genesis(
    pool: &PgPool,
    account_id: AccountId,
    bootstrap_digest: [u8; 32],
    genesis: &SignedDeviceSet,
) -> Result<bool> {
    if genesis.set.account_id != account_id || genesis.set.epoch != 0 {
        return Err(GatewayError::DeviceSetConflict);
    }
    genesis.verify_genesis().map_err(GatewayError::Sync)?;
    let mut tx = pool.begin().await.map_err(|_| GatewayError::Repository)?;
    let found = sqlx::query(
        "SELECT 1 FROM registration_device_bootstraps \
         WHERE bootstrap_digest=$1 AND account_id=$2::uuid AND expires_at>now() FOR UPDATE"
    ).bind(bootstrap_digest.to_vec()).bind(account_id_uuid(account_id))
     .fetch_optional(&mut *tx).await.map_err(|_| GatewayError::Repository)?;
    if found.is_none() { return Ok(false); }
    let epoch = i64::try_from(genesis.set.epoch).map_err(|_| GatewayError::Repository)?;
    let encoded = genesis.encode().map_err(GatewayError::Sync)?;
    let inserted = sqlx::query(
        "INSERT INTO device_sets(account_id,epoch,signed_device_set) VALUES($1::uuid,$2,$3) ON CONFLICT DO NOTHING"
    ).bind(account_id_uuid(account_id)).bind(epoch).bind(encoded)
     .execute(&mut *tx).await.map_err(|_| GatewayError::Repository)?;
    if inserted.rows_affected() != 1 { return Ok(false); }
    let activated = sqlx::query(
        "UPDATE accounts SET status=0 WHERE account_id=$1::uuid AND status=1"
    ).bind(account_id_uuid(account_id)).execute(&mut *tx).await
     .map_err(|_| GatewayError::Repository)?;
    if activated.rows_affected() != 1 { return Err(GatewayError::Repository); }
    let deleted = sqlx::query(
        "DELETE FROM registration_device_bootstraps WHERE bootstrap_digest=$1 AND account_id=$2::uuid"
    ).bind(bootstrap_digest.to_vec()).bind(account_id_uuid(account_id))
     .execute(&mut *tx).await.map_err(|_| GatewayError::Repository)?;
    if deleted.rows_affected() != 1 { return Err(GatewayError::Repository); }
    tx.commit().await.map_err(|_| GatewayError::Repository)?;
    Ok(true)
}

/// Loads the latest signed DeviceSet. The bytes were verified before insertion;
/// decoding here still enforces canonical wire structure and account binding.
pub async fn current_device_set(pool: &PgPool, account_id: AccountId) -> Result<Option<SignedDeviceSet>> {
    let row = sqlx::query(
        "SELECT signed_device_set FROM device_sets WHERE account_id=$1::uuid"
    ).bind(account_id_uuid(account_id)).fetch_optional(pool).await
     .map_err(|_| GatewayError::Repository)?;
    let Some(row) = row else { return Ok(None); };
    let bytes: Vec<u8> = row.try_get("signed_device_set").map_err(|_| GatewayError::Repository)?;
    let set = SignedDeviceSet::decode(&bytes).map_err(GatewayError::Sync)?;
    if set.set.account_id != account_id { return Err(GatewayError::Repository); }
    Ok(Some(set))
}

/// Makes a successfully verified device-session proof one-shot. Store only a
/// domain-separated digest of the public challenge, never device private data.
pub async fn consume_device_binding_challenge(
    pool: &PgPool,
    challenge_digest: [u8; 32],
    expires_unix_ms: i64,
) -> Result<bool> {
    let inserted = sqlx::query(
        "INSERT INTO consumed_device_binding_challenges(challenge_digest,expires_at) \
         VALUES($1,to_timestamp($2::double precision/1000.0)) ON CONFLICT DO NOTHING"
    ).bind(challenge_digest.to_vec()).bind(expires_unix_ms)
     .execute(pool).await.map_err(|_| GatewayError::Repository)?;
    Ok(inserted.rows_affected() == 1)
}


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JreqDeviceSetOutcome {
    Applied,
    Replay,
    Conflict,
}

/// Performs replay consumption and DeviceSet mutation in one transaction.
/// If CAS/transition validation fails, the nonce insert rolls back as well.
pub async fn compare_and_swap_device_set_with_jreq(
    pool: &PgPool,
    account_id: AccountId,
    device_id: jend_sync::SyncDeviceId,
    nonce: [u8; 32],
    expected_epoch: u64,
    next: &SignedDeviceSet,
) -> Result<JreqDeviceSetOutcome> {
    if next.set.account_id != account_id || next.author != device_id {
        return Ok(JreqDeviceSetOutcome::Conflict);
    }
    let mut tx = pool.begin().await.map_err(|_| GatewayError::Repository)?;

    let row = sqlx::query(
        "SELECT epoch, signed_device_set FROM device_sets \
         WHERE account_id=$1::uuid FOR UPDATE"
    ).bind(account_id_uuid(account_id)).fetch_optional(&mut *tx).await
     .map_err(|_| GatewayError::Repository)?;
    let Some(row) = row else { return Ok(JreqDeviceSetOutcome::Conflict); };

    let epoch_i64: i64 = row.try_get("epoch").map_err(|_| GatewayError::Repository)?;
    let epoch = u64::try_from(epoch_i64).map_err(|_| GatewayError::Repository)?;
    if epoch != expected_epoch {
        return Ok(JreqDeviceSetOutcome::Conflict);
    }

    let current_bytes: Vec<u8> = row.try_get("signed_device_set")
        .map_err(|_| GatewayError::Repository)?;
    let current = SignedDeviceSet::decode(&current_bytes).map_err(GatewayError::Sync)?;
    if current.set.account_id != account_id || current.set.epoch != epoch
        || !current.set.contains(device_id)
    {
        return Ok(JreqDeviceSetOutcome::Conflict);
    }
    next.verify_transition(&current).map_err(GatewayError::Sync)?;

    let nonce_insert = sqlx::query(
        "INSERT INTO consumed_jreq_nonces(account_id,device_id,nonce) \
         VALUES($1::uuid,$2,$3) ON CONFLICT DO NOTHING"
    )
    .bind(account_id_uuid(account_id))
    .bind(device_id.0.to_vec())
    .bind(nonce.to_vec())
    .execute(&mut *tx).await.map_err(|_| GatewayError::Repository)?;
    if nonce_insert.rows_affected() != 1 {
        return Ok(JreqDeviceSetOutcome::Replay);
    }

    let next_epoch = i64::try_from(next.set.epoch).map_err(|_| GatewayError::Repository)?;
    let encoded = next.encode().map_err(GatewayError::Sync)?;
    let updated = sqlx::query(
        "UPDATE device_sets SET epoch=$2,signed_device_set=$3,updated_at=now() \
         WHERE account_id=$1::uuid AND epoch=$4"
    )
    .bind(account_id_uuid(account_id))
    .bind(next_epoch)
    .bind(encoded)
    .bind(epoch_i64)
    .execute(&mut *tx).await.map_err(|_| GatewayError::Repository)?;
    if updated.rows_affected() != 1 {
        return Ok(JreqDeviceSetOutcome::Conflict);
    }

    tx.commit().await.map_err(|_| GatewayError::Repository)?;
    Ok(JreqDeviceSetOutcome::Applied)
}

/// Replay guard for JREQ. Must run only AFTER cryptographic validation and
/// BEFORE the protected side effect. Duplicate nonces return false.
pub async fn consume_jreq_nonce(
    pool: &PgPool, account_id: AccountId, device_id: [u8;16], nonce: [u8;32],
) -> Result<bool> {
    let inserted = sqlx::query(
        "INSERT INTO consumed_jreq_nonces(account_id,device_id,nonce)          VALUES($1::uuid,$2,$3) ON CONFLICT DO NOTHING"
    )
    .bind(account_id_uuid(account_id))
    .bind(device_id.to_vec())
    .bind(nonce.to_vec())
    .execute(pool).await.map_err(|_| GatewayError::Repository)?;
    Ok(inserted.rows_affected() == 1)
}
