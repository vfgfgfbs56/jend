#![forbid(unsafe_code)]

//! Development-only headless smoke client.
//! It intentionally keeps the generated device key in memory only and does
//! not pretend to be the production Vault-backed Jend client.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jend_admission::{solve_for_testing, RegistrationChallenge};
use jend_jreq::{Proof as JreqProof, Request as JreqRequest};
use jend_auth::{
    client_login_finish, client_login_start,
    client_registration_finish, client_registration_start, SensitivePassword,
};
use jend_sync::{
    AccountId, DeviceSessionChallenge, DeviceSessionProof, DeviceSet,
    SignedDeviceSet, SyncDeviceIdentity,
};
use reqwest::{Client, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zeroize::Zeroizing;
use std::{io::Read, time::{SystemTime, UNIX_EPOCH}};

#[derive(Serialize)]
struct UsernameRequest<'a> { username: &'a str }

#[derive(Deserialize)]
struct AdmissionResponse {
    challenge: String,
    difficulty_bits: u8,
    expires_unix_ms: i64,
}

#[derive(Serialize)]
struct RegistrationStartRequest<'a> {
    username: &'a str,
    challenge: &'a str,
    solution: u64,
    opaque_request: String,
}

#[derive(Deserialize)]
struct OpaqueStartResponse { opaque_response: String, ticket: String }

#[derive(Serialize)]
struct RegistrationFinishRequest<'a> {
    username: &'a str,
    ticket: &'a str,
    upload: String,
}

#[derive(Deserialize)]
struct RegistrationFinishResponse {
    registered: bool,
    account_id: String,
    device_bootstrap: String,
    bootstrap_expires_unix_ms: i64,
}

#[derive(Serialize)]
struct DeviceGenesisRequest<'a> {
    account_id: &'a str,
    device_bootstrap: &'a str,
    device_set: String,
}

#[derive(Deserialize)]
struct DeviceGenesisResponse { activated: bool, epoch: u64 }

#[derive(Serialize)]
struct LoginStartRequest<'a> { username: &'a str, opaque_request: String }

#[derive(Serialize)]
struct LoginFinishRequest<'a> { ticket: &'a str, finalization: String }

#[derive(Deserialize)]
struct LoginFinishResponse { capability: String, expires_unix_ms: i64 }

#[derive(Deserialize)]
struct DeviceBindingBeginResponse { challenge: String, expires_unix_ms: i64 }

#[derive(Serialize)]
struct DeviceBindingFinishRequest { challenge: String, proof: String }

#[derive(Deserialize)]
struct DeviceBindingFinishResponse { capability: String, expires_unix_ms: i64 }

#[derive(Deserialize)]
struct DeviceSetResponse { device_set: String, epoch: u64 }

#[derive(Serialize)]
struct DeviceSessionStartRequest<'a> { account_id: &'a str }
#[derive(Deserialize)]
struct DeviceSessionStartResponse {
    challenge: String,
    challenge_mac: String,
    expires_unix_ms: i64,
}
#[derive(Serialize)]
struct DeviceSessionFinishRequest {
    challenge: String,
    challenge_mac: String,
    proof: String,
}

async fn post_json<T: Serialize + ?Sized, U: DeserializeOwned>(
    client: &Client, url: String, body: &T, bearer: Option<&str>,
) -> Result<U, Box<dyn std::error::Error>> {
    let mut request = client.post(url).json(body);
    if let Some(token) = bearer {
        request = request.bearer_auth(token);
    }
    let response = request.send().await?;
    let status = response.status();
    let bytes = response.bytes().await?;
    if !status.is_success() {
        let text = String::from_utf8_lossy(&bytes);
        return Err(format!("HTTP {status}: {text}").into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn decode_b64(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(URL_SAFE_NO_PAD.decode(value.as_bytes())?)
}


fn unix_ms() -> Result<u64, Box<dyn std::error::Error>> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis().try_into()?)
}

fn require_future_expiry(
    label: &str,
    expires_unix_ms: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = i64::try_from(unix_ms()?)?;
    if expires_unix_ms <= now {
        return Err(format!("{label} returned an already-expired timestamp").into());
    }
    Ok(())
}

fn make_jreq_header(
    device: &SyncDeviceIdentity,
    capability_b64: &str,
    method: &'static str,
    path_and_query: &str,
    body: &[u8],
) -> Result<String, Box<dyn std::error::Error>> {
    let capability_bytes = decode_b64(capability_b64)?;
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce)?;
    let request = JreqRequest {
        method,
        path_and_query,
        body,
        capability_digest: jend_jreq::sha256(&capability_bytes),
        device_id: device.public_identity().device_id.0,
        nonce,
        timestamp_ms: unix_ms()?,
    };
    let proof: JreqProof = jend_jreq::sign(&request, device)?;
    Ok(URL_SAFE_NO_PAD.encode(proof.encode()))
}

async fn get_current_device_set(
    client: &Client,
    base: &str,
    capability: &str,
    device: &SyncDeviceIdentity,
) -> Result<DeviceSetResponse, Box<dyn std::error::Error>> {
    let path = "/v1/devices/current";
    let proof = make_jreq_header(device, capability, "GET", path, b"")?;
    let response = client.get(format!("{base}{path}"))
        .bearer_auth(capability)
        .header("jend-request-proof", proof)
        .send().await?;
    let status = response.status();
    let bytes = response.bytes().await?;
    if !status.is_success() {
        return Err(format!("HTTP {status}: {}", String::from_utf8_lossy(&bytes)).into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

async fn refresh_device_capability(
    client: &Client,
    base: &str,
    capability: &str,
    device: &SyncDeviceIdentity,
) -> Result<DeviceBindingFinishResponse, Box<dyn std::error::Error>> {
    let path = "/v1/auth/device/refresh";
    let proof = make_jreq_header(device, capability, "POST", path, b"")?;
    let response = client.post(format!("{base}{path}"))
        .bearer_auth(capability)
        .header("jend-request-proof", proof)
        .body(Vec::<u8>::new())
        .send().await?;
    let status = response.status();
    let bytes = response.bytes().await?;
    if !status.is_success() {
        return Err(format!("HTTP {status}: {}", String::from_utf8_lossy(&bytes)).into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}


fn read_smoke_password(password_stdin: bool) -> Result<SensitivePassword, Box<dyn std::error::Error>> {
    if password_stdin {
        let mut input = Zeroizing::new(String::new());
        std::io::stdin().read_to_string(&mut *input)?;
        let mut lines = input.lines();
        let first = lines.next().ok_or("missing password on stdin")?;
        let second = lines.next().ok_or("missing password confirmation on stdin")?;
        if first != second {
            return Err("passwords do not match".into());
        }
        return Ok(SensitivePassword::from_utf8(first)?);
    }

    let password_text = Zeroizing::new(rpassword::prompt_password("Password (>=12 chars): ")?);
    let confirm = Zeroizing::new(rpassword::prompt_password("Repeat password: ")?);
    if password_text.as_str() != confirm.as_str() {
        return Err("passwords do not match".into());
    }
    Ok(SensitivePassword::from_utf8(password_text.as_str())?)
}

async fn assert_bearer_without_jreq_rejected(
    client: &Client,
    base: &str,
    capability: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = client.get(format!("{base}/v1/devices/current"))
        .bearer_auth(capability)
        .send().await?;
    if response.status() != StatusCode::UNAUTHORIZED {
        return Err(format!(
            "security regression: bearer-only device request returned {}",
            response.status()
        ).into());
    }
    Ok(())
}

async fn assert_jreq_replay_rejected(
    client: &Client,
    base: &str,
    capability: &str,
    device: &SyncDeviceIdentity,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = "/v1/devices/current";
    let proof = make_jreq_header(device, capability, "GET", path, b"")?;

    let first = client.get(format!("{base}{path}"))
        .bearer_auth(capability)
        .header("jend-request-proof", &proof)
        .send().await?;
    if !first.status().is_success() {
        return Err(format!("first JREQ unexpectedly failed: {}", first.status()).into());
    }

    let replay = client.get(format!("{base}{path}"))
        .bearer_auth(capability)
        .header("jend-request-proof", proof)
        .send().await?;
    if replay.status() != StatusCode::UNAUTHORIZED {
        return Err(format!(
            "security regression: replayed JREQ returned {}",
            replay.status()
        ).into());
    }
    Ok(())
}

async fn smoke_register(
    base: &str,
    username: &str,
    password_stdin: bool,
) -> Result<(), Box<dyn std::error::Error>> {

    let client = Client::builder()
        .https_only(false) // localhost smoke mode; production must use HTTPS.
        .build()?;

    let ready = client.get(format!("{base}/readyz")).send().await?;
    if ready.status() != StatusCode::OK {
        return Err(format!("gateway not ready: {}", ready.status()).into());
    }

    let admission: AdmissionResponse = post_json(
        &client,
        format!("{base}/v1/registration/admission"),
        &UsernameRequest { username },
        None,
    ).await?;
    let challenge = RegistrationChallenge::decode(&decode_b64(&admission.challenge)?)?;
    if challenge.difficulty_bits != admission.difficulty_bits
        || challenge.expires_unix_ms != admission.expires_unix_ms
    {
        return Err("admission response mismatch".into());
    }
    // Development smoke client only. Production UI should solve off the UI thread
    // and enforce its own work/time budget.
    let solution = solve_for_testing(&challenge, 1u64 << 28)
        .ok_or("unable to solve registration proof of work in smoke budget")?;

    let password = read_smoke_password(password_stdin)?;

    let (reg_state, opaque_request) = client_registration_start(&password)?;
    let started: OpaqueStartResponse = post_json(
        &client,
        format!("{base}/v1/auth/register/start"),
        &RegistrationStartRequest {
            username,
            challenge: &admission.challenge,
            solution,
            opaque_request: URL_SAFE_NO_PAD.encode(opaque_request),
        },
        None,
    ).await?;
    let reg_finished = client_registration_finish(
        reg_state, &password, &decode_b64(&started.opaque_response)?,
    )?;
    let registered: RegistrationFinishResponse = post_json(
        &client,
        format!("{base}/v1/auth/register/finish"),
        &RegistrationFinishRequest {
            username,
            ticket: &started.ticket,
            upload: URL_SAFE_NO_PAD.encode(reg_finished.upload),
        },
        None,
    ).await?;
    if !registered.registered {
        return Err("registration was not committed".into());
    }
    require_future_expiry("registration bootstrap", registered.bootstrap_expires_unix_ms)?;

    let account_raw: [u8; 16] = decode_b64(&registered.account_id)?
        .try_into().map_err(|_| "invalid account id returned by gateway")?;
    let account_id = AccountId(account_raw);
    let device = SyncDeviceIdentity::generate()?;
    let genesis = SignedDeviceSet::sign_genesis(
        DeviceSet::genesis(account_id, device.public_identity()), &device,
    )?;
    let genesis_reply: DeviceGenesisResponse = post_json(
        &client,
        format!("{base}/v1/devices/genesis"),
        &DeviceGenesisRequest {
            account_id: &registered.account_id,
            device_bootstrap: &registered.device_bootstrap,
            device_set: URL_SAFE_NO_PAD.encode(genesis.encode()?),
        },
        None,
    ).await?;
    if !genesis_reply.activated || genesis_reply.epoch != 0 {
        return Err("device genesis did not activate account".into());
    }

    // Login again after activation. OPAQUE client state never leaves this process.
    let (login_state, login_request) = client_login_start(&password)?;
    let login_started: OpaqueStartResponse = post_json(
        &client,
        format!("{base}/v1/auth/login/start"),
        &LoginStartRequest {
            username,
            opaque_request: URL_SAFE_NO_PAD.encode(login_request),
        },
        None,
    ).await?;
    let login_finished = client_login_finish(
        login_state, &password, &decode_b64(&login_started.opaque_response)?,
    )?;
    let login: LoginFinishResponse = post_json(
        &client,
        format!("{base}/v1/auth/login/finish"),
        &LoginFinishRequest {
            ticket: &login_started.ticket,
            finalization: URL_SAFE_NO_PAD.encode(login_finished.finalization),
        },
        None,
    ).await?;
    require_future_expiry("login capability", login.expires_unix_ms)?;

    let bind_started: DeviceBindingBeginResponse = post_json(
        &client,
        format!("{base}/v1/devices/bind/start"),
        &serde_json::json!({}),
        Some(&login.capability),
    ).await?;
    let session_challenge = DeviceSessionChallenge::decode(
        &decode_b64(&bind_started.challenge)?,
    )?;
    if session_challenge.expires_unix_ms != bind_started.expires_unix_ms {
        return Err("device binding challenge expiry mismatch".into());
    }
    require_future_expiry("device binding challenge", bind_started.expires_unix_ms)?;
    let proof = DeviceSessionProof::sign(&session_challenge, &device);
    let bound: DeviceBindingFinishResponse = post_json(
        &client,
        format!("{base}/v1/devices/bind/finish"),
        &DeviceBindingFinishRequest {
            challenge: bind_started.challenge,
            proof: URL_SAFE_NO_PAD.encode(proof.encode()),
        },
        Some(&login.capability),
    ).await?;
    require_future_expiry("device capability", bound.expires_unix_ms)?;

    // Device-bound reads now require a JREQ proof, not only a bearer token.
    let current = get_current_device_set(&client, base, &bound.capability, &device).await?;
    let current_set = SignedDeviceSet::decode(&decode_b64(&current.device_set)?)?;
    if current_set.set.account_id != account_id || current.epoch != 0
        || !current_set.set.contains(device.public_identity().device_id)
    {
        return Err("returned DeviceSet does not match registered device".into());
    }

    assert_bearer_without_jreq_rejected(
        &client, base, &bound.capability,
    ).await?;
    assert_jreq_replay_rejected(
        &client, base, &bound.capability, &device,
    ).await?;

    // Exercise JREQ-protected refresh while the capability is still valid.
    let refreshed = refresh_device_capability(
        &client, base, &bound.capability, &device,
    ).await?;
    require_future_expiry("refreshed device capability", refreshed.expires_unix_ms)?;
    let refreshed_current = get_current_device_set(
        &client, base, &refreshed.capability, &device,
    ).await?;
    if refreshed_current.epoch != 0 {
        return Err("refreshed capability returned unexpected DeviceSet".into());
    }

    // Exercise trusted-device session bootstrap with no password and no
    // pre-existing capability. This is the path used after a capability expires.
    let session_started: DeviceSessionStartResponse = post_json(
        &client,
        format!("{base}/v1/auth/device/session/start"),
        &DeviceSessionStartRequest { account_id: &registered.account_id },
        None,
    ).await?;
    let session_challenge = DeviceSessionChallenge::decode(
        &decode_b64(&session_started.challenge)?,
    )?;
    if session_challenge.expires_unix_ms != session_started.expires_unix_ms {
        return Err("device session challenge expiry mismatch".into());
    }
    require_future_expiry("device session challenge", session_started.expires_unix_ms)?;
    let session_proof = DeviceSessionProof::sign(&session_challenge, &device);
    let mut forged_mac = decode_b64(&session_started.challenge_mac)?;
    if forged_mac.is_empty() {
        return Err("empty device-session challenge MAC".into());
    }
    forged_mac[0] ^= 1;
    let forged = DeviceSessionFinishRequest {
        challenge: session_started.challenge.clone(),
        challenge_mac: URL_SAFE_NO_PAD.encode(forged_mac),
        proof: URL_SAFE_NO_PAD.encode(session_proof.encode()),
    };
    let forged_response = client.post(format!("{base}/v1/auth/device/session/finish"))
        .json(&forged)
        .send().await?;
    if forged_response.status() != StatusCode::UNAUTHORIZED {
        return Err(format!(
            "security regression: forged device-session challenge MAC returned {}",
            forged_response.status()
        ).into());
    }

    let session_finish = DeviceSessionFinishRequest {
        challenge: session_started.challenge,
        challenge_mac: session_started.challenge_mac,
        proof: URL_SAFE_NO_PAD.encode(session_proof.encode()),
    };
    let session_cap: DeviceBindingFinishResponse = post_json(
        &client,
        format!("{base}/v1/auth/device/session/finish"),
        &session_finish,
        None,
    ).await?;
    require_future_expiry("trusted-device capability", session_cap.expires_unix_ms)?;

    let replay = client.post(format!("{base}/v1/auth/device/session/finish"))
        .json(&session_finish)
        .send().await?;
    if replay.status() != StatusCode::UNAUTHORIZED {
        return Err(format!(
            "security regression: replayed device-session proof returned {}",
            replay.status()
        ).into());
    }
    let session_current = get_current_device_set(
        &client, base, &session_cap.capability, &device,
    ).await?;
    if session_current.epoch != 0 {
        return Err("device-session capability rejected".into());
    }

    // Never print password, OPAQUE keys, bootstrap secret, or capabilities.
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if !(args.len() == 4 || args.len() == 5) || args[1] != "smoke-register" {
        return Err(
            "usage: jend-cli smoke-register <base-url> <username> [--password-stdin]".into()
        );
    }
    let password_stdin = match args.get(4).map(String::as_str) {
        None => false,
        Some("--password-stdin") => true,
        Some(_) => return Err("unknown option".into()),
    };
    let base = args[2].trim_end_matches('/');
    smoke_register(base, &args[3], password_stdin).await
}
