# M3.5 — Jend recovery protocol

## Security goal

Password recovery must not create a server-side master path into encrypted user data.
A six-digit code is a human comparison value, **not** an authentication secret.

## Trusted-device password reset

1. The new device generates its own signing/KEX keys and a self-signed `RecoveryRequest`.
2. The relay routes the opaque request to already trusted devices.
3. A trusted device verifies account binding, device fingerprint, expiry and user intent.
4. The trusted device creates a short-lived `RecoveryApproval`, signs it, then encrypts it to the candidate device using X25519 + HKDF + XChaCha20-Poly1305.
5. A fresh six-digit code is mixed into the approval encryption key and shown only on the trusted device. The code is never sent through the relay.
6. The new device obtains the code from the human, opens the approval and verifies the trusted-device signature and pinned `DeviceSet` epoch/hash.
7. The auth service accepts a new OPAQUE registration only when presented with that valid approval.
8. Finishing reset returns a random 256-bit `grant_nonce`. Persistence atomically inserts that nonce as consumed, replaces the OPAQUE password file, increments `auth_epoch`, and invalidates old sessions.

The server cannot manufacture step 4 because it lacks a trusted device private key.
Possession of the six-digit code alone is insufficient.

## Replay protection

`request_id`, request commitment, candidate device identity, current DeviceSet hash/epoch,
expiry and random `grant_nonce` are cryptographically bound into the approval. The database
must enforce `grant_nonce` uniqueness. Replaying an old approval therefore cannot perform a
second password rotation.

## No-device case

There is intentionally no hidden administrator recovery key. Future recovery options are:

- guardian threshold recovery (for example 2-of-3 trusted Jend accounts),
- an optional offline recovery card,
- later, distributed recovery shares across independent providers.

If all trusted devices and every user-configured recovery factor are lost, encrypted history
is unrecoverable. Making it recoverable by Jend alone would violate the zero-access design.

## Account recovery vs data recovery

Password reset restores account authentication only. Access to historical chats requires
authorization into the encrypted device/sync key graph. These capabilities remain separate.
