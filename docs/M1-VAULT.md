# M1 — Jend Vault design

Status: implementation draft; compile/integration testing intentionally deferred to the test milestone.

## Goal

Jend Vault is the only normal client component that owns account/device cryptographic secrets. It has no Internet access. UI and local-AI processes may receive narrowly scoped plaintext, but they also have no Internet access. The Network process has Internet access but receives neither raw keys nor arbitrary conversation plaintext.

```text
             Internet
                ^
                |
        +-------+--------+
        | Jend Network   |
        | network: YES   |
        | keys:    NO    |
        | plaintext: NO  |
        +-------+--------+
                |
          typed local IPC
                |
       +--------+---------+
       |                  |
+------+-----+      +-----+--------+
| Jend UI    |      | Local AI     |
| network:NO |      | network:NO   |
| plaintext  |      | plaintext    |
+------+-----+      +-----+--------+
       |                  |
       +--------+---------+
                |
           local IPC
                |
        +-------+--------+
        | Jend Vault     |
        | network: NO    |
        | keys:    YES   |
        | plaintext:YES  |
        +----------------+
```

## M1 components

- `jend-core`: crypto/container primitives.
- `jend-vault`: local key-owning service and storage engine.
- `jend-vaultd`: Unix-domain-socket daemon for the first Linux prototype.
- `security/processes.toml`: declarative capability baseline.
- `deployment/systemd/jend-vault.service`: Linux sandbox baseline with `PrivateNetwork=yes` and `AF_UNIX` only.

## Secret handling

M1 introduces an explicit `SecretStore` boundary. The included `DevFileSecretStore` is **development-only** and stores 32-byte secrets in mode-0600 files under a mode-0700 directory.

Production adapters must use platform facilities where possible:

- Windows: TPM / CNG / DPAPI-backed key storage;
- macOS/iOS: Keychain / Secure Enclave where applicable;
- Android: Android Keystore / StrongBox where available;
- Linux: TPM2-backed secret sealing or a reviewed desktop secret-service integration.

The cryptographic API accepts imported secret bytes only through consuming/zeroizing buffers. There is intentionally no `AccountRootKey::export_*` or device-private-key export API.

## Encrypted conversation index

The local `conversations.idx` file contains conversation IDs and wrapped conversation seeds. The complete index plaintext is encrypted under a domain-separated key derived internally from the Account Root Key.

The disk format exposes only:

```text
JVIX | version | nonce | ciphertext_length | ciphertext
```

The Account Root Key itself is not written into the index.

## Append-only conversation logs

Each conversation has a `<conversation-id>.jendlog` file. A log is a sequence of frames:

```text
u32_be record_length
record_length bytes of canonical .jend v1 record
```

A complete frame is cryptographically checked by `jend-core` before it is accepted during recovery.

## Transactional ratchet transition

Persistent writes use a two-phase ratchet operation:

```text
prepare_next()
     |
     +--> message key
     +--> candidate next chain key

seal .jend record
     |
write durability journal + fsync
     |
append record + fsync
     |
commit_prepared()
```

If disk append fails, the in-memory ratchet does not advance.

## Durability journal

Blindly truncating an incomplete tail is dangerous because tampering with a length prefix could otherwise be mistaken for a power failure.

Before appending a record, Vault writes and fsyncs a `.pending` journal containing:

- log length before append;
- expected encoded record length;
- SHA-256 domain-separated digest of the exact record.

Recovery rules:

1. no pending journal + malformed/incomplete tail -> fail closed;
2. valid pending + no bytes appended -> remove journal;
3. valid pending + partial exact append -> truncate to recorded pre-length;
4. valid pending + complete exact append -> verify hash and `.jend`, then accept;
5. pending/log mismatch -> fail closed.

Future timestamp/Merkle anchoring is still required to detect an attacker who can arbitrarily roll back the entire local storage directory.

## IPC M1

M1 uses a small hand-written binary protocol over Unix domain sockets. Current request types are deliberately narrow:

- create conversation;
- append one message;
- list conversation IDs;
- read one conversation history for a local plaintext consumer.

IPC request buffers containing plaintext are zeroized after handling. The IPC protocol is not exposed on TCP/UDP.

## Known M1 limitations

- Linux/Unix daemon only for the first prototype;
- development file secret store is not hardware-backed;
- single trusted device signer per local Vault;
- rebuilding a ratchet after restart scans the conversation log from the beginning;
- no multi-device protocol yet;
- no external Merkle/timestamp anchor yet;
- no release threshold-signing enforcement yet;
- code has not yet passed the planned Rust compile/test/fuzz/audit milestone.
