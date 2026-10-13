# M5 — Production release trust

Status: implementation baseline, pre-test/pre-audit.

Jend's server-side zero-access architecture is insufficient if one developer can
silently ship a modified plaintext-owning client. M5 therefore treats release
authorization as part of the cryptographic threat model.

## Independent roles

A production release should require two independent classes of evidence:

1. **Builder attestations** — independent builders assert that the exact artifact
   digest was produced from the declared source-tree and pinned build recipe.
2. **Release approvals** — independent release authorities approve that exact
   release statement for production distribution.

Initial target policy:

```text
3 registered independent builders  -> require any 2
3 registered independent approvers -> require any 2
```

The two sets should be operationally independent and use separate hardware-backed
keys. A person controlling two keys defeats the human-separation assumption even
if the cryptographic threshold verifies.

## Release statement

`jend-release` defines canonical `JREL v1` statements containing:

- artifact kind (Vault, UI, Network, local AI runtime, desktop/mobile bundle, model);
- monotonically increasing release sequence;
- version and target;
- artifact byte length and SHA-256 digest;
- canonical source-tree SHA-256 digest;
- pinned build-recipe/toolchain SHA-256 digest;
- previous accepted release-statement ID.

The previous-statement binding gives a client with a trusted head local
anti-rollback/fork detection.

## What is implemented

- canonical release statement encoding;
- domain-separated statement IDs;
- separate Ed25519 builder and approver key domains;
- unique-signer threshold verification;
- exact artifact size/digest verification;
- previous-release chain verification;
- `#![forbid(unsafe_code)]`.

## What this does NOT yet prove

A local release hash chain is **not** a public transparency log. A malicious
update service could try to maintain different valid-looking chains for different
users unless releases are published to a globally observable append-only log with
independent witnesses/gossip.

Therefore the following remain mandatory before production:

- deterministic/reproducible build pipeline;
- independent build infrastructure;
- public append-only release log;
- independent log witnesses / gossip or equivalent split-view detection;
- hardware-backed signing shares/keys;
- client-side fail-closed updater;
- external review of release governance and key rotation/recovery.

The security claim is deliberately limited: the goal is that compromising the
servers or one developer identity is insufficient to publish a privacy-breaking
client.
