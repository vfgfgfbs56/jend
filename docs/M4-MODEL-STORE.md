# M4 — Jend Model Store

Status: architecture/prototype implementation. Not production-audited.

## Goal

Jend lets an account select at most three active models at a time. The model
store is control-plane infrastructure only: it must never gain chat plaintext,
conversation keys, local AI context, or Vault master keys.

Account selection and physical installation are separate concepts:

```text
account
  slot 0 -> Model A
  slot 1 -> Model B
  slot 2 -> Model C

Desktop: A, B
Laptop:  A, C
Phone:   A
```

Installing the same selected model on another trusted device does not consume a
fourth account slot.

## Database-enforced three-slot invariant

`model_entitlements.slot` is constrained to `0..2` and the primary key is
`(account_id, slot)`. Therefore application code cannot accidentally create a
fourth entitlement row for an account.

Slot replacement uses optimistic compare-and-swap with `entitlement_epoch` so
two devices cannot silently race an entitlement replacement.

## Signed manifest

A release is described by canonical binary `JMDL v1` metadata:

```text
model_id
release_sequence
minimum_runtime
format
architecture
quantization
total_plaintext_len
whole_model_sha256
chunk[]:
    index
    opaque object_id
    offset
    plaintext_len
    sha256
```

The object ID is random and does not encode the model name/version. URLs are not
signed into the manifest; CDN routing and signed download URLs may change
without changing the model's cryptographic identity.

`manifest_id = SHA-256(domain || canonical_manifest)`.

The release signature covers the manifest ID. A client accepts a release only
if all of the following hold:

1. canonical manifest decoding succeeds;
2. manifest structure/offsets/lengths are valid;
3. `manifest_id` recomputes exactly;
4. the release signature verifies against a pinned Jend release public key;
5. every downloaded chunk length/hash verifies;
6. the final assembled model length/hash verifies.

A compromised PostgreSQL row, object store, CDN or ordinary API server cannot
silently substitute another model without also defeating the release-signing
policy.

## Chunking and resumable download

Target chunk size for ordinary releases: 128 MiB. The manifest allows chunks up
to 512 MiB.

Client flow:

```text
verify signed manifest
        |
        v
create local .part state
        |
        +-> fetch missing chunk by opaque object_id
        |       |
        |       v
        |   stream SHA-256 while writing temp chunk
        |       |
        |       +-- mismatch -> delete temp chunk / retry
        |       |
        |       `-- match -> fsync / mark complete
        |
        v
all chunks complete
        |
        v
assemble/stream whole-model SHA-256
        |
        +-- mismatch -> fail closed
        |
        `-- match -> atomic rename to installed release
```

Partial chunks are never considered installed. Resume state is bound to one
`manifest_id`, so state from one release cannot be reused for another.

## Release key policy

M4 contains a single Ed25519 release-signing wrapper only as the cryptographic
building block. Production release authority is M5 and MUST NOT consist of one
developer-held signing key.

Production target:

```text
canonical manifest
    -> independent review/build evidence
    -> transparency inclusion
    -> 2-of-3 release authorization
    -> client verification
```

The single-key API is therefore suitable for test/dev/offline composition, not
the final governance policy.

## Download authorization

The future gateway issues short-lived download capabilities only after:

- valid account session;
- selected model exists in one of slots 0..2;
- requesting device is in the current signed DeviceSet;
- requested manifest belongs to the selected model and satisfies update policy.

The object/CDN layer receives a capability and opaque object ID; it does not need
chat state or Vault secrets.

## Model confidentiality / DRM limitation

Jend may optionally encrypt model chunks at rest and wrap a model content key to
a trusted device. This can stop casual URL sharing and reduce storage/CDN
exposure, but it cannot be an absolute confidentiality guarantee: a user who
fully controls their machine can eventually observe weights required for local
inference.

Therefore model DRM is not part of Jend's message-security trust claim.

## Privacy note

The baseline server currently knows the selected `model_id` for entitlement
enforcement. It still does not learn which conversation used which model. A
future privacy-preserving entitlement design may hide account model choices, but
that is not required for zero-access chat content.

## Edge/object-store serving rule

The CDN/object adapter must not accept a raw object ID as authorization. It must
verify the short-lived online download grant and bind it to the signed manifest:

```text
request(grant, manifest_id, object_id)
        |
        +-- verify online grant signature + expiry
        +-- grant.model_id == manifest.model_id
        +-- grant.manifest_id == SHA256(canonical manifest)
        +-- object_id is present in that manifest
        `-- only then serve object bytes
```

This makes random R2/object identifiers routing identifiers, not bearer secrets.
The online grant key remains separate from release authority.
