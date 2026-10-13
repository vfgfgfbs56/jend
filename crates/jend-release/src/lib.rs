#![forbid(unsafe_code)]

//! Production release authorization primitives for Jend.
//!
//! This crate deliberately separates independent builder attestations from
//! release approvals. A valid production artifact needs both. The hash-chain
//! state here gives a client local anti-rollback/fork detection once it has a
//! trusted head; a public transparency service with independent witnesses/gossip
//! is a later layer and MUST NOT be implied by this local chain alone.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

const STATEMENT_MAGIC: &[u8; 4] = b"JREL";
const STATEMENT_VERSION: u16 = 1;
const STATEMENT_ID_DOMAIN: &[u8] = b"JEND/RELEASE/STATEMENT-ID/V1";
const BUILDER_KEY_ID_DOMAIN: &[u8] = b"JEND/RELEASE/BUILDER-KEY-ID/V1";
const APPROVER_KEY_ID_DOMAIN: &[u8] = b"JEND/RELEASE/APPROVER-KEY-ID/V1";
const BUILD_ATTEST_DOMAIN: &[u8] = b"JEND/RELEASE/BUILD-ATTESTATION/V1";
const APPROVAL_DOMAIN: &[u8] = b"JEND/RELEASE/APPROVAL/V1";
const MAX_VERSION_LEN: usize = 64;
const MAX_TARGET_LEN: usize = 128;
const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum ReleaseError {
    #[error("operating-system CSPRNG failed")]
    Random(#[from] getrandom::Error),
    #[error("release statement is malformed")]
    Malformed,
    #[error("release statement violates policy")]
    Policy,
    #[error("release signature is invalid")]
    Signature,
    #[error("release signer is not trusted")]
    UntrustedSigner,
    #[error("not enough independent builder attestations")]
    BuilderThreshold,
    #[error("not enough independent release approvals")]
    ApprovalThreshold,
    #[error("artifact digest/size does not match release statement")]
    ArtifactMismatch,
    #[error("release sequence rollback or fork detected")]
    ReleaseChain,
}

pub type Result<T> = core::result::Result<T, ReleaseError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ArtifactKind {
    Vault = 1,
    Ui = 2,
    Network = 3,
    LocalAiRuntime = 4,
    DesktopBundle = 5,
    MobileBundle = 6,
    Model = 7,
}

impl TryFrom<u8> for ArtifactKind {
    type Error = ReleaseError;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Vault),
            2 => Ok(Self::Ui),
            3 => Ok(Self::Network),
            4 => Ok(Self::LocalAiRuntime),
            5 => Ok(Self::DesktopBundle),
            6 => Ok(Self::MobileBundle),
            7 => Ok(Self::Model),
            _ => Err(ReleaseError::Malformed),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ReleaseKeyId(pub [u8; 16]);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ReleaseStatementId(pub [u8; 32]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseStatement {
    pub artifact_kind: ArtifactKind,
    pub sequence: u64,
    pub version: String,
    pub target: String,
    pub artifact_size: u64,
    pub artifact_sha256: [u8; 32],
    /// Digest of a canonical source snapshot/tree, not a human-readable branch.
    pub source_tree_sha256: [u8; 32],
    /// Digest of the pinned toolchain/build recipe/container definition.
    pub build_recipe_sha256: [u8; 32],
    /// All-zero only for sequence 0. Otherwise the previous accepted statement ID.
    pub previous_statement_id: ReleaseStatementId,
}

impl ReleaseStatement {
    pub fn validate(&self) -> Result<()> {
        if self.version.is_empty()
            || self.version.len() > MAX_VERSION_LEN
            || self.target.is_empty()
            || self.target.len() > MAX_TARGET_LEN
            || self.artifact_size == 0
            || self.artifact_size > MAX_ARTIFACT_BYTES
        {
            return Err(ReleaseError::Policy);
        }
        if self.sequence == 0 {
            if self.previous_statement_id.0 != [0u8; 32] {
                return Err(ReleaseError::ReleaseChain);
            }
        } else if self.previous_statement_id.0 == [0u8; 32] {
            return Err(ReleaseError::ReleaseChain);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let version = self.version.as_bytes();
        let target = self.target.as_bytes();
        let mut out = Vec::with_capacity(4 + 2 + 1 + 8 + 2 + version.len() + 2 + target.len() + 8 + 32 * 4);
        out.extend_from_slice(STATEMENT_MAGIC);
        out.extend_from_slice(&STATEMENT_VERSION.to_be_bytes());
        out.push(self.artifact_kind as u8);
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&(version.len() as u16).to_be_bytes());
        out.extend_from_slice(version);
        out.extend_from_slice(&(target.len() as u16).to_be_bytes());
        out.extend_from_slice(target);
        out.extend_from_slice(&self.artifact_size.to_be_bytes());
        out.extend_from_slice(&self.artifact_sha256);
        out.extend_from_slice(&self.source_tree_sha256);
        out.extend_from_slice(&self.build_recipe_sha256);
        out.extend_from_slice(&self.previous_statement_id.0);
        Ok(out)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let mut pos = 0usize;
        if take::<4>(bytes, &mut pos)? != *STATEMENT_MAGIC { return Err(ReleaseError::Malformed); }
        if u16::from_be_bytes(take(bytes, &mut pos)?) != STATEMENT_VERSION { return Err(ReleaseError::Malformed); }
        let artifact_kind = ArtifactKind::try_from(take::<1>(bytes, &mut pos)?[0])?;
        let sequence = u64::from_be_bytes(take(bytes, &mut pos)?);
        let version_len = u16::from_be_bytes(take(bytes, &mut pos)?) as usize;
        if version_len == 0 || version_len > MAX_VERSION_LEN { return Err(ReleaseError::Malformed); }
        let version = String::from_utf8(take_slice(bytes, &mut pos, version_len)?.to_vec()).map_err(|_| ReleaseError::Malformed)?;
        let target_len = u16::from_be_bytes(take(bytes, &mut pos)?) as usize;
        if target_len == 0 || target_len > MAX_TARGET_LEN { return Err(ReleaseError::Malformed); }
        let target = String::from_utf8(take_slice(bytes, &mut pos, target_len)?.to_vec()).map_err(|_| ReleaseError::Malformed)?;
        let artifact_size = u64::from_be_bytes(take(bytes, &mut pos)?);
        let artifact_sha256 = take(bytes, &mut pos)?;
        let source_tree_sha256 = take(bytes, &mut pos)?;
        let build_recipe_sha256 = take(bytes, &mut pos)?;
        let previous_statement_id = ReleaseStatementId(take(bytes, &mut pos)?);
        if pos != bytes.len() { return Err(ReleaseError::Malformed); }
        let out = Self { artifact_kind, sequence, version, target, artifact_size, artifact_sha256, source_tree_sha256, build_recipe_sha256, previous_statement_id };
        out.validate()?;
        Ok(out)
    }

    pub fn statement_id(&self) -> Result<ReleaseStatementId> {
        let bytes = self.canonical_bytes()?;
        let mut h = Sha256::new();
        h.update(STATEMENT_ID_DOMAIN);
        h.update(bytes);
        Ok(ReleaseStatementId(h.finalize().into()))
    }

    pub fn verify_artifact(&self, artifact: &[u8]) -> Result<()> {
        if artifact.len() as u64 != self.artifact_size { return Err(ReleaseError::ArtifactMismatch); }
        let digest: [u8; 32] = Sha256::digest(artifact).into();
        if digest != self.artifact_sha256 { return Err(ReleaseError::ArtifactMismatch); }
        Ok(())
    }
}

pub struct BuilderSigningKey { key: SigningKey, key_id: ReleaseKeyId }
pub struct ApproverSigningKey { key: SigningKey, key_id: ReleaseKeyId }

#[derive(Clone)]
pub struct BuilderPublicKey { key: VerifyingKey, key_id: ReleaseKeyId }
#[derive(Clone)]
pub struct ApproverPublicKey { key: VerifyingKey, key_id: ReleaseKeyId }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildAttestation {
    pub builder_key_id: ReleaseKeyId,
    pub statement_id: ReleaseStatementId,
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseApproval {
    pub approver_key_id: ReleaseKeyId,
    pub statement_id: ReleaseStatementId,
    pub signature: [u8; 64],
}

macro_rules! signing_key_impl {
    ($name:ident, $public:ident, $domain:expr, $key_domain:expr, $output:ident, $field:ident) => {
        impl $name {
            pub fn generate() -> Result<Self> {
                let mut secret = [0u8; 32];
                getrandom::fill(&mut secret)?;
                Ok(Self::from_secret_bytes(&mut secret))
            }
            pub fn from_secret_bytes(secret: &mut [u8; 32]) -> Self {
                let key = SigningKey::from_bytes(secret);
                secret.zeroize();
                let key_id = derive_key_id($key_domain, &key.verifying_key().to_bytes());
                Self { key, key_id }
            }
            pub fn public_key(&self) -> $public {
                $public { key: self.key.verifying_key(), key_id: self.key_id }
            }
            pub fn sign(&self, statement: &ReleaseStatement) -> Result<$output> {
                let statement_id = statement.statement_id()?;
                let signature = self.key.sign(&signature_message($domain, self.key_id, statement_id)).to_bytes();
                Ok($output { $field: self.key_id, statement_id, signature })
            }
        }
    };
}

signing_key_impl!(BuilderSigningKey, BuilderPublicKey, BUILD_ATTEST_DOMAIN, BUILDER_KEY_ID_DOMAIN, BuildAttestation, builder_key_id);
signing_key_impl!(ApproverSigningKey, ApproverPublicKey, APPROVAL_DOMAIN, APPROVER_KEY_ID_DOMAIN, ReleaseApproval, approver_key_id);

impl BuilderPublicKey {
    pub fn key_id(&self) -> ReleaseKeyId { self.key_id }
    pub fn as_bytes(&self) -> [u8; 32] { self.key.to_bytes() }
    fn verify(&self, attestation: &BuildAttestation, expected: ReleaseStatementId) -> Result<()> {
        if self.key_id != attestation.builder_key_id || attestation.statement_id != expected { return Err(ReleaseError::Signature); }
        self.key.verify_strict(&signature_message(BUILD_ATTEST_DOMAIN, self.key_id, expected), &Signature::from_bytes(&attestation.signature)).map_err(|_| ReleaseError::Signature)
    }
}

impl ApproverPublicKey {
    pub fn key_id(&self) -> ReleaseKeyId { self.key_id }
    pub fn as_bytes(&self) -> [u8; 32] { self.key.to_bytes() }
    fn verify(&self, approval: &ReleaseApproval, expected: ReleaseStatementId) -> Result<()> {
        if self.key_id != approval.approver_key_id || approval.statement_id != expected { return Err(ReleaseError::Signature); }
        self.key.verify_strict(&signature_message(APPROVAL_DOMAIN, self.key_id, expected), &Signature::from_bytes(&approval.signature)).map_err(|_| ReleaseError::Signature)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseBundle {
    pub statement: ReleaseStatement,
    pub builder_attestations: Vec<BuildAttestation>,
    pub approvals: Vec<ReleaseApproval>,
}

#[derive(Clone)]
pub struct ReleasePolicy {
    builders: BTreeMap<ReleaseKeyId, BuilderPublicKey>,
    approvers: BTreeMap<ReleaseKeyId, ApproverPublicKey>,
    required_builders: usize,
    required_approvers: usize,
}

impl ReleasePolicy {
    pub fn new(
        builders: impl IntoIterator<Item = BuilderPublicKey>,
        required_builders: usize,
        approvers: impl IntoIterator<Item = ApproverPublicKey>,
        required_approvers: usize,
    ) -> Result<Self> {
        let builders: BTreeMap<_, _> = builders.into_iter().map(|k| (k.key_id(), k)).collect();
        let approvers: BTreeMap<_, _> = approvers.into_iter().map(|k| (k.key_id(), k)).collect();
        if required_builders == 0 || required_approvers == 0 || required_builders > builders.len() || required_approvers > approvers.len() {
            return Err(ReleaseError::Policy);
        }
        Ok(Self { builders, approvers, required_builders, required_approvers })
    }

    pub fn verify_bundle(&self, bundle: &ReleaseBundle) -> Result<()> {
        bundle.statement.validate()?;
        let statement_id = bundle.statement.statement_id()?;

        let mut builders_seen = BTreeSet::new();
        for attestation in &bundle.builder_attestations {
            if !builders_seen.insert(attestation.builder_key_id) { continue; }
            let key = self.builders.get(&attestation.builder_key_id).ok_or(ReleaseError::UntrustedSigner)?;
            key.verify(attestation, statement_id)?;
        }
        if builders_seen.len() < self.required_builders { return Err(ReleaseError::BuilderThreshold); }

        let mut approvers_seen = BTreeSet::new();
        for approval in &bundle.approvals {
            if !approvers_seen.insert(approval.approver_key_id) { continue; }
            let key = self.approvers.get(&approval.approver_key_id).ok_or(ReleaseError::UntrustedSigner)?;
            key.verify(approval, statement_id)?;
        }
        if approvers_seen.len() < self.required_approvers { return Err(ReleaseError::ApprovalThreshold); }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptedReleaseHead {
    pub sequence: u64,
    pub statement_id: ReleaseStatementId,
}

impl AcceptedReleaseHead {
    pub fn genesis(bundle: &ReleaseBundle, policy: &ReleasePolicy) -> Result<Self> {
        policy.verify_bundle(bundle)?;
        if bundle.statement.sequence != 0 || bundle.statement.previous_statement_id.0 != [0u8; 32] {
            return Err(ReleaseError::ReleaseChain);
        }
        Ok(Self { sequence: 0, statement_id: bundle.statement.statement_id()? })
    }

    /// Verify an exact next release. This gives local anti-rollback/fork
    /// protection. It is not a substitute for a witnessed public transparency log.
    pub fn advance(self, bundle: &ReleaseBundle, policy: &ReleasePolicy) -> Result<Self> {
        policy.verify_bundle(bundle)?;
        if bundle.statement.sequence != self.sequence.checked_add(1).ok_or(ReleaseError::ReleaseChain)?
            || bundle.statement.previous_statement_id != self.statement_id
        {
            return Err(ReleaseError::ReleaseChain);
        }
        Ok(Self { sequence: bundle.statement.sequence, statement_id: bundle.statement.statement_id()? })
    }

    /// Fail-closed updater primitive: both release policy/chain and exact artifact
    /// bytes must verify before a caller persists the returned head or installs.
    pub fn verify_update(
        self,
        bundle: &ReleaseBundle,
        artifact: &[u8],
        policy: &ReleasePolicy,
    ) -> Result<Self> {
        bundle.statement.verify_artifact(artifact)?;
        self.advance(bundle, policy)
    }
}

fn derive_key_id(domain: &[u8], public: &[u8; 32]) -> ReleaseKeyId {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(public);
    let digest = h.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    ReleaseKeyId(id)
}

fn signature_message(domain: &[u8], key_id: ReleaseKeyId, statement_id: ReleaseStatementId) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + 16 + 32);
    out.extend_from_slice(domain);
    out.extend_from_slice(&key_id.0);
    out.extend_from_slice(&statement_id.0);
    out
}

fn take<const N: usize>(bytes: &[u8], pos: &mut usize) -> Result<[u8; N]> {
    let end = pos.checked_add(N).ok_or(ReleaseError::Malformed)?;
    if end > bytes.len() { return Err(ReleaseError::Malformed); }
    let out = bytes[*pos..end].try_into().map_err(|_| ReleaseError::Malformed)?;
    *pos = end;
    Ok(out)
}

fn take_slice<'a>(bytes: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = pos.checked_add(len).ok_or(ReleaseError::Malformed)?;
    if end > bytes.len() { return Err(ReleaseError::Malformed); }
    let out = &bytes[*pos..end];
    *pos = end;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement(artifact: &[u8]) -> ReleaseStatement {
        ReleaseStatement {
            artifact_kind: ArtifactKind::Vault,
            sequence: 0,
            version: "0.1.0".into(),
            target: "x86_64-unknown-linux-gnu".into(),
            artifact_size: artifact.len() as u64,
            artifact_sha256: Sha256::digest(artifact).into(),
            source_tree_sha256: [7u8; 32],
            build_recipe_sha256: [8u8; 32],
            previous_statement_id: ReleaseStatementId([0u8; 32]),
        }
    }

    #[test]
    fn two_builders_and_two_approvers_are_required() {
        let b1 = BuilderSigningKey::generate().unwrap();
        let b2 = BuilderSigningKey::generate().unwrap();
        let b3 = BuilderSigningKey::generate().unwrap();
        let a1 = ApproverSigningKey::generate().unwrap();
        let a2 = ApproverSigningKey::generate().unwrap();
        let a3 = ApproverSigningKey::generate().unwrap();
        let s = statement(b"artifact");
        let policy = ReleasePolicy::new(
            [b1.public_key(), b2.public_key(), b3.public_key()], 2,
            [a1.public_key(), a2.public_key(), a3.public_key()], 2,
        ).unwrap();
        let bundle = ReleaseBundle {
            statement: s.clone(),
            builder_attestations: vec![b1.sign(&s).unwrap(), b2.sign(&s).unwrap()],
            approvals: vec![a1.sign(&s).unwrap(), a2.sign(&s).unwrap()],
        };
        policy.verify_bundle(&bundle).unwrap();
        s.verify_artifact(b"artifact").unwrap();
    }
}
