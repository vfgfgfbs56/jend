//! Immutable model-source and provenance contracts for Store ingestion.
//!
//! End-user clients never install arbitrary URLs. Store ingestion resolves a
//! source to an immutable identity, records license evidence, scans artifacts,
//! and only then produces Jend-signed manifests/object IDs.

use sha2::{Digest, Sha256};

use crate::{ModelObjectId, ModelStoreError, Result};

const SOURCE_DOMAIN: &[u8] = b"JEND/MODEL-SOURCE/V1";
const MAX_REPO_ID: usize = 128;
const MAX_HOST: usize = 253;
const MAX_PATH: usize = 1024;
const MAX_LICENSE_ID: usize = 96;
const MAX_PUBLISHER: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelSource {
    /// Hugging Face repository pinned to a full immutable 40-hex commit SHA.
    HuggingFaceSnapshot {
        repo_id: String,
        commit_sha: String,
    },

    /// Publisher-controlled HTTPS origin. The URL is constructed from validated
    /// host/path components and the artifact is pinned by SHA-256.
    PublisherHttps {
        host: String,
        immutable_path: String,
        artifact_sha256: [u8; 32],
    },

    /// Already-ingested immutable Jend object.
    JendObject {
        object_id: ModelObjectId,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LicenseEvidenceKind {
    HubMetadata,
    RepositoryLicenseFile,
    PublisherAttestation,
    JendCommercialAgreement,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedistributionDecision {
    /// Ingest may proceed, but public Store distribution is not approved yet.
    PendingReview,
    /// Publisher/model license permits the relevant weight redistribution.
    Approved,
    /// Model may be connected as a provider service but weights may not be
    /// redistributed by Jend.
    ProviderOnly,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LicenseEvidence {
    pub license_id: String,
    pub evidence_kind: LicenseEvidenceKind,
    pub redistribution: RedistributionDecision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelProvenance {
    pub publisher: String,
    pub source: ModelSource,
    pub license: LicenseEvidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SourceFingerprint(pub [u8; 32]);

impl ModelSource {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::HuggingFaceSnapshot {
                repo_id,
                commit_sha,
            } => {
                validate_repo_id(repo_id)?;
                if commit_sha.len() != 40
                    || !commit_sha
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(ModelStoreError::InvalidModelSource);
                }
            }
            Self::PublisherHttps {
                host,
                immutable_path,
                artifact_sha256,
            } => {
                validate_host(host)?;
                validate_immutable_path(immutable_path)?;
                if artifact_sha256.iter().all(|byte| *byte == 0) {
                    return Err(ModelStoreError::InvalidModelSource);
                }
            }
            Self::JendObject { object_id } => {
                if object_id.0.iter().all(|byte| *byte == 0) {
                    return Err(ModelStoreError::InvalidModelSource);
                }
            }
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> Result<SourceFingerprint> {
        self.validate()?;
        let mut h = Sha256::new();
        h.update(SOURCE_DOMAIN);
        match self {
            Self::HuggingFaceSnapshot {
                repo_id,
                commit_sha,
            } => {
                h.update([1]);
                put_len_bytes(&mut h, repo_id.as_bytes())?;
                put_len_bytes(&mut h, commit_sha.as_bytes())?;
            }
            Self::PublisherHttps {
                host,
                immutable_path,
                artifact_sha256,
            } => {
                h.update([2]);
                put_len_bytes(&mut h, host.as_bytes())?;
                put_len_bytes(&mut h, immutable_path.as_bytes())?;
                h.update(artifact_sha256);
            }
            Self::JendObject { object_id } => {
                h.update([3]);
                h.update(object_id.0);
            }
        }
        Ok(SourceFingerprint(h.finalize().into()))
    }

    /// Useful only for the typed Network ingest worker. End-user clients should
    /// never receive a raw publisher URL as an installation authority.
    pub fn publisher_https_url(&self) -> Result<Option<String>> {
        self.validate()?;
        Ok(match self {
            Self::PublisherHttps {
                host,
                immutable_path,
                ..
            } => Some(format!("https://{host}{immutable_path}")),
            _ => None,
        })
    }
}

impl ModelProvenance {
    pub fn validate(&self) -> Result<()> {
        validate_simple_text(&self.publisher, MAX_PUBLISHER)?;
        self.source.validate()?;
        validate_simple_text(&self.license.license_id, MAX_LICENSE_ID)?;
        Ok(())
    }

    pub fn permits_weight_publication(&self) -> Result<bool> {
        self.validate()?;
        Ok(self.license.redistribution == RedistributionDecision::Approved)
    }
}

fn validate_repo_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_REPO_ID
        || value.starts_with('/')
        || value.ends_with('/')
        || value.matches('/').count() != 1
        || !value.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/')
        })
    {
        return Err(ModelStoreError::InvalidModelSource);
    }
    Ok(())
}

fn validate_host(host: &str) -> Result<()> {
    if host.is_empty()
        || host.len() > MAX_HOST
        || host.starts_with('.')
        || host.ends_with('.')
        || host.contains("..")
        || !host.contains('.')
        || !host.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
    {
        return Err(ModelStoreError::InvalidModelSource);
    }

    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
        {
            return Err(ModelStoreError::InvalidModelSource);
        }
    }
    Ok(())
}

fn validate_immutable_path(path: &str) -> Result<()> {
    if !path.starts_with('/')
        || path.len() > MAX_PATH
        || path.contains('?')
        || path.contains('#')
        || path.contains('\\')
        || path.split('/').any(|segment| segment == "." || segment == "..")
        || !path.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'/' | b'-' | b'_' | b'.' | b'+' | b'=')
        })
    {
        return Err(ModelStoreError::InvalidModelSource);
    }
    Ok(())
}

fn validate_simple_text(text: &str, max: usize) -> Result<()> {
    if text.is_empty()
        || text.len() > max
        || !text.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b' ' | b'-' | b'_' | b'.' | b'/' | b'+')
        })
    {
        return Err(ModelStoreError::InvalidModelSource);
    }
    Ok(())
}

fn put_len_bytes(h: &mut Sha256, bytes: &[u8]) -> Result<()> {
    let len = u16::try_from(bytes.len()).map_err(|_| ModelStoreError::Overflow)?;
    h.update(len.to_be_bytes());
    h.update(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hugging_face_source_requires_full_immutable_commit() {
        let good = ModelSource::HuggingFaceSnapshot {
            repo_id: "org/model".into(),
            commit_sha: "0123456789abcdef0123456789abcdef01234567".into(),
        };
        assert!(good.validate().is_ok());

        let main = ModelSource::HuggingFaceSnapshot {
            repo_id: "org/model".into(),
            commit_sha: "main".into(),
        };
        assert!(main.validate().is_err());

        let short = ModelSource::HuggingFaceSnapshot {
            repo_id: "org/model".into(),
            commit_sha: "0123456".into(),
        };
        assert!(short.validate().is_err());
    }

    #[test]
    fn publisher_source_constructs_https_only_after_validation() {
        let source = ModelSource::PublisherHttps {
            host: "models.example.com".into(),
            immutable_path: "/releases/model-v1/model.safetensors".into(),
            artifact_sha256: [7u8; 32],
        };
        assert_eq!(
            source.publisher_https_url().unwrap().unwrap(),
            "https://models.example.com/releases/model-v1/model.safetensors"
        );
    }

    #[test]
    fn path_traversal_and_query_are_rejected() {
        for path in ["/a/../secret", "/model?latest=1", "/model#fragment"] {
            let source = ModelSource::PublisherHttps {
                host: "models.example.com".into(),
                immutable_path: path.into(),
                artifact_sha256: [9u8; 32],
            };
            assert!(source.validate().is_err());
        }
    }

    #[test]
    fn publication_requires_explicit_license_approval() {
        let pending = ModelProvenance {
            publisher: "Example".into(),
            source: ModelSource::JendObject {
                object_id: ModelObjectId([3u8; 32]),
            },
            license: LicenseEvidence {
                license_id: "apache-2.0".into(),
                evidence_kind: LicenseEvidenceKind::RepositoryLicenseFile,
                redistribution: RedistributionDecision::PendingReview,
            },
        };
        assert!(!pending.permits_weight_publication().unwrap());
    }

    #[test]
    fn source_fingerprint_is_stable_and_revision_bound() {
        let a = ModelSource::HuggingFaceSnapshot {
            repo_id: "org/model".into(),
            commit_sha: "0123456789abcdef0123456789abcdef01234567".into(),
        };
        let b = ModelSource::HuggingFaceSnapshot {
            repo_id: "org/model".into(),
            commit_sha: "1123456789abcdef0123456789abcdef01234567".into(),
        };
        assert_eq!(a.fingerprint().unwrap(), a.fingerprint().unwrap());
        assert_ne!(a.fingerprint().unwrap(), b.fingerprint().unwrap());
    }
}
