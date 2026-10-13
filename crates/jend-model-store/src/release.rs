use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use zeroize::Zeroize;

use crate::{ids::derive_release_key_id, ManifestId, ModelManifest, ModelSourceMap, ModelStoreError, ReleaseKeyId, Result, SignedModelManifest, SignedModelSourceMap, SignedVirtualModelMap, SourceId, SourceMapId, VerifiedSourceReadRequest, VirtualMapId, VirtualModelMap, WeightPageId};

const RELEASE_SIGNATURE_DOMAIN: &[u8] = b"JEND/MODEL/RELEASE-SIGNATURE/V1";
const VIRTUAL_MAP_SIGNATURE_DOMAIN: &[u8] = b"JEND/MODEL/VIRTUAL-MAP-SIGNATURE/V1";
const SOURCE_MAP_SIGNATURE_DOMAIN: &[u8] = b"JEND/MODEL/SOURCE-MAP-SIGNATURE/V1";

pub struct ModelReleaseSigningKey {
    signing_key: SigningKey,
}

#[derive(Clone, Debug)]
pub struct ModelReleasePublicKey {
    verifying_key: VerifyingKey,
    key_id: ReleaseKeyId,
}

impl ModelReleaseSigningKey {
    pub fn generate() -> Result<Self> {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret)?;
        Ok(Self::from_secret_bytes(&mut secret))
    }

    /// Intended for an offline/threshold release-signing adapter. The caller's
    /// secret buffer is cleared and there is no secret-export API.
    pub fn from_secret_bytes(secret: &mut [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(secret);
        secret.zeroize();
        Self { signing_key }
    }

    pub fn public_key(&self) -> ModelReleasePublicKey {
        ModelReleasePublicKey::new(self.signing_key.verifying_key())
    }

    pub fn sign_manifest(&self, manifest: ModelManifest) -> Result<SignedModelManifest> {
        let manifest_id = manifest.manifest_id()?;
        let public = self.public_key();
        let signature = self.signing_key.sign(&signature_message(manifest_id)).to_bytes();
        Ok(SignedModelManifest {
            manifest,
            manifest_id,
            release_key_id: public.key_id,
            signature,
        })
    }

    pub fn sign_virtual_map(&self, map: VirtualModelMap) -> Result<SignedVirtualModelMap> {
        let map_id = map.map_id()?;
        let public = self.public_key();
        let signature = self
            .signing_key
            .sign(&virtual_map_signature_message(map_id))
            .to_bytes();
        Ok(SignedVirtualModelMap {
            map,
            map_id,
            release_key_id: public.key_id,
            signature,
        })
    }

    pub fn sign_source_map(&self, map: ModelSourceMap) -> Result<SignedModelSourceMap> {
        let map_id = map.map_id()?;
        let public = self.public_key();
        let signature = self
            .signing_key
            .sign(&source_map_signature_message(map_id))
            .to_bytes();
        Ok(SignedModelSourceMap {
            map,
            map_id,
            release_key_id: public.key_id,
            signature,
        })
    }
}

impl ModelReleasePublicKey {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let verifying_key = VerifyingKey::from_bytes(bytes).map_err(|_| ModelStoreError::InvalidSignature)?;
        Ok(Self::new(verifying_key))
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    pub fn key_id(&self) -> ReleaseKeyId {
        self.key_id
    }

    pub fn verify(&self, signed: &SignedModelManifest) -> Result<()> {
        let recomputed = signed.manifest.manifest_id()?;
        if recomputed != signed.manifest_id {
            return Err(ModelStoreError::InvalidManifest);
        }
        if signed.release_key_id != self.key_id {
            return Err(ModelStoreError::ReleaseKeyMismatch);
        }
        let signature = Signature::from_bytes(&signed.signature);
        self.verifying_key
            .verify_strict(&signature_message(recomputed), &signature)
            .map_err(|_| ModelStoreError::InvalidSignature)
    }

    pub fn verify_virtual_map(&self, signed: &SignedVirtualModelMap) -> Result<()> {
        let recomputed = signed.map.map_id()?;
        if recomputed != signed.map_id {
            return Err(ModelStoreError::InvalidVirtualModelMap);
        }
        if signed.release_key_id != self.key_id {
            return Err(ModelStoreError::ReleaseKeyMismatch);
        }
        let signature = Signature::from_bytes(&signed.signature);
        self.verifying_key
            .verify_strict(&virtual_map_signature_message(recomputed), &signature)
            .map_err(|_| ModelStoreError::InvalidSignature)
    }

    pub fn verify_source_map(&self, signed: &SignedModelSourceMap) -> Result<()> {
        let recomputed = signed.map.map_id()?;
        if recomputed != signed.map_id {
            return Err(ModelStoreError::InvalidSourceMap);
        }
        if signed.release_key_id != self.key_id {
            return Err(ModelStoreError::ReleaseKeyMismatch);
        }
        let signature = Signature::from_bytes(&signed.signature);
        self.verifying_key
            .verify_strict(&source_map_signature_message(recomputed), &signature)
            .map_err(|_| ModelStoreError::InvalidSignature)
    }

    /// Verify both release-signed maps, require that the source map covers
    /// exactly the same logical WeightPages as the virtual map, then mint an
    /// opaque request token suitable for verified durable publication.
    pub fn verify_source_read_request(
        &self,
        source_map: &SignedModelSourceMap,
        virtual_map: &SignedVirtualModelMap,
        page_id: WeightPageId,
        source_id: SourceId,
    ) -> Result<VerifiedSourceReadRequest> {
        self.verify_virtual_map(virtual_map)?;
        self.verify_source_map(source_map)?;
        source_map.map.validate_against_virtual_map(&virtual_map.map)?;
        let request = source_map.map.read_request(page_id, source_id)?;
        if request.expected_page.page_id != page_id
            || request.len != request.expected_page.plaintext_len
        {
            return Err(ModelStoreError::InvalidSourceBinding);
        }
        Ok(VerifiedSourceReadRequest::from_verified_maps(
            request,
            source_map.map_id,
            virtual_map.map_id,
            self.key_id,
        ))
    }

    fn new(verifying_key: VerifyingKey) -> Self {
        let key_id = derive_release_key_id(&verifying_key.to_bytes());
        Self { verifying_key, key_id }
    }
}

fn signature_message(manifest_id: ManifestId) -> Vec<u8> {
    let mut out = Vec::with_capacity(RELEASE_SIGNATURE_DOMAIN.len() + 32);
    out.extend_from_slice(RELEASE_SIGNATURE_DOMAIN);
    out.extend_from_slice(&manifest_id.0);
    out
}

fn virtual_map_signature_message(map_id: VirtualMapId) -> Vec<u8> {
    let mut out = Vec::with_capacity(VIRTUAL_MAP_SIGNATURE_DOMAIN.len() + 32);
    out.extend_from_slice(VIRTUAL_MAP_SIGNATURE_DOMAIN);
    out.extend_from_slice(&map_id.0);
    out
}

fn source_map_signature_message(map_id: SourceMapId) -> Vec<u8> {
    let mut out = Vec::with_capacity(SOURCE_MAP_SIGNATURE_DOMAIN.len() + 32);
    out.extend_from_slice(SOURCE_MAP_SIGNATURE_DOMAIN);
    out.extend_from_slice(&map_id.0);
    out
}

#[cfg(test)]
mod tests {
    use crate::{ModelChunk, ModelId, ModelObjectId};

    use super::*;

    fn manifest() -> ModelManifest {
        ModelManifest {
            model_id: ModelId([1u8; 16]),
            release_sequence: 1,
            minimum_runtime: 1,
            format: "gguf".into(),
            architecture: "llama".into(),
            quantization: "Q4_K_M".into(),
            total_plaintext_len: 1,
            whole_model_sha256: [7u8; 32],
            chunks: vec![ModelChunk {
                index: 0,
                object_id: ModelObjectId([2u8; 32]),
                offset: 0,
                plaintext_len: 1,
                sha256: [8u8; 32],
            }],
        }
    }

    #[test]
    fn release_signature_detects_manifest_tampering() {
        let signing = ModelReleaseSigningKey::generate().unwrap();
        let public = signing.public_key();
        let mut signed = signing.sign_manifest(manifest()).unwrap();
        public.verify(&signed).unwrap();
        signed.manifest.release_sequence += 1;
        assert!(public.verify(&signed).is_err());
    }
}
