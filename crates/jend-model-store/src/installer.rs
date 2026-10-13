use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use crate::{ChunkVerifier, ManifestId, ModelManifest, ModelStoreError, Result, WholeModelVerifier};

const IO_BUFFER: usize = 1024 * 1024;

/// Filesystem installer for already-authorized model data.
///
/// Data is first written beneath a manifest-specific staging directory. A chunk
/// is renamed from `.part` to `.chunk` only after its signed-manifest hash and
/// length verify. The assembled model becomes visible under its final filename
/// only after the whole-model digest verifies and the file has been `sync_all`ed.
pub struct AtomicModelInstaller {
    root: PathBuf,
    manifest: ModelManifest,
    manifest_id: ManifestId,
}

impl AtomicModelInstaller {
    pub fn new(root: impl AsRef<Path>, manifest: ModelManifest) -> Result<Self> {
        let manifest_id = manifest.manifest_id()?;
        Ok(Self { root: root.as_ref().to_path_buf(), manifest, manifest_id })
    }

    pub fn prepare(&self) -> Result<()> {
        fs::create_dir_all(self.chunk_dir())?;
        fs::create_dir_all(self.final_dir())?;
        Ok(())
    }

    /// Ingest one complete chunk. Network resume may happen outside this API;
    /// Jend only marks a chunk durable after full signed-manifest verification.
    pub fn ingest_chunk<R: Read>(&self, index: u32, mut input: R) -> Result<()> {
        self.prepare()?;
        let chunk = self.manifest.chunk(index)?;
        let part = self.chunk_part_path(index);
        let complete = self.chunk_complete_path(index);

        let _ = fs::remove_file(&part);
        let mut file = OpenOptions::new().write(true).create_new(true).open(&part)?;
        let mut verifier = ChunkVerifier::new(chunk);
        let mut buffer = vec![0u8; IO_BUFFER];

        let result = (|| -> Result<()> {
            loop {
                let n = input.read(&mut buffer)?;
                if n == 0 { break; }
                verifier.update(&buffer[..n])?;
                file.write_all(&buffer[..n])?;
            }
            verifier.finish()?;
            file.sync_all()?;
            drop(file);
            let _ = fs::remove_file(&complete);
            fs::rename(&part, &complete)?;
            Ok(())
        })();

        if result.is_err() {
            let _ = fs::remove_file(&part);
        }
        result
    }

    pub fn completed_chunks(&self) -> Result<Vec<u32>> {
        let mut complete = Vec::new();
        for chunk in &self.manifest.chunks {
            let path = self.chunk_complete_path(chunk.index);
            if path.is_file() {
                complete.push(chunk.index);
            }
        }
        Ok(complete)
    }

    pub fn finalize(&self) -> Result<PathBuf> {
        self.prepare()?;
        for chunk in &self.manifest.chunks {
            if !self.chunk_complete_path(chunk.index).is_file() {
                return Err(ModelStoreError::InstallationIncomplete);
            }
        }

        let assembled_part = self.assembled_part_path();
        let final_path = self.final_path();
        let _ = fs::remove_file(&assembled_part);
        let mut assembled = OpenOptions::new().write(true).create_new(true).open(&assembled_part)?;
        let mut whole = WholeModelVerifier::new(&self.manifest);
        let mut buffer = vec![0u8; IO_BUFFER];

        let result = (|| -> Result<()> {
            for chunk in &self.manifest.chunks {
                let mut source = File::open(self.chunk_complete_path(chunk.index))?;
                loop {
                    let n = source.read(&mut buffer)?;
                    if n == 0 { break; }
                    whole.update(&buffer[..n])?;
                    assembled.write_all(&buffer[..n])?;
                }
            }
            whole.finish()?;
            assembled.sync_all()?;
            drop(assembled);
            if final_path.exists() {
                fs::remove_file(&final_path)?;
            }
            fs::rename(&assembled_part, &final_path)?;
            Ok(())
        })();

        if result.is_err() {
            let _ = fs::remove_file(&assembled_part);
            return result.map(|_| final_path);
        }

        Ok(final_path)
    }

    pub fn cleanup_staging(&self) -> Result<()> {
        let stage = self.stage_dir();
        if stage.exists() {
            fs::remove_dir_all(stage)?;
        }
        Ok(())
    }

    pub fn final_path(&self) -> PathBuf {
        self.final_dir().join(format!("{}.model", hex(&self.manifest_id.0)))
    }

    fn final_dir(&self) -> PathBuf {
        self.root.join("models").join(hex(&self.manifest.model_id.0))
    }

    fn stage_dir(&self) -> PathBuf {
        self.root.join(".jend-model-staging").join(hex(&self.manifest_id.0))
    }

    fn chunk_dir(&self) -> PathBuf {
        self.stage_dir().join("chunks")
    }

    fn chunk_part_path(&self, index: u32) -> PathBuf {
        self.chunk_dir().join(format!("{index:08}.part"))
    }

    fn chunk_complete_path(&self, index: u32) -> PathBuf {
        self.chunk_dir().join(format!("{index:08}.chunk"))
    }

    fn assembled_part_path(&self) -> PathBuf {
        self.stage_dir().join("assembled.part")
    }
}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    out
}
