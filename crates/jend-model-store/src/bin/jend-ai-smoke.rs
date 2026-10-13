#![forbid(unsafe_code)]

#[cfg(not(unix))]
fn main() {
    eprintln!("jend-ai-smoke currently requires Unix-domain sockets");
    std::process::exit(2);
}

#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    unix::run()
}

#[cfg(unix)]
mod unix {
    use std::{fs, io::{Read, Write}, os::unix::net::UnixStream, path::Path};
    use jend_model_store::{AiJobId, ModelId};
    use sha2::{Digest, Sha256};

    const MAGIC: &[u8; 4] = b"JAIX";
    const VERSION: u16 = 1;

    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        let args: Vec<String> = std::env::args().collect();
        if args.len() != 3 {
            return Err("usage: jend-ai-smoke <roundtrip|wrong-auth> <socket>".into());
        }
        let socket = Path::new(&args[2]);
        let auth_path = socket.with_extension("auth");
        let mut auth: [u8; 32] = fs::read(auth_path)?.try_into().map_err(|_| "invalid AI auth length")?;
        if args[1] == "wrong-auth" {
            auth = [0u8; 32];
            let (status, _) = request(socket, &auth, 1, &[])?;
            if status != 3 {
                return Err("wrong AI IPC capability was not rejected".into());
            }
            println!("Jend AI wrong-capability rejection: PASS");
            return Ok(());
        }
        if args[1] != "roundtrip" {
            return Err("unknown smoke command".into());
        }

        let (status, pong) = request(socket, &auth, 1, &[])?;
        if status != 0 || pong != b"pong" {
            return Err("AI IPC ping failed".into());
        }

        let id = AiJobId([7u8; 16]);
        let model = ModelId([9u8; 16]);
        let prompt = b"jend-ai-boundary-smoke-plaintext";
        let mut body = Vec::with_capacity(36 + prompt.len());
        body.extend_from_slice(&id.0);
        body.extend_from_slice(&model.0);
        body.extend_from_slice(&(prompt.len() as u32).to_be_bytes());
        body.extend_from_slice(prompt);
        let (status, digest) = request(socket, &auth, 2, &body)?;
        if status != 0 || digest.len() != 32 {
            return Err("AI executor submit failed".into());
        }
        let expected: [u8; 32] = Sha256::digest(prompt).into();
        if digest.as_slice() != expected {
            return Err("AI executor boundary returned wrong digest".into());
        }

        let mut limits = Vec::new();
        limits.extend_from_slice(&1u16.to_be_bytes());
        limits.extend_from_slice(&1u32.to_be_bytes());
        let (status, _) = request(socket, &auth, 4, &limits)?;
        if status != 0 {
            return Err("AI executor dynamic limit update failed".into());
        }

        println!("Jend AI process/auth/zeroized-input boundary: PASS");
        Ok(())
    }

    fn request(
        socket: &Path,
        auth: &[u8; 32],
        op: u8,
        body: &[u8],
    ) -> Result<(u8, Vec<u8>), Box<dyn std::error::Error>> {
        let mut stream = UnixStream::connect(socket)?;
        let mut header = Vec::with_capacity(43);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&VERSION.to_be_bytes());
        header.extend_from_slice(auth);
        header.push(op);
        header.extend_from_slice(&(body.len() as u32).to_be_bytes());
        stream.write_all(&header)?;
        stream.write_all(body)?;
        stream.flush()?;
        let mut response_header = [0u8; 5];
        stream.read_exact(&mut response_header)?;
        let status = response_header[0];
        let len = u32::from_be_bytes(response_header[1..5].try_into()?) as usize;
        if len > 1024 {
            return Err("AI IPC response exceeds smoke bound".into());
        }
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload)?;
        Ok((status, payload))
    }
}
