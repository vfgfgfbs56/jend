#![forbid(unsafe_code)]

#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::{
        env,
        path::Path,
        time::{SystemTime, UNIX_EPOCH},
    };

    use jend_core::{ConversationId, MessageRole};
    use jend_vault::VaultIpcClient;

    const SMOKE_TEXT: &[u8] = b"jend-vault-ipc-durability-smoke";

    fn encode_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
        out
    }

    fn decode_nibble(b: u8) -> Result<u8, &'static str> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err("invalid hex"),
        }
    }

    fn decode_hex<const N: usize>(text: &str) -> Result<[u8; N], &'static str> {
        let bytes = text.as_bytes();
        if bytes.len() != N * 2 {
            return Err("invalid hex length");
        }
        let mut out = [0u8; N];
        for i in 0..N {
            out[i] = (decode_nibble(bytes[i * 2])? << 4)
                | decode_nibble(bytes[i * 2 + 1])?;
        }
        Ok(out)
    }

    fn verify_history(
        client: &VaultIpcClient,
        id: ConversationId,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let ids = client.list_conversations()?;
        if !ids.contains(&id) {
            return Err("Vault list lost the smoke conversation".into());
        }
        let history = client.read_history(id)?;
        if history.len() != 1
            || history[0].role != MessageRole::User
            || history[0].sequence != 0
            || history[0].plaintext.as_bytes() != SMOKE_TEXT
        {
            return Err("Vault history did not survive exactly".into());
        }
        Ok(())
    }

    let args: Vec<String> = env::args().collect();
    match args.as_slice() {
        [_, command, socket] if command == "roundtrip" => {
            let client = VaultIpcClient::connect(Path::new(socket), Path::new(socket).with_extension("auth"))?;
            let id = client.create_conversation()?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_millis()
                .try_into()?;
            client.append_message(id, MessageRole::User, now, SMOKE_TEXT)?;
            verify_history(&client, id)?;
            let device = client.device_public_identity()?;
            println!("conversation={}", encode_hex(&id.0));
            println!("device_public={}", encode_hex(&device.as_bytes()));
            Ok(())
        }
        [_, command, socket, conversation_hex, device_hex] if command == "verify" => {
            let client = VaultIpcClient::connect(Path::new(socket), Path::new(socket).with_extension("auth"))?;
            let id = ConversationId(decode_hex::<16>(conversation_hex)?);
            verify_history(&client, id)?;
            let expected = decode_hex::<32>(device_hex)?;
            let actual = client.device_public_identity()?.as_bytes();
            if actual != expected {
                return Err("device signing identity changed across Vault restart".into());
            }
            println!("Jend Vault durable identity/history: PASS");
            Ok(())
        }
        _ => Err(
            "usage: jend-vault-smoke roundtrip <socket> | verify <socket> <conversation-hex> <device-public-hex>"
                .into(),
        ),
    }
}

#[cfg(not(unix))]
fn main() {
    compile_error!("jend-vault-smoke currently supports Unix-domain sockets only");
}
