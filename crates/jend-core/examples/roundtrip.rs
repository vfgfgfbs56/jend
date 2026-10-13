use jend_core::{
    ConversationId, ConversationSeed, DeviceIdentity, InnerMessage, JendRecord, MessageRole,
    RatchetState, SensitiveBytes, ZERO_COMMITMENT,
};

fn main() -> jend_core::Result<()> {
    let device = DeviceIdentity::generate()?;
    let trusted_device = device.public_identity();
    let conversation_id = ConversationId::generate()?;
    let seed = ConversationSeed::generate()?;

    // In the real client these two states live on the encrypt/decrypt side of the Vault API.
    let mut writer = RatchetState::from_seed(&seed)?;
    let mut reader = RatchetState::from_seed(&seed)?;

    let (sequence, message_key) = writer.next_key()?;
    let message = InnerMessage {
        conversation_id,
        sequence,
        epoch: 0,
        local_unix_ms: 1_800_000_000_000,
        previous_commitment: ZERO_COMMITMENT,
        role: MessageRole::User,
        plaintext: SensitiveBytes::from_slice(b"Hello from a local Jend client"),
    };

    let record = JendRecord::seal(&message, &message_key, &device)?;
    let serialized = record.encode()?;

    let parsed = JendRecord::decode_exact(&serialized)?;
    let (expected_sequence, read_key) = reader.next_key()?;
    let opened = parsed.open_checked(
        &read_key,
        &trusted_device,
        expected_sequence,
        ZERO_COMMITMENT,
    )?;

    println!(".jend record size: {} bytes", serialized.len());
    println!(
        "decrypted locally: {}",
        String::from_utf8_lossy(opened.plaintext.as_bytes())
    );

    Ok(())
}
