#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../xet_metadata.rs"]
mod xet_metadata;
#[allow(dead_code)]
#[path = "../xorb_decode.rs"]
mod xorb_decode;

use std::io::Write;
use lz4_flex::frame::FrameEncoder;
use xet_metadata::{ChunkSpan, Reconstruction, ReconstructionTerm};
use xorb_decode::{decode_xorb_single_range, reconstruct_slice_from_single_xorb, reconstruct_slice_from_ranges};

fn le24(value: usize) -> [u8; 3] {
    [value as u8, (value >> 8) as u8, (value >> 16) as u8]
}
fn lz4(data: &[u8]) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut encoder = FrameEncoder::new(Vec::new());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}
fn group4(data: &[u8]) -> Vec<u8> {
    let mut groups = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
    for (index, byte) in data.iter().copied().enumerate() { groups[index % 4].push(byte); }
    groups.into_iter().flatten().collect()
}
fn record(scheme: u8, raw: &[u8]) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
    let compressed = match scheme { 0 => raw.to_vec(), 1 => lz4(raw)?, 2 => lz4(&group4(raw))?, _ => return Err("bad scheme".into()) };
    let mut out = vec![0];
    out.extend(le24(compressed.len())); out.push(scheme); out.extend(le24(raw.len())); out.extend(compressed);
    Ok(out)
}
fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let hash = "a".repeat(64);
    let a = b"none".repeat(1024);
    let b = b"lz4-weights".repeat(2048);
    let c: Vec<u8> = (0..8193).map(|i| ((i * 29) & 255) as u8).collect();
    let mut payload = record(0, &a)?; payload.extend(record(1, &b)?); payload.extend(record(2, &c)?);
    let decoded = decode_xorb_single_range(&hash, &payload, 40, 43, 4 * 1024 * 1024)?;
    if decoded.chunks != vec![a, b, c] { return Err("xorb decode mismatch".into()); }
    let total: u64 = decoded.chunks.iter().map(|v| v.len() as u64).sum();
    let reconstruction = Reconstruction {
        offset_into_first_range: 3,
        terms: vec![ReconstructionTerm { hash, chunks: ChunkSpan { start: 40, end: 43 }, unpacked_length: total }],
        fetches: Vec::new(),
    };
    let slice = reconstruct_slice_from_single_xorb(&reconstruction, &decoded, 5)?;
    if slice != b"enone" { return Err("logical slice mismatch".into()); }
    println!("Jend Xet xorb v0 header parser: PASS");
    println!("Jend Xet None/LZ4/BG4-LZ4 decode: PASS");
    println!("Jend Xet bounded logical reconstruction: PASS");
    let h2 = "b".repeat(64);
    let p2 = record(0, b"second")?;
    let d2 = decode_xorb_single_range(&h2, &p2, 100, 101, 1024)?;
    let multi = Reconstruction {
        offset_into_first_range: 3,
        terms: vec![
            ReconstructionTerm { hash: "a".repeat(64), chunks: ChunkSpan { start: 40, end: 43 }, unpacked_length: total },
            ReconstructionTerm { hash: h2, chunks: ChunkSpan { start: 100, end: 101 }, unpacked_length: 6 },
        ],
        fetches: Vec::new(),
    };
    let joined = reconstruct_slice_from_ranges(&multi, &[d2, decoded], total + 3, total + 3)?;
    // offset_into_first_range=3 removes three bytes from the first term.
    // Requesting total+3 therefore consumes the remaining (total-3) bytes
    // from the first term plus all six bytes of the second term.
    if joined.len() != (total + 3) as usize
        || !joined.starts_with(b"enone")
        || !joined.ends_with(b"second")
    {
        return Err("multi-xorb assembler mismatch".into());
    }
    println!("Jend Xet multi-term multi-xorb logical assembler: PASS");
    Ok(())
}
