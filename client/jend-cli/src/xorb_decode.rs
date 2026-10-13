//! M8.5.5 bounded Xet xorb chunk decoding.
//!
//! Xorb chunk wire format (v0):
//!   version:u8 | compressed_len:u24le | scheme:u8 | uncompressed_len:u24le
//! followed by exactly `compressed_len` bytes.
//!
//! Supported schemes are the current Xet protocol values:
//!   0 None, 1 LZ4 frame, 2 ByteGrouping4 + LZ4 frame.
//!
//! This module is deliberately transport-independent. It accepts only bytes
//! already authorized by validated reconstruction metadata and does not publish
//! anything to WeightVM. Cryptographic WeightPage verification remains a later
//! boundary.

use std::io::{Cursor, Read};

use lz4_flex::frame::FrameDecoder;

use crate::xet_metadata::Reconstruction;

const CHUNK_HEADER_BYTES: usize = 8;
const MAX_RAW_CHUNK_BYTES: usize = 128 * 1024;
const MAX_XORB_CHUNKS: u64 = 8192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XorbCompression {
    None,
    Lz4,
    ByteGrouping4Lz4,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DecodeStats {
    pub raw_chunks: u64,
    pub lz4_chunks: u64,
    pub bg4_lz4_chunks: u64,
    pub decoded_bytes: u64,
}

pub struct DecodedXorbRange {
    pub xorb_hash: String,
    pub chunk_start: u64,
    pub chunks: Vec<Vec<u8>>,
    pub stats: DecodeStats,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum XorbDecodeError {
    InvalidChunkSpan,
    TooManyChunks,
    TruncatedHeader,
    UnsupportedVersion,
    UnsupportedCompression,
    InvalidLength,
    RawLengthMismatch,
    TruncatedPayload,
    TrailingPayload,
    Lz4Decode,
    DecompressedLengthMismatch,
    DecodeBudgetExceeded,
    ReconstructionCoverage,
    ReconstructionLengthMismatch,
    ReconstructionSlice,
    AmbiguousChunkCoverage,
    DuplicateChunkCoverage,
    OutputBudgetExceeded,
    Overflow,
}

impl std::fmt::Display for XorbDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Xet xorb decode rejected: {self:?}")
    }
}

impl std::error::Error for XorbDecodeError {}

fn u24_le(bytes: &[u8]) -> usize {
    usize::from(bytes[0]) | (usize::from(bytes[1]) << 8) | (usize::from(bytes[2]) << 16)
}

fn decode_lz4_frame(payload: &[u8], expected_len: usize) -> Result<Vec<u8>, XorbDecodeError> {
    // A Cursor lets us verify that the LZ4 frame consumed the entire payload;
    // trailing bytes inside a chunk record are not accepted.
    let cursor = Cursor::new(payload);
    let mut decoder = FrameDecoder::new(cursor);
    let mut out = Vec::with_capacity(expected_len);
    let mut scratch = [0u8; 8192];

    loop {
        let read = decoder
            .read(&mut scratch)
            .map_err(|_| XorbDecodeError::Lz4Decode)?;
        if read == 0 {
            break;
        }
        let next = out
            .len()
            .checked_add(read)
            .ok_or(XorbDecodeError::Overflow)?;
        if next > expected_len {
            return Err(XorbDecodeError::DecompressedLengthMismatch);
        }
        out.extend_from_slice(&scratch[..read]);
    }

    let cursor = decoder.into_inner();
    if usize::try_from(cursor.position()).map_err(|_| XorbDecodeError::Overflow)? != payload.len() {
        return Err(XorbDecodeError::TrailingPayload);
    }
    if out.len() != expected_len {
        return Err(XorbDecodeError::DecompressedLengthMismatch);
    }
    Ok(out)
}

fn undo_byte_grouping4(grouped: &[u8]) -> Vec<u8> {
    let n = grouped.len();
    let base = n / 4;
    let remainder = n % 4;
    let mut group_len = [base; 4];
    for len in group_len.iter_mut().take(remainder) {
        *len += 1;
    }
    let offsets = [
        0,
        group_len[0],
        group_len[0] + group_len[1],
        group_len[0] + group_len[1] + group_len[2],
    ];
    let mut out = vec![0u8; n];
    for (index, slot) in out.iter_mut().enumerate() {
        let group = index % 4;
        let in_group = index / 4;
        *slot = grouped[offsets[group] + in_group];
    }
    out
}

pub fn decode_xorb_single_range(
    xorb_hash: &str,
    payload: &[u8],
    chunk_start: u64,
    chunk_end: u64,
    max_decoded_bytes: u64,
) -> Result<DecodedXorbRange, XorbDecodeError> {
    if chunk_start >= chunk_end || max_decoded_bytes == 0 {
        return Err(XorbDecodeError::InvalidChunkSpan);
    }
    let expected_chunks = chunk_end
        .checked_sub(chunk_start)
        .ok_or(XorbDecodeError::Overflow)?;
    if expected_chunks > MAX_XORB_CHUNKS {
        return Err(XorbDecodeError::TooManyChunks);
    }
    let capacity = usize::try_from(expected_chunks).map_err(|_| XorbDecodeError::Overflow)?;
    let mut chunks = Vec::with_capacity(capacity);
    let mut stats = DecodeStats::default();
    let mut cursor = 0usize;

    for _ in 0..expected_chunks {
        let header_end = cursor
            .checked_add(CHUNK_HEADER_BYTES)
            .ok_or(XorbDecodeError::Overflow)?;
        if header_end > payload.len() {
            return Err(XorbDecodeError::TruncatedHeader);
        }
        let header = &payload[cursor..header_end];
        cursor = header_end;
        if header[0] != 0 {
            return Err(XorbDecodeError::UnsupportedVersion);
        }

        let compressed_len = u24_le(&header[1..4]);
        let scheme = match header[4] {
            0 => XorbCompression::None,
            1 => XorbCompression::Lz4,
            2 => XorbCompression::ByteGrouping4Lz4,
            _ => return Err(XorbDecodeError::UnsupportedCompression),
        };
        let uncompressed_len = u24_le(&header[5..8]);
        if compressed_len == 0
            || uncompressed_len == 0
            || uncompressed_len > MAX_RAW_CHUNK_BYTES
        {
            return Err(XorbDecodeError::InvalidLength);
        }
        let payload_end = cursor
            .checked_add(compressed_len)
            .ok_or(XorbDecodeError::Overflow)?;
        if payload_end > payload.len() {
            return Err(XorbDecodeError::TruncatedPayload);
        }
        let compressed = &payload[cursor..payload_end];
        cursor = payload_end;

        let decoded = match scheme {
            XorbCompression::None => {
                if compressed_len != uncompressed_len {
                    return Err(XorbDecodeError::RawLengthMismatch);
                }
                stats.raw_chunks += 1;
                compressed.to_vec()
            }
            XorbCompression::Lz4 => {
                stats.lz4_chunks += 1;
                decode_lz4_frame(compressed, uncompressed_len)?
            }
            XorbCompression::ByteGrouping4Lz4 => {
                stats.bg4_lz4_chunks += 1;
                let grouped = decode_lz4_frame(compressed, uncompressed_len)?;
                undo_byte_grouping4(&grouped)
            }
        };
        if decoded.len() != uncompressed_len {
            return Err(XorbDecodeError::DecompressedLengthMismatch);
        }
        stats.decoded_bytes = stats
            .decoded_bytes
            .checked_add(u64::try_from(decoded.len()).map_err(|_| XorbDecodeError::Overflow)?)
            .ok_or(XorbDecodeError::Overflow)?;
        if stats.decoded_bytes > max_decoded_bytes {
            return Err(XorbDecodeError::DecodeBudgetExceeded);
        }
        chunks.push(decoded);
    }

    if cursor != payload.len() {
        return Err(XorbDecodeError::TrailingPayload);
    }
    Ok(DecodedXorbRange {
        xorb_hash: xorb_hash.to_owned(),
        chunk_start,
        chunks,
        stats,
    })
}

fn decoded_chunk<'a>(
    decoded: &'a DecodedXorbRange,
    absolute_index: u64,
) -> Result<&'a [u8], XorbDecodeError> {
    let relative = absolute_index
        .checked_sub(decoded.chunk_start)
        .ok_or(XorbDecodeError::ReconstructionCoverage)?;
    let index = usize::try_from(relative).map_err(|_| XorbDecodeError::Overflow)?;
    decoded
        .chunks
        .get(index)
        .map(Vec::as_slice)
        .ok_or(XorbDecodeError::ReconstructionCoverage)
}

/// Reconstruct a logical file sub-range when all terms are covered by the one
/// decoded xorb range. M8.5.5's live smoke intentionally exercises a one-byte
/// probe with one xorb; general multi-xorb scheduling remains later work.
pub fn reconstruct_slice_from_single_xorb(
    reconstruction: &Reconstruction,
    decoded: &DecodedXorbRange,
    needed_len: u64,
) -> Result<Vec<u8>, XorbDecodeError> {
    if needed_len == 0 {
        return Err(XorbDecodeError::ReconstructionSlice);
    }
    let wanted = usize::try_from(needed_len).map_err(|_| XorbDecodeError::Overflow)?;
    let mut skip = usize::try_from(reconstruction.offset_into_first_range)
        .map_err(|_| XorbDecodeError::Overflow)?;
    let mut out = Vec::with_capacity(wanted);

    for term in &reconstruction.terms {
        if term.hash != decoded.xorb_hash {
            return Err(XorbDecodeError::ReconstructionCoverage);
        }
        let mut term_len = 0u64;
        for chunk_index in term.chunks.start..term.chunks.end {
            let chunk = decoded_chunk(decoded, chunk_index)?;
            term_len = term_len
                .checked_add(u64::try_from(chunk.len()).map_err(|_| XorbDecodeError::Overflow)?)
                .ok_or(XorbDecodeError::Overflow)?;

            if skip >= chunk.len() {
                skip -= chunk.len();
                continue;
            }
            let source = &chunk[skip..];
            skip = 0;
            let remaining = wanted.saturating_sub(out.len());
            let take = source.len().min(remaining);
            out.extend_from_slice(&source[..take]);
        }
        if term_len != term.unpacked_length {
            return Err(XorbDecodeError::ReconstructionLengthMismatch);
        }
        if out.len() == wanted {
            break;
        }
    }

    if skip != 0 || out.len() != wanted {
        return Err(XorbDecodeError::ReconstructionSlice);
    }
    Ok(out)
}

/// Assemble a bounded logical byte slice from independently decoded physical
/// xorb ranges. This is an in-memory assembler, NOT a network scheduler or a
/// trusted WeightPage publisher. A caller must first validate reconstruction
/// metadata and fetch each authorized physical range independently.
///
/// Each (hash, absolute chunk index) must have exactly one supplied value.
/// Overlapping physical fetches are rejected rather than picking one copy.
/// Every reconstruction term is fully validated, even after the requested
/// output slice has been filled.
pub fn reconstruct_slice_from_ranges(
    reconstruction: &Reconstruction,
    decoded_ranges: &[DecodedXorbRange],
    needed_len: u64,
    max_output_bytes: u64,
) -> Result<Vec<u8>, XorbDecodeError> {
    if needed_len == 0 || reconstruction.terms.is_empty() {
        return Err(XorbDecodeError::ReconstructionSlice);
    }
    if max_output_bytes == 0 || needed_len > max_output_bytes {
        return Err(XorbDecodeError::OutputBudgetExceeded);
    }
    let wanted = usize::try_from(needed_len).map_err(|_| XorbDecodeError::Overflow)?;
    let mut skip = reconstruction.offset_into_first_range;
    let mut out = Vec::with_capacity(wanted);

    // Only decoded ranges actually referenced by the reconstruction are useful.
    // Reject duplicate coverage, including identical payloads, to avoid
    // ambiguity and bypasses when transport fetches are combined.
    let mut seen = std::collections::HashSet::new();
    for range in decoded_ranges {
        for i in 0..range.chunks.len() {
            let index = range.chunk_start.checked_add(
                u64::try_from(i).map_err(|_| XorbDecodeError::Overflow)?
            ).ok_or(XorbDecodeError::Overflow)?;
            if !seen.insert((range.xorb_hash.as_str(), index)) {
                return Err(XorbDecodeError::DuplicateChunkCoverage);
            }
        }
    }

    for term in &reconstruction.terms {
        if term.chunks.start >= term.chunks.end {
            return Err(XorbDecodeError::InvalidChunkSpan);
        }
        let mut term_len = 0u64;
        for index in term.chunks.start..term.chunks.end {
            let mut found = None;
            for range in decoded_ranges {
                if range.xorb_hash == term.hash {
                    if let Some(relative) = index.checked_sub(range.chunk_start) {
                        if let Ok(i) = usize::try_from(relative) {
                            if let Some(chunk) = range.chunks.get(i) {
                                if found.is_some() {
                                    return Err(XorbDecodeError::AmbiguousChunkCoverage);
                                }
                                found = Some(chunk.as_slice());
                            }
                        }
                    }
                }
            }
            let chunk = found.ok_or(XorbDecodeError::ReconstructionCoverage)?;
            let chunk_len = u64::try_from(chunk.len()).map_err(|_| XorbDecodeError::Overflow)?;
            term_len = term_len.checked_add(chunk_len).ok_or(XorbDecodeError::Overflow)?;
            if skip >= chunk_len {
                skip -= chunk_len;
                continue;
            }
            if out.len() < wanted {
                let start = usize::try_from(skip).map_err(|_| XorbDecodeError::Overflow)?;
                let remaining = wanted - out.len();
                let take = (chunk.len() - start).min(remaining);
                out.extend_from_slice(&chunk[start..start + take]);
            }
            skip = 0;
        }
        if term_len != term.unpacked_length {
            return Err(XorbDecodeError::ReconstructionLengthMismatch);
        }
    }
    if skip != 0 || out.len() != wanted {
        return Err(XorbDecodeError::ReconstructionSlice);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    use lz4_flex::frame::FrameEncoder;

    use crate::xet_metadata::{ChunkSpan, Reconstruction, ReconstructionTerm};

    fn le24(value: usize) -> [u8; 3] {
        assert!(value <= 0x00ff_ffff);
        [value as u8, (value >> 8) as u8, (value >> 16) as u8]
    }

    fn lz4(data: &[u8]) -> Vec<u8> {
        let mut encoder = FrameEncoder::new(Vec::new());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn group4(data: &[u8]) -> Vec<u8> {
        let mut groups = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
        for (index, byte) in data.iter().copied().enumerate() {
            groups[index % 4].push(byte);
        }
        groups.into_iter().flatten().collect()
    }

    fn record(scheme: u8, raw: &[u8]) -> Vec<u8> {
        let compressed = match scheme {
            0 => raw.to_vec(),
            1 => lz4(raw),
            2 => lz4(&group4(raw)),
            _ => unreachable!(),
        };
        let mut out = Vec::new();
        out.push(0);
        out.extend_from_slice(&le24(compressed.len()));
        out.push(scheme);
        out.extend_from_slice(&le24(raw.len()));
        out.extend_from_slice(&compressed);
        out
    }

    #[test]
    fn assembles_multiple_hashes_and_ranges_without_trusting_order() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let r1 = decode_xorb_single_range(&a, &record(0, b"abcdefgh"), 10, 11, 128).unwrap();
        let r2 = decode_xorb_single_range(&b, &record(0, b"ijklmnop"), 21, 22, 128).unwrap();
        let reconstruction = Reconstruction {
            offset_into_first_range: 3,
            terms: vec![
                ReconstructionTerm { hash: a.clone(), chunks: ChunkSpan { start: 10, end: 11 }, unpacked_length: 8 },
                ReconstructionTerm { hash: b.clone(), chunks: ChunkSpan { start: 21, end: 22 }, unpacked_length: 8 },
            ],
            fetches: Vec::new(),
        };
        assert_eq!(reconstruct_slice_from_ranges(&reconstruction, &[r2, r1], 10, 64).unwrap(), b"defghijklm");
    }

    #[test]
    fn assembler_rejects_missing_duplicate_budget_and_late_bad_term() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let make_a = || decode_xorb_single_range(&a, &record(0, b"abcdefgh"), 10, 11, 128).unwrap();
        let make_b = || decode_xorb_single_range(&b, &record(0, b"ijklmnop"), 21, 22, 128).unwrap();
        let mut reconstruction = Reconstruction {
            offset_into_first_range: 0,
            terms: vec![
                ReconstructionTerm { hash: a.clone(), chunks: ChunkSpan { start: 10, end: 11 }, unpacked_length: 8 },
                ReconstructionTerm { hash: b.clone(), chunks: ChunkSpan { start: 21, end: 22 }, unpacked_length: 8 },
            ],
            fetches: Vec::new(),
        };
        assert!(matches!(reconstruct_slice_from_ranges(&reconstruction, &[make_a()], 1, 64), Err(XorbDecodeError::ReconstructionCoverage)));
        assert!(matches!(reconstruct_slice_from_ranges(&reconstruction, &[make_a(), make_a(), make_b()], 1, 64), Err(XorbDecodeError::DuplicateChunkCoverage)));
        assert!(matches!(reconstruct_slice_from_ranges(&reconstruction, &[make_a(), make_b()], 65, 64), Err(XorbDecodeError::OutputBudgetExceeded)));
        reconstruction.terms[1].unpacked_length = 9;
        assert!(matches!(reconstruct_slice_from_ranges(&reconstruction, &[make_a(), make_b()], 1, 64), Err(XorbDecodeError::ReconstructionLengthMismatch)));
    }

    #[test]
    fn decodes_all_current_xet_compression_schemes() {
        let a = b"plain chunk".repeat(100);
        let b = b"lz4 chunk with repeated weights".repeat(200);
        let c: Vec<u8> = (0..4097).map(|i| ((i * 17) & 0xff) as u8).collect();
        let mut payload = record(0, &a);
        payload.extend(record(1, &b));
        payload.extend(record(2, &c));
        let decoded = decode_xorb_single_range(&"a".repeat(64), &payload, 7, 10, 1024 * 1024).unwrap();
        assert_eq!(decoded.chunks, vec![a, b, c]);
        assert_eq!(decoded.stats.raw_chunks, 1);
        assert_eq!(decoded.stats.lz4_chunks, 1);
        assert_eq!(decoded.stats.bg4_lz4_chunks, 1);
    }

    fn assert_decode_error(
        result: Result<DecodedXorbRange, XorbDecodeError>,
        expected: XorbDecodeError,
    ) {
        match result {
            Err(actual) => assert_eq!(actual, expected),
            Ok(_) => panic!("expected xorb decode failure"),
        }
    }

    #[test]
    fn malformed_or_amplified_chunks_fail_closed() {
        let mut bad_version = record(0, b"abcd");
        bad_version[0] = 1;
        assert_decode_error(
            decode_xorb_single_range(&"a".repeat(64), &bad_version, 0, 1, 1024),
            XorbDecodeError::UnsupportedVersion,
        );

        let large = vec![7u8; 4096];
        let payload = record(1, &large);
        assert_decode_error(
            decode_xorb_single_range(&"a".repeat(64), &payload, 0, 1, 1024),
            XorbDecodeError::DecodeBudgetExceeded,
        );

        let mut trailing = record(0, b"abcd");
        trailing.push(0);
        assert_decode_error(
            decode_xorb_single_range(&"a".repeat(64), &trailing, 0, 1, 1024),
            XorbDecodeError::TrailingPayload,
        );
    }

    #[test]
    fn reconstructs_only_requested_logical_slice() {
        let hash = "b".repeat(64);
        let c0 = b"01234567".to_vec();
        let c1 = b"abcdefgh".to_vec();
        let mut payload = record(0, &c0);
        payload.extend(record(0, &c1));
        let decoded = decode_xorb_single_range(&hash, &payload, 10, 12, 1024).unwrap();
        let reconstruction = Reconstruction {
            offset_into_first_range: 9,
            terms: vec![ReconstructionTerm {
                hash,
                chunks: ChunkSpan { start: 10, end: 12 },
                unpacked_length: 16,
            }],
            fetches: Vec::new(),
        };
        assert_eq!(
            reconstruct_slice_from_single_xorb(&reconstruction, &decoded, 3).unwrap(),
            b"bcd"
        );
    }
}
