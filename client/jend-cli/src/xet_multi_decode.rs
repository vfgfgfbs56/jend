//! M8.5.11: bounded xorb decode boundary for strictly validated multipart parts.
//!
//! Physical parts remain untrusted until a separate signed Jend WeightPage
//! hash and exact-length gate accepts an assembled logical slice. No publish.

use crate::xet_multi_fetch_transport::UntrustedXorbPhysicalRange;
use crate::xorb_decode::{decode_xorb_single_range, DecodedXorbRange, XorbDecodeError};

const HARD_MAX_PHYSICAL_BYTES: u64 = 16 * 1024 * 1024;
const HARD_MAX_DECODED_BYTES: u64 = 16 * 1024 * 1024;
const HARD_MAX_PARTS: usize = 512;

#[derive(Debug, PartialEq, Eq)]
pub enum MultiDecodeError {
    InvalidLimits,
    InvalidPart,
    PhysicalBudgetExceeded,
    DecodedBudgetExceeded,
    DuplicateChunkCoverage,
    Decode(XorbDecodeError),
}

impl std::fmt::Display for MultiDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bounded untrusted Xet multi-range decode rejected: {self:?}")
    }
}

impl std::error::Error for MultiDecodeError {}

/// Only decoded xorb ranges are returned. They still do not constitute a
/// verified WeightPage and MUST NOT be persisted or admitted to WeightVM.
pub fn decode_untrusted_multipart_ranges(
    parts: Vec<UntrustedXorbPhysicalRange>,
    max_physical_bytes: u64,
    max_decoded_bytes: u64,
) -> Result<Vec<DecodedXorbRange>, MultiDecodeError> {
    if max_physical_bytes == 0 || max_physical_bytes > HARD_MAX_PHYSICAL_BYTES
        || max_decoded_bytes == 0 || max_decoded_bytes > HARD_MAX_DECODED_BYTES
    {
        return Err(MultiDecodeError::InvalidLimits);
    }
    if !(2..=HARD_MAX_PARTS).contains(&parts.len()) {
        return Err(MultiDecodeError::InvalidPart);
    }

    // Validate all descriptors and the aggregate download budget before any
    // decompression. A caller must not bypass the authenticated byte spans.
    let mut total_physical = 0u64;
    let mut coverage = Vec::with_capacity(parts.len());
    for part in &parts {
        if part.xorb_hash.len() != 64
            || !part.xorb_hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || part.chunks.start >= part.chunks.end
            || part.physical_bytes.start > part.physical_bytes.end
        {
            return Err(MultiDecodeError::InvalidPart);
        }
        let declared = part.physical_bytes.end
            .checked_sub(part.physical_bytes.start)
            .and_then(|n| n.checked_add(1))
            .ok_or(MultiDecodeError::InvalidPart)?;
        let actual = u64::try_from(part.bytes.len()).map_err(|_| MultiDecodeError::InvalidPart)?;
        if declared != actual {
            return Err(MultiDecodeError::InvalidPart);
        }
        total_physical = total_physical.checked_add(actual)
            .ok_or(MultiDecodeError::PhysicalBudgetExceeded)?;
        if total_physical > max_physical_bytes {
            return Err(MultiDecodeError::PhysicalBudgetExceeded);
        }
        coverage.push((&part.xorb_hash, part.chunks));
    }
    coverage.sort_by(|a,b| a.0.cmp(b.0).then(a.1.start.cmp(&b.1.start)));
    for pair in coverage.windows(2) {
        if pair[0].0 == pair[1].0 && pair[1].1.start < pair[0].1.end {
            return Err(MultiDecodeError::DuplicateChunkCoverage);
        }
    }

    let mut decoded = Vec::with_capacity(parts.len());
    let mut total_decoded = 0u64;
    for part in parts {
        let remaining = max_decoded_bytes.checked_sub(total_decoded)
            .ok_or(MultiDecodeError::DecodedBudgetExceeded)?;
        if remaining == 0 {
            return Err(MultiDecodeError::DecodedBudgetExceeded);
        }
        let next = decode_xorb_single_range(
            &part.xorb_hash, &part.bytes, part.chunks.start,
            part.chunks.end, remaining
        ).map_err(MultiDecodeError::Decode)?;
        total_decoded = total_decoded.checked_add(next.stats.decoded_bytes)
            .ok_or(MultiDecodeError::DecodedBudgetExceeded)?;
        if total_decoded > max_decoded_bytes {
            return Err(MultiDecodeError::DecodedBudgetExceeded);
        }
        decoded.push(next);
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xet_metadata::{ByteSpan, ChunkSpan, Reconstruction, ReconstructionTerm};
    use crate::xorb_decode::reconstruct_slice_from_ranges;

    fn record(payload: &[u8]) -> Vec<u8> {
        let length = payload.len();
        let mut out = vec![
            0, length as u8, (length >> 8) as u8, (length >> 16) as u8,
            0, length as u8, (length >> 8) as u8, (length >> 16) as u8
        ];
        out.extend_from_slice(payload);
        out
    }

    fn fixture() -> Vec<UntrustedXorbPhysicalRange> {
        let hash = "a".repeat(64);
        vec![
            UntrustedXorbPhysicalRange {
                xorb_hash: hash.clone(),
                chunks: ChunkSpan { start: 0, end: 1 },
                physical_bytes: ByteSpan { start: 0, end: 10 },
                bytes: record(b"abc"),
            },
            UntrustedXorbPhysicalRange {
                xorb_hash: hash,
                chunks: ChunkSpan { start: 1, end: 2 },
                physical_bytes: ByteSpan { start: 20, end: 30 },
                bytes: record(b"def"),
            },
        ]
    }

    #[test]
    fn multipart_parts_decode_and_assemble_without_page_admission() {
        let parts = fixture();
        let decoded = decode_untrusted_multipart_ranges(parts, 22, 6).unwrap();
        let reconstruction = Reconstruction {
            offset_into_first_range: 0,
            terms: vec![
                ReconstructionTerm { hash: "a".repeat(64), chunks: ChunkSpan { start: 0, end: 1 }, unpacked_length: 3 },
                ReconstructionTerm { hash: "a".repeat(64), chunks: ChunkSpan { start: 1, end: 2 }, unpacked_length: 3 },
            ],
            fetches: Vec::new(),
        };
        let logical = reconstruct_slice_from_ranges(&reconstruction, &decoded, 6, 6).unwrap();
        assert_eq!(logical, b"abcdef");
    }

    #[test]
    fn malformed_and_ambiguous_physical_descriptors_fail_closed() {
        let mut parts = fixture();
        parts[1].physical_bytes.start = 21;
        assert_eq!(
            decode_untrusted_multipart_ranges(parts, 22, 6).err(),
            Some(MultiDecodeError::InvalidPart)
        );
        let mut parts = fixture();
        parts[1].chunks.start = 0;
        assert_eq!(
            decode_untrusted_multipart_ranges(parts, 22, 6).err(),
            Some(MultiDecodeError::DuplicateChunkCoverage)
        );
        let mut parts = fixture();
        parts[1].xorb_hash = "evil.example.com".to_string();
        assert_eq!(
            decode_untrusted_multipart_ranges(parts, 22, 6).err(),
            Some(MultiDecodeError::InvalidPart)
        );
    }

    #[test]
    fn budgets_and_corrupt_chunk_payload_are_rejected() {
        assert_eq!(
            decode_untrusted_multipart_ranges(fixture(), 21, 6).err(),
            Some(MultiDecodeError::PhysicalBudgetExceeded)
        );
        assert!(decode_untrusted_multipart_ranges(fixture(), 22, 5).is_err());
        assert_eq!(
            decode_untrusted_multipart_ranges(fixture(), 0, 6).err(),
            Some(MultiDecodeError::InvalidLimits)
        );
        let mut parts = fixture();
        parts[1].bytes[0] = 7; // unsupported xorb record version
        assert!(matches!(
            decode_untrusted_multipart_ranges(parts, 22, 6).err(),
            Some(MultiDecodeError::Decode(XorbDecodeError::UnsupportedVersion))
        ));
    }
}
