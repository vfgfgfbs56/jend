//! M8.5: strict offline validation of Xet multipart/byteranges bodies.
//! Network fetch execution and WeightVM publication remain fail-closed.

use crate::xet_metadata::ByteSpan;

pub const HARD_MAX_PAYLOAD: u64 = 16 * 1024 * 1024;
pub const HARD_MAX_FRAMING: u64 = 128 * 1024;
pub const HARD_MAX_PARTS: usize = 512;
const MAX_HEADER_BYTES: usize = 8192;

#[derive(Clone, Copy, Debug)]
pub struct MultipartLimits {
    pub max_payload: u64,
    pub max_framing: u64,
}

impl Default for MultipartLimits {
    fn default() -> Self {
        Self { max_payload: HARD_MAX_PAYLOAD, max_framing: HARD_MAX_FRAMING }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum MultipartError {
    InvalidLimits,
    InvalidAuthorization,
    InvalidContentType,
    InvalidPart,
    WrongRange,
    DuplicateRange,
    InconsistentTotal,
    InvalidFraming,
    BudgetExceeded,
}

impl std::fmt::Display for MultipartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "untrusted multipart response rejected: {self:?}")
    }
}
impl std::error::Error for MultipartError {}

#[derive(Debug, PartialEq, Eq)]
pub struct ValidatedPhysicalRange {
    pub span: ByteSpan,
    pub bytes: Vec<u8>,
}

fn length(span: ByteSpan) -> Option<u64> {
    span.end.checked_sub(span.start)?.checked_add(1)
}

fn boundary(value: &str) -> Result<&str, MultipartError> {
    let (kind, parameter) = value.split_once(';').ok_or(MultipartError::InvalidContentType)?;
    if !kind.eq_ignore_ascii_case("multipart/byteranges") {
        return Err(MultipartError::InvalidContentType);
    }
    let parameter = parameter.strip_prefix(' ').unwrap_or(parameter);
    let (key, raw) = parameter.split_once('=').ok_or(MultipartError::InvalidContentType)?;
    if !key.eq_ignore_ascii_case("boundary") {
        return Err(MultipartError::InvalidContentType);
    }
    let name = if raw.starts_with('"') && raw.ends_with('"') {
        raw.strip_prefix('"').and_then(|s| s.strip_suffix('"'))
            .ok_or(MultipartError::InvalidContentType)?
    } else {
        raw
    };
    if name.is_empty() || name.len() > 70 || !name.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(b, b'\'' | b'(' | b')' | b'+' | b'_' | b',' | b'-' | b'.' | b'/' | b':' | b'=' | b'?')
    }) {
        return Err(MultipartError::InvalidContentType);
    }
    Ok(name)
}

fn number(value: &str) -> Result<u64, MultipartError> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(MultipartError::InvalidPart);
    }
    value.parse().map_err(|_| MultipartError::InvalidPart)
}

fn parse_content_range(value: &str) -> Result<(ByteSpan, u64), MultipartError> {
    let (range, total) = value.strip_prefix("bytes ")
        .ok_or(MultipartError::InvalidPart)?
        .split_once('/').ok_or(MultipartError::InvalidPart)?;
    let (start, end) = range.split_once('-').ok_or(MultipartError::InvalidPart)?;
    let span = ByteSpan { start: number(start)?, end: number(end)? };
    let total = number(total)?;
    if length(span).is_none() || total <= span.end {
        return Err(MultipartError::InvalidPart);
    }
    Ok((span, total))
}

fn parse_headers(input: &[u8]) -> Result<(ByteSpan, u64, usize), MultipartError> {
    let mut cursor = 0usize;
    let mut lines = 0;
    let mut range = None;
    let mut declared_length = None;
    let mut content_type_seen = false;
    loop {
        if cursor >= input.len() || cursor >= MAX_HEADER_BYTES {
            return Err(MultipartError::InvalidPart);
        }
        let end = input.len().min(MAX_HEADER_BYTES);
        let rel = input[cursor..end].windows(2)
            .position(|window| window == b"\r\n")
            .ok_or(MultipartError::InvalidPart)?;
        let line = &input[cursor..cursor + rel];
        cursor += rel + 2;
        if line.is_empty() {
            break;
        }
        lines += 1;
        if lines > 3 || !line.iter().all(|b| (b' '..=b'~').contains(b)) {
            return Err(MultipartError::InvalidPart);
        }
        let text = std::str::from_utf8(line).map_err(|_| MultipartError::InvalidPart)?;
        let (key, raw) = text.split_once(':').ok_or(MultipartError::InvalidPart)?;
        let value = raw.strip_prefix(' ').unwrap_or(raw);
        if value.is_empty() || value != value.trim() {
            return Err(MultipartError::InvalidPart);
        }
        if key.eq_ignore_ascii_case("Content-Range") {
            if range.replace(parse_content_range(value)?).is_some() {
                return Err(MultipartError::InvalidPart);
            }
        } else if key.eq_ignore_ascii_case("Content-Length") {
            if declared_length.replace(number(value)?).is_some() {
                return Err(MultipartError::InvalidPart);
            }
        } else if key.eq_ignore_ascii_case("Content-Type") {
            if content_type_seen || !value.eq_ignore_ascii_case("application/octet-stream") {
                return Err(MultipartError::InvalidPart);
            }
            content_type_seen = true;
        } else {
            // Reject unknown encodings, folded headers, and extensions.
            return Err(MultipartError::InvalidPart);
        }
    }
    let (span, total) = range.ok_or(MultipartError::InvalidPart)?;
    if declared_length.is_some_and(|declared| Some(declared) != length(span)) {
        return Err(MultipartError::InvalidPart);
    }
    Ok((span, total, cursor))
}

/// The caller must separately require HTTP 206 and a signed authorization.
/// No bytes are returned unless every part passes. Returned order matches
/// signed ranges, not arbitrary server part order.
pub fn parse_multipart_ranges(
    content_type: &str,
    body: &[u8],
    authorized: &[ByteSpan],
    limits: MultipartLimits,
) -> Result<Vec<ValidatedPhysicalRange>, MultipartError> {
    if limits.max_payload == 0 || limits.max_payload > HARD_MAX_PAYLOAD
        || limits.max_framing == 0 || limits.max_framing > HARD_MAX_FRAMING {
        return Err(MultipartError::InvalidLimits);
    }
    if !(2..=HARD_MAX_PARTS).contains(&authorized.len()) {
        return Err(MultipartError::InvalidAuthorization);
    }
    let mut authorized_bytes = 0u64;
    for (index, &span) in authorized.iter().enumerate() {
        authorized_bytes = authorized_bytes.checked_add(
            length(span).ok_or(MultipartError::InvalidAuthorization)?
        ).ok_or(MultipartError::BudgetExceeded)?;
        if authorized_bytes > limits.max_payload {
            return Err(MultipartError::BudgetExceeded);
        }
        if authorized[..index].iter().any(|earlier| {
            span.start <= earlier.end && earlier.start <= span.end
        }) {
            return Err(MultipartError::InvalidAuthorization);
        }
    }
    let max_body = authorized_bytes.checked_add(limits.max_framing)
        .ok_or(MultipartError::BudgetExceeded)?;
    if u64::try_from(body.len()).map_err(|_| MultipartError::BudgetExceeded)? > max_body {
        return Err(MultipartError::BudgetExceeded);
    }
    let boundary = boundary(content_type)?;
    let opening = format!("--{boundary}\r\n");
    let next_marker = format!("\r\n--{boundary}");
    if !body.starts_with(opening.as_bytes()) {
        return Err(MultipartError::InvalidFraming);
    }
    let mut cursor = opening.len();
    let mut file_length = None;
    let mut collected: Vec<Option<ValidatedPhysicalRange>> =
        std::iter::repeat_with(|| None).take(authorized.len()).collect();

    for index in 0..authorized.len() {
        let (span, total, header_size) =
            parse_headers(body.get(cursor..).ok_or(MultipartError::InvalidFraming)?)?;
        cursor = cursor.checked_add(header_size).ok_or(MultipartError::InvalidFraming)?;
        if file_length.is_some_and(|existing| existing != total) {
            return Err(MultipartError::InconsistentTotal);
        }
        file_length = Some(total);
        let slot = authorized.iter().position(|expected| *expected == span)
            .ok_or(MultipartError::WrongRange)?;
        if collected[slot].is_some() {
            return Err(MultipartError::DuplicateRange);
        }
        let size = usize::try_from(length(span).ok_or(MultipartError::InvalidPart)?)
            .map_err(|_| MultipartError::BudgetExceeded)?;
        let end = cursor.checked_add(size).ok_or(MultipartError::InvalidFraming)?;
        let data = body.get(cursor..end).ok_or(MultipartError::InvalidFraming)?;
        collected[slot] = Some(ValidatedPhysicalRange { span, bytes: data.to_vec() });
        cursor = end;
        if !body.get(cursor..).is_some_and(|tail| tail.starts_with(next_marker.as_bytes())) {
            return Err(MultipartError::InvalidFraming);
        }
        cursor += next_marker.len();
        let tail = body.get(cursor..).ok_or(MultipartError::InvalidFraming)?;
        if index + 1 == authorized.len() {
            if tail != b"--" && tail != b"--\r\n" {
                return Err(MultipartError::InvalidFraming);
            }
        } else if tail.starts_with(b"\r\n") {
            cursor += 2;
        } else {
            return Err(MultipartError::InvalidFraming);
        }
    }
    collected.into_iter()
        .map(|part| part.ok_or(MultipartError::InvalidFraming))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed() -> [ByteSpan; 2] {
        [ByteSpan { start: 0, end: 2 }, ByteSpan { start: 20, end: 22 }]
    }
    fn body(parts: &[(ByteSpan, &[u8])]) -> Vec<u8> {
        let mut result = Vec::new();
        for (span, data) in parts {
            result.extend_from_slice(format!(
                "--JEND\r\nContent-Type: application/octet-stream\r\nContent-Range: bytes {}-{}/100\r\nContent-Length: {}\r\n\r\n",
                span.start, span.end, data.len()
            ).as_bytes());
            result.extend_from_slice(data);
            result.extend_from_slice(b"\r\n");
        }
        result.extend_from_slice(b"--JEND--\r\n");
        result
    }
    fn good() -> Vec<u8> {
        let s = signed();
        body(&[(s[0], b"abc"), (s[1], b"xyz")])
    }
    fn check(data: &[u8]) -> Result<Vec<ValidatedPhysicalRange>, MultipartError> {
        parse_multipart_ranges("multipart/byteranges; boundary=JEND", data, &signed(),
            MultipartLimits { max_payload: 6, max_framing: 512 })
    }

    #[test]
    fn valid_ranges_and_reordering() {
        let got = check(&good()).unwrap();
        assert_eq!(got[0].bytes, b"abc");
        assert_eq!(got[1].bytes, b"xyz");
        let s = signed();
        let reversed = check(&body(&[(s[1], b"xyz"), (s[0], b"abc")])).unwrap();
        assert_eq!(reversed[0].bytes, b"abc");
        assert_eq!(reversed[1].bytes, b"xyz");
        assert!(parse_multipart_ranges(
            "multipart/byteranges; boundary=\"JEND\"", &good(), &signed(),
            MultipartLimits { max_payload: 6, max_framing: 512 }
        ).is_ok());
    }

    #[test]
    fn missing_duplicate_and_extra_ranges_are_rejected() {
        let s = signed();
        assert!(check(&body(&[(s[0], b"abc")])).is_err());
        assert_eq!(check(&body(&[(s[0], b"abc"), (s[0], b"abc")])).err(),
            Some(MultipartError::DuplicateRange));
        assert_eq!(check(&body(&[(s[0], b"abc"), (ByteSpan { start: 30, end: 32 }, b"zzz")])).err(),
            Some(MultipartError::WrongRange));
    }

    #[test]
    fn tampered_headers_lengths_and_trailers_fail_closed() {
        let wrong = body(&[(signed()[0], b"ab"), (signed()[1], b"xyz")]);
        assert!(check(&wrong).is_err());
        let changed = String::from_utf8(good()).unwrap().replacen("/100", "/101", 1);
        assert_eq!(check(changed.as_bytes()).err(), Some(MultipartError::InconsistentTotal));
        let encoding = String::from_utf8(good()).unwrap().replace(
            "Content-Type: application/octet-stream", "Content-Encoding: gzip");
        assert_eq!(check(encoding.as_bytes()).err(), Some(MultipartError::InvalidPart));
        let mut trailing = good();
        trailing.extend_from_slice(b"extra");
        assert_eq!(check(&trailing).err(), Some(MultipartError::InvalidFraming));
    }

    #[test]
    fn bounded_fail_closed_and_binary_body() {
        assert_eq!(parse_multipart_ranges(
            "multipart/byteranges; boundary=JEND", &good(), &signed(),
            MultipartLimits { max_payload: 5, max_framing: 512 }
        ).err(), Some(MultipartError::BudgetExceeded));
        assert_eq!(parse_multipart_ranges(
            "multipart/byteranges; boundary=JEND", &good(), &signed(),
            MultipartLimits { max_payload: 6, max_framing: 5 }
        ).err(), Some(MultipartError::BudgetExceeded));
        assert_eq!(parse_multipart_ranges(
            "multipart/byteranges; boundary=JEND\r\nX: evil", &good(), &signed(),
            MultipartLimits { max_payload: 6, max_framing: 512 }
        ).err(), Some(MultipartError::InvalidContentType));
        let payload = b"A\r\n--JEND\r\nB";
        let first = ByteSpan { start: 0, end: payload.len() as u64 - 1 };
        let second = ByteSpan { start: 30, end: 32 };
        let raw = body(&[(first, payload), (second, b"xyz")]);
        let result = parse_multipart_ranges(
            "multipart/byteranges; boundary=JEND", &raw, &[first, second],
            MultipartLimits { max_payload: 64, max_framing: 512 }
        ).unwrap();
        assert_eq!(result[0].bytes, payload);
    }

    #[test]
    fn overlapped_authorization_is_rejected() {
        let spans = [ByteSpan { start: 0, end: 10 }, ByteSpan { start: 10, end: 15 }];
        assert_eq!(parse_multipart_ranges(
            "multipart/byteranges; boundary=JEND", &good(), &spans,
            MultipartLimits::default()
        ).err(), Some(MultipartError::InvalidAuthorization));
    }
}
