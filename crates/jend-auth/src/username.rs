use crate::{AuthError, Result};

/// Canonical launch username policy. Intentionally ASCII-only to eliminate
/// Unicode confusable/homoglyph ambiguity in account identity.
///
/// Display names can later be Unicode and non-unique; `Username` is the unique
/// security identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Username(String);

impl Username {
    pub const MIN_LEN: usize = 3;
    pub const MAX_LEN: usize = 24;

    pub fn parse(input: &str) -> Result<Self> {
        if input.len() < Self::MIN_LEN || input.len() > Self::MAX_LEN {
            return Err(AuthError::InvalidUsername);
        }
        if input.starts_with('_') || input.ends_with('_') {
            return Err(AuthError::InvalidUsername);
        }

        let mut canonical = String::with_capacity(input.len());
        for byte in input.bytes() {
            let lower = byte.to_ascii_lowercase();
            if !(lower.is_ascii_lowercase() || lower.is_ascii_digit() || lower == b'_') {
                return Err(AuthError::InvalidUsername);
            }
            canonical.push(lower as char);
        }
        Ok(Self(canonical))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_is_case_canonicalized() {
        assert_eq!(Username::parse("Alice_7").unwrap().as_str(), "alice_7");
    }

    #[test]
    fn username_rejects_confusable_unicode() {
        assert!(Username::parse("аlice").is_err()); // leading Cyrillic 'a'
    }
}
