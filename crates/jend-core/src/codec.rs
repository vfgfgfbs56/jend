use crate::{JendError, Result};

pub(crate) struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.pos)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub(crate) fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(len).ok_or(JendError::Truncated)?;
        if end > self.input.len() {
            return Err(JendError::Truncated);
        }
        let out = &self.input[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        let b: [u8; 2] = self.take(2)?.try_into().map_err(|_| JendError::Truncated)?;
        Ok(u16::from_be_bytes(b))
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        let b: [u8; 4] = self.take(4)?.try_into().map_err(|_| JendError::Truncated)?;
        Ok(u32::from_be_bytes(b))
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        let b: [u8; 8] = self.take(8)?.try_into().map_err(|_| JendError::Truncated)?;
        Ok(u64::from_be_bytes(b))
    }

    pub(crate) fn i64(&mut self) -> Result<i64> {
        let b: [u8; 8] = self.take(8)?.try_into().map_err(|_| JendError::Truncated)?;
        Ok(i64::from_be_bytes(b))
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| JendError::Truncated)
    }
}

pub(crate) fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn put_i64(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_be_bytes());
}
