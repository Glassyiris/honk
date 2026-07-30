use super::DecodeError;

const MAX_FIELD_LEN: usize = 1 << 20;

pub(super) struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    pub(super) fn take(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        let (value, remaining) = self
            .remaining
            .split_at_checked(len)
            .ok_or(DecodeError::Corrupt)?;
        self.remaining = remaining;
        Ok(value)
    }

    pub(super) fn byte(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    pub(super) fn u16(&mut self) -> Result<u16, DecodeError> {
        let bytes = <[u8; 2]>::try_from(self.take(2)?).map_err(|_| DecodeError::Corrupt)?;
        Ok(u16::from_be_bytes(bytes))
    }

    pub(super) fn u64(&mut self) -> Result<u64, DecodeError> {
        let bytes = <[u8; 8]>::try_from(self.take(8)?).map_err(|_| DecodeError::Corrupt)?;
        Ok(u64::from_be_bytes(bytes))
    }

    pub(super) fn bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let length = usize::try_from(u32::from_be_bytes(
            <[u8; 4]>::try_from(self.take(4)?).map_err(|_| DecodeError::Corrupt)?,
        ))
        .map_err(|_| DecodeError::Corrupt)?;
        if length > MAX_FIELD_LEN {
            return Err(DecodeError::Corrupt);
        }
        self.take(length)
    }

    pub(super) const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::dns::forwarder::build_dns_query;

    #[test]
    fn v2_encoding_matches_golden_bytes() {
        let query_wire = build_dns_query("example.com", 1);
        let query =
            QueryContext::parse_with_profile(&query_wire, IngressProfile::Internal).expect("query");
        let mut response = query_wire;
        response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        response[6..8].copy_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 192, 0, 2, 1]);
        let key = CacheKey::new(
            &query,
            None,
            RequestScope::Upstream(UpstreamTag::new("default").expect("tag")),
            OperationKind::Resolve,
        );

        let encoded = encode(&key, &response, 0x0102_0304_0506_0708);
        let payload = encoded
            .bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        assert_eq!(
            encoded.suffix,
            "06bd0c8eca602e2c3af0b60abca13d83d19e58c11f887ec14c7109861826ac66"
        );
        assert_eq!(
            payload,
            "48444e53020102030405060708000000300000001d000001000001000000000000076578616d706c6503636f6d00000100010300000000000764656661756c74000000002d000081800001000100000000076578616d706c6503636f6d0000010001c00c000100010000012c0004c0000201"
        );
    }
}
