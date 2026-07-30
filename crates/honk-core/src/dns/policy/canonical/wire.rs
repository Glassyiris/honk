use super::PolicyError;

pub(super) struct Writer(Vec<u8>);

impl Writer {
    pub(super) fn new() -> Self {
        Self(Vec::new())
    }

    pub(super) fn finish(self) -> Vec<u8> {
        self.0
    }

    pub(super) fn byte(&mut self, value: u8) {
        self.0.push(value);
    }

    pub(super) fn u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    pub(super) fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    pub(super) fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    pub(super) fn len(&mut self, value: usize) -> Result<(), PolicyError> {
        self.u64(u64::try_from(value).map_err(|_| PolicyError::FieldTooLarge)?);
        Ok(())
    }

    pub(super) fn string(&mut self, value: &str) -> Result<(), PolicyError> {
        self.len(value.len())?;
        self.0.extend_from_slice(value.as_bytes());
        Ok(())
    }

    pub(super) fn optional(&mut self, value: Option<&str>) -> Result<(), PolicyError> {
        match value {
            Some(value) => {
                self.byte(1);
                self.string(value)?;
            }
            None => self.byte(0),
        }
        Ok(())
    }
}
