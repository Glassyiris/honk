#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct RuntimeGeneration(u64);

impl RuntimeGeneration {
    pub(crate) const fn new(value: u64) -> Self {
        Self(value)
    }

    pub(crate) const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum RuntimeState {
    Active,
    Draining,
    Closing,
    Closed,
}

impl RuntimeState {
    pub(super) const fn from_raw(value: u8) -> Self {
        match value {
            0 => Self::Active,
            1 => Self::Draining,
            2 => Self::Closing,
            _ => Self::Closed,
        }
    }
}
