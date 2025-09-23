// Licensed under the Apache-2.0 license

use caliptra_error::CaliptraError;

use crate::Lifecycle;

#[derive(Debug)]
pub enum HekSeedState {
    Empty,
    Zeroized,
    Corrupted,
    Programmed,
    Unerasable,
}

impl TryFrom<u16> for HekSeedState {
    type Error = CaliptraError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        // Values defined in OCP LOCK spec v1.0
        // Table 15
        match value {
            0x0 => Ok(HekSeedState::Empty),
            0x1 => Ok(HekSeedState::Zeroized),
            0x2 => Ok(HekSeedState::Corrupted),
            0x3 => Ok(HekSeedState::Programmed),
            0x4 => Ok(HekSeedState::Unerasable),
            _ => Err(CaliptraError::DRIVER_OCP_LOCK_COLD_RESET_INVALID_HEK_SEED),
        }
    }
}

impl From<HekSeedState> for u16 {
    fn from(value: HekSeedState) -> Self {
        match value {
            HekSeedState::Empty => 0x0,
            HekSeedState::Zeroized => 0x1,
            HekSeedState::Corrupted => 0x2,
            HekSeedState::Programmed => 0x3,
            HekSeedState::Unerasable => 0x4,
        }
    }
}

impl From<&HekSeedState> for u16 {
    fn from(value: &HekSeedState) -> Self {
        match value {
            HekSeedState::Empty => 0x0,
            HekSeedState::Zeroized => 0x1,
            HekSeedState::Corrupted => 0x2,
            HekSeedState::Programmed => 0x3,
            HekSeedState::Unerasable => 0x4,
        }
    }
}

impl HekSeedState {
    /// Checks if HEK is available based on the HEK seed state and the Caliptra lifecycle state.
    ///
    /// Section 4.6.4.1 of the OCP LOCK v1.0 spec.
    pub fn hek_is_available(&self, lifecycle_state: Lifecycle) -> bool {
        matches!(
            (lifecycle_state, self),
            (Lifecycle::Unprovisioned | Lifecycle::Manufacturing, _)
                | (Lifecycle::Production, Self::Unerasable)
                | (Lifecycle::Production, Self::Programmed)
        )
    }
}
