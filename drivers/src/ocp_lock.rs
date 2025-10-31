// Licensed under the Apache-2.0 license

use caliptra_error::CaliptraError;

use crate::{Array4x8, Lifecycle};

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
    pub fn hek_is_available(&self, lifecycle_state: Lifecycle, hek_seed_value: &Array4x8) -> bool {
        let seed_is_empty = *hek_seed_value == Array4x8::default();
        match (self, lifecycle_state, seed_is_empty) {
            // HEK is always available in these life cycle states.
            (_, Lifecycle::Unprovisioned | Lifecycle::Manufacturing, _) => true,
            // Actual seed must not be zeroized when drive declares seed state is programmed.
            (Self::Programmed, Lifecycle::Production, false) => true,
            // HEK is Unerasable so it's okay if the actual seed is zeroized.
            (Self::Unerasable, Lifecycle::Production, _) => true,
            _ => false,
        }
    }
}
