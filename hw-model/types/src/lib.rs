// Licensed under the Apache-2.0 license

// Based on device_lifecycle_e from RTL
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DeviceLifecycle {
    Unprovisioned = 0b00,
    Manufacturing = 0b01,
    Reserved2 = 0b10,
    Production = 0b11,
}
impl TryFrom<u32> for DeviceLifecycle {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0b00 => Ok(Self::Unprovisioned),
            0b01 => Ok(Self::Manufacturing),
            0b10 => Ok(Self::Reserved2),
            0b11 => Ok(Self::Production),
            _ => Err(()),
        }
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SecurityState(u32);
impl From<u32> for SecurityState {
    fn from(value: u32) -> Self {
        Self(value)
    }
}
impl From<SecurityState> for u32 {
    fn from(value: SecurityState) -> Self {
        value.0
    }
}

impl SecurityState {
    pub fn debug_locked(self) -> bool {
        (self.0 & (1 << 2)) != 0
    }
    pub fn set_debug_locked(&mut self, val: bool) -> &mut Self {
        let mask = 1 << 2;
        if val {
            self.0 |= mask;
        } else {
            self.0 &= !mask
        };
        self
    }
    pub fn device_lifecycle(self) -> DeviceLifecycle {
        DeviceLifecycle::try_from(self.0 & 0x3).unwrap()
    }
    pub fn set_device_lifecycle(&mut self, val: DeviceLifecycle) -> &mut Self {
        self.0 |= (val as u32) & 0x3;
        self
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test() {
        let mut ss = *SecurityState::default()
            .set_debug_locked(true)
            .set_device_lifecycle(DeviceLifecycle::Manufacturing);
        assert_eq!(0x5u32, ss.into());
        assert!(ss.debug_locked());
        assert_eq!(ss.device_lifecycle(), DeviceLifecycle::Manufacturing);
        ss.set_debug_locked(false);
        assert_eq!(0x1u32, ss.into());
    }
}
