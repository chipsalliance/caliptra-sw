// Licensed under the Apache-2.0 license

#[derive(Clone, Copy, Debug)]
#[repr(u32)]
pub enum LcCtrlReg {
    AlertTest = 0x0,
    Status = 0x4,
    ClaimTransitionIfRegwen = 0x8,
    ClaimTransitionIf = 0xC,
    TransitionRegwen = 0x10,
    TransitionCmd = 0x14,
    TransitionCtrl = 0x18,
    TransitionToken0 = 0x1C,
    TransitionToken1 = 0x20,
    TransitionToken2 = 0x24,
    TransitionToken3 = 0x28,
    TransitionTarget = 0x2C,
    OtpVendorTestCtrl = 0x30,
    OtpVendorTestStatus = 0x34,
    LcState = 0x38,
    LcTransitionCnt = 0x3C,
    LcIdState = 0x40,
    HwRevision0 = 0x44,
    HwRevision1 = 0x48,
    DeviceId0 = 0x4C,
    DeviceId1 = 0x50,
    DeviceId2 = 0x54,
    DeviceId3 = 0x58,
    DeviceId4 = 0x5C,
    DeviceId5 = 0x60,
    DeviceId6 = 0x64,
    DeviceId7 = 0x68,
    ManufState0 = 0x6C,
    ManufState1 = 0x70,
    ManufState2 = 0x74,
    ManufState3 = 0x78,
    ManufState4 = 0x7C,
    ManufState5 = 0x80,
    ManufState6 = 0x84,
    ManufState7 = 0x88,
}

impl LcCtrlReg {
    pub fn byte_offset(&self) -> u32 {
        *self as u32
    }

    /// Converts the register's byte offset into a word offset for use with DMI.
    pub fn word_offset(&self) -> u32 {
        const BYTES_PER_WORD: u32 = std::mem::size_of::<u32>() as u32;
        assert_eq!(self.byte_offset() % BYTES_PER_WORD, 0);
        self.byte_offset() / BYTES_PER_WORD
    }
}
