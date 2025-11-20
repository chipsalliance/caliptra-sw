// Licensed under the Apache-2.0 license

#![allow(dead_code)]

pub trait JtagAccessibleReg {
    fn byte_offset(&self) -> u32;

    /// Converts the register's byte offset into a word offset for use with DMI.
    fn word_offset(&self) -> u32 {
        const BYTES_PER_WORD: u32 = std::mem::size_of::<u32>() as u32;
        assert_eq!(self.byte_offset() % BYTES_PER_WORD, 0);
        self.byte_offset() / BYTES_PER_WORD
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(u32)]
pub enum CaliptraCoreReg {
    MboxDlen = 0x50,
    MboxDout = 0x51,
    MboxStatus = 0x52,
    BootStatus = 0x53,
    CptraHwErrrorEnc = 0x54,
    CptraFwErrorEnc = 0x55,
    SsUdsSeedBaseAddrL = 0x56,
    SsUdsSeedBaseAddrH = 0x57,
    HwFatalError = 0x58,
    FwFatalError = 0x59,
    HwNonFatalError = 0x5a,
    FwNonFatalError = 0x5b,
    CptraDbgManufServiceReg = 0x60,
    BootfsmGo = 0x61,
    MboxDin = 0x62,
    SsDebugIntent = 0x63,
    SsCaliptraBaseAddrL = 0x64,
    SsCaliptraBaseAddrH = 0x65,
    SsMciBaseAddrL = 0x66,
    SsMciBaseAddrH = 0x67,
    SsRecoveryIfcBaseAddrL = 0x68,
    SsRecoveryIfcBaseAddrH = 0x69,
    SsOtpFcBaseAddrL = 0x6A,
    SsOtpFcBaseAddrH = 0x6B,
    SsStrapGeneric0 = 0x6C,
    SsStrapGeneric1 = 0x6D,
    SsStrapGeneric2 = 0x6E,
    SsStrapGeneric3 = 0x6F,
    SsDbgManufServiceRegReq = 0x70,
    SsDbgManufServiceRegRsp = 0x71,
    SsDbgUnlockLevel0 = 0x72,
    SsDbgUnlockLevel1 = 0x73,
    SsStrapCaliptraDmaAxiUser = 0x74,
    MboxLock = 0x75,
    MboxCmd = 0x76,
    MboxExecute = 0x77,
    SsExternalStagingAreaBaseAddrL = 0x78,
    SsExternalStagingAreaBaseAddrH = 0x79,
}

impl JtagAccessibleReg for CaliptraCoreReg {
    // The offsets above are word offsets.
    fn byte_offset(&self) -> u32 {
        *self as u32 * 4
    }
}
