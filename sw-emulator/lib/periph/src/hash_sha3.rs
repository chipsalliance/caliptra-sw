/*++

Licensed under the Apache-2.0 license.

File Name:

    sha3.rs

Abstract:

    File contains SHA3 peripheral implementation.

--*/

use crate::KeyVault;
use caliptra_emu_bus::{BusError, Clock, ReadOnlyRegister, ReadWriteRegister, Timer};
use caliptra_emu_crypto::Sha3;
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use tock_registers::register_bitfields;

enum CmdType {
    Start = 0x1D,
    Process = 0x2E,
    Run = 0x31,
    Done = 0x16,
}

impl From<CmdType> for u32 {
    fn from(mode: CmdType) -> Self {
        mode as Self
    }
}

impl From<u32> for CmdType {
    fn from(value: u32) -> Self {
        match value {
            0x1D => CmdType::Start,
            0x2E => CmdType::Process,
            0x31 => CmdType::Run,
            0x16 => CmdType::Done,
            _ => panic!("Invalid command type"),
        }
    }
}

enum Endianness {
    Little = 0x0,
    Big = 0x1,
}

impl From<Endianness> for u32 {
    fn from(mode: Endianness) -> Self {
        mode as Self
    }
}

impl From<u32> for Endianness {
    fn from(value: u32) -> Self {
        match value {
            0x0 => Endianness::Little,
            0x1 => Endianness::Big,
            _ => panic!("Invalid endianness"),
        }
    }
}

fn digest_to_state(input: [u8; 200]) -> [u32; 50] {
    let mut output = [0u32; 50];
    for (i, chunk) in input.chunks(4).enumerate() {
        let mut array = [0u8; 4];
        array.copy_from_slice(chunk);
        output[i] = u32::from_be_bytes(array);
    }

    output
}

register_bitfields! [
    u32,

    /// Alert Test Register Fields
    AlertTest [
        RECOV_OPERATION_ERR OFFSET(0) NUMBITS(1) [],
        FATAL_FAULT_ERR OFFSET(1) NUMBITS(1) [],
        RSVD OFFSET(2) NUMBITS(30) [],
    ],

    /// Cfg Write Enable Register Fields
    CfgRegWen [
        EN OFFSET(0) NUMBITS(1) [],
        RSVD OFFSET(1) NUMBITS(31) [],
    ],

    /// Cfg Shadowed Register Fields
    CfgShadowed [
        RSVD1 OFFSET(0) NUMBITS(1) [],
        KSTRENGTH OFFSET(1) NUMBITS(3) [],
        MODE OFFSET(4) NUMBITS(2) [],
        RSVD2 OFFSET(6) NUMBITS(2) [],
        MSG_ENDIANNESS OFFSET(8) NUMBITS(1) [],
        STATE_ENDIANNESS OFFSET(9) NUMBITS(1) [],
        RSVD3 OFFSET(10) NUMBITS(22) [],
    ],

    /// Command Register Fields
    Cmd [
        CMD OFFSET(0) NUMBITS(6) [],
        RSVD1 OFFSET(6) NUMBITS(4) [],
        ERR_PROCESSED OFFSET(10) NUMBITS(1) [],
        RSVD2 OFFSET(11) NUMBITS(21) [],
    ],

    /// Status Register Fields
    Status [
        SHA3_IDLE OFFSET(0) NUMBITS(1) [],
        SHA3_ABSORB OFFSET(1) NUMBITS(1) [],
        SHA3_SQUEEZE OFFSET(2) NUMBITS(1) [],
        RSVD1 OFFSET(3) NUMBITS(5) [],
        FIFO_DEPTH OFFSET(8) NUMBITS(5) [],
        RSVD2 OFFSET(13) NUMBITS(1) [],
        FIFO_EMPTY OFFSET(14) NUMBITS(1) [],
        FIFO_FULL OFFSET(15) NUMBITS(1) [],
        ALERT_FATAL_FAULT OFFSET(16) NUMBITS(1) [],
        ALERT_RECOV_CTRL_UPDATE_ERR OFFSET(17) NUMBITS(1) [],
        RSVD3 OFFSET(18) NUMBITS(14) [],
    ],

    /// Err Code Register Fields
    ErrCode [
        ERR_CODE OFFSET(0) NUMBITS(32) [],
    ],
];

const SHA3_STATE_MEMORY_SIZE: usize = 1600 / 32;

/// SHA3 Peripheral
#[derive(Bus)]
#[warm_reset_fn(warm_reset)]
#[update_reset_fn(update_reset)]
pub struct HashSha3 {
    /// Name 0 register
    #[register(offset = 0x0000_0000)]
    name0: ReadOnlyRegister<u32>,

    /// Name 1 register
    #[register(offset = 0x0000_0004)]
    name1: ReadOnlyRegister<u32>,

    /// Version 0 register
    #[register(offset = 0x0000_0008)]
    version0: ReadOnlyRegister<u32>,

    /// Version 1 register
    #[register(offset = 0x0000_000C)]
    version1: ReadOnlyRegister<u32>,

    /// Alert test register
    #[register(offset = 0x0000_000C, write_fn = on_write_alert_test)]
    alert_test: ReadWriteRegister<u32, AlertTest::Register>,

    /// CFG_REGWEN register
    #[register(offset = 0x0000_0010)]
    cfg_regwen: ReadOnlyRegister<u32, CfgRegWen::Register>,

    /// CFG_SHADOWED register
    #[register(offset = 0x0000_0014, write_fn = on_write_cfg_shadowed)]
    cfg_shadowed: ReadWriteRegister<u32, CfgShadowed::Register>,

    /// CMD register
    #[register(offset = 0x0000_0018, write_fn = on_write_cmd)]
    cmd: ReadWriteRegister<u32, Cmd::Register>,

    /// STATUS register
    #[register(offset = 0x0000_001C)]
    status: ReadOnlyRegister<u32, Status::Register>,

    /// ERR_CODE memory
    #[register(offset = 0x0000_004c)]
    err_code: ReadOnlyRegister<u32, ErrCode::Register>,

    /// STATE memory
    #[register_array(offset = 0x0000_0400)]
    state: [u32; SHA3_STATE_MEMORY_SIZE],

    /// MSG_FIFO memory.
    /// Separate peripheral since it can handle writes at any offset and for bytes or words,
    /// which is not supported by register or register_array.
    #[peripheral(offset = 0x0000_0800, len = 0x100)]
    msg_fifo: MsgFifo,

    /// SHA3 engine
    sha3: Sha3,

    /// Key Vault
    #[allow(dead_code)]
    key_vault: KeyVault,

    /// Timer
    #[allow(dead_code)]
    timer: Timer,
}

struct MsgFifo {
    data: Vec<u8>,
    swap_endianness: bool,
}

impl caliptra_emu_bus::Bus for MsgFifo {
    fn read(&mut self, _size: RvSize, _addr: RvAddr) -> Result<RvData, BusError> {
        Ok(0)
    }

    fn write(&mut self, size: RvSize, _addr: RvAddr, val: RvData) -> Result<(), BusError> {
        match size {
            RvSize::Byte => {
                self.data.push(val as u8);
            }
            RvSize::HalfWord => {
                // TODO: it's not clear what endianness means for halfword writes
                let val = val as u16;
                let val = if self.swap_endianness {
                    val.to_le_bytes()
                } else {
                    val.to_be_bytes()
                };
                self.data.extend_from_slice(&val);
            }
            RvSize::Word => {
                let val = if self.swap_endianness {
                    val.to_le_bytes()
                } else {
                    val.to_be_bytes()
                };
                self.data.extend_from_slice(&val);
            }
            RvSize::Invalid => panic!("Invalid size"),
        }
        Ok(())
    }
}

impl HashSha3 {
    /// NAME0 Register Value
    const NAME0_VAL: RvData = 0x63616d68; // hmac

    /// NAME1 Register Value
    const NAME1_VAL: RvData = 0x33616873; // sha3

    /// VERSION0 Register Value
    const VERSION0_VAL: RvData = 0x30302E31; // 1.0

    /// VERSION1 Register Value
    const VERSION1_VAL: RvData = 0x00000000;

    /// Create a new instance of HMAC-SHA-384 Engine
    ///
    /// # Arguments
    ///
    /// * `clock` - Clock
    /// * `key_vault` - Key Vault
    ///
    /// # Returns
    ///
    /// * `Self` - Instance of HMAC-SHA-384 Engine
    pub fn new(clock: &Clock, key_vault: KeyVault) -> Self {
        Self {
            sha3: Sha3::new(),
            name0: ReadOnlyRegister::new(Self::NAME0_VAL),
            name1: ReadOnlyRegister::new(Self::NAME1_VAL),
            version0: ReadOnlyRegister::new(Self::VERSION0_VAL),
            version1: ReadOnlyRegister::new(Self::VERSION1_VAL),
            alert_test: ReadWriteRegister::new(0),
            cfg_regwen: ReadOnlyRegister::new(1),
            cfg_shadowed: ReadWriteRegister::new(0),
            cmd: ReadWriteRegister::new(0),
            status: ReadOnlyRegister::new(
                (Status::SHA3_IDLE::SET + Status::FIFO_EMPTY::SET).into(),
            ),
            err_code: ReadOnlyRegister::new(0),
            state: [0; SHA3_STATE_MEMORY_SIZE],
            key_vault,
            timer: Timer::new(clock),
            msg_fifo: MsgFifo {
                data: Vec::new(),
                swap_endianness: false,
            },
        }
    }

    /// On Write callback for `alert test` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    pub fn on_write_alert_test(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        self.alert_test.reg.set(val);

        let fatal_fault = self.alert_test.reg.read(AlertTest::FATAL_FAULT_ERR);
        let recov_err = self.alert_test.reg.read(AlertTest::RECOV_OPERATION_ERR);

        self.status.reg.modify(
            Status::ALERT_RECOV_CTRL_UPDATE_ERR.val(recov_err)
                + Status::ALERT_FATAL_FAULT.val(fatal_fault),
        );

        Ok(())
    }

    /// On Write callback for `configuration` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    pub fn on_write_cfg_shadowed(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        // TODO: Figure out how to implement the "two subsequent writes" feature.
        self.cfg_shadowed.reg.set(val);

        let mode = self.cfg_shadowed.reg.read(CfgShadowed::MODE);
        let strength = self.cfg_shadowed.reg.read(CfgShadowed::KSTRENGTH);
        self.sha3.set_hasher(mode.into(), strength.into());

        self.msg_fifo.swap_endianness =
            self.cfg_shadowed.reg.read(CfgShadowed::STATE_ENDIANNESS) == Endianness::Big.into();

        Ok(())
    }

    /// On Write callback for `cmd` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    pub fn on_write_cmd(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        if !self.status.reg.is_set(Status::SHA3_IDLE) {
            Err(BusError::StoreAccessFault)?
        }
        if !self.sha3.has_hasher() {
            Err(BusError::StoreAccessFault)?
        }

        self.cmd.reg.set(val);

        let cmd: CmdType = self.cmd.reg.read(Cmd::CMD).into();
        match cmd {
            CmdType::Start => {
                // change to abosrb state
                self.status.reg.modify(Status::SHA3_ABSORB::SET);
            }
            CmdType::Process => {
                // change to squeeze state
                self.status.reg.modify(Status::SHA3_SQUEEZE::SET);

                let res = self.sha3.update(&self.msg_fifo.data);
                if !res {
                    Err(BusError::StoreAccessFault)?
                }
                let res = self.sha3.finalize();
                self.msg_fifo.data.clear();

                if !res {
                    Err(BusError::StoreAccessFault)?
                }
                self.state = digest_to_state(self.sha3.digest());
            }
            CmdType::Run => todo!(),
            CmdType::Done => {
                self.state.fill(0);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_emu_bus::Bus;
    use caliptra_emu_crypto::{Sha3Mode, Sha3Strength};
    use caliptra_emu_types::RvAddr;
    use tock_registers::registers::InMemoryRegister;

    const OFFSET_NAME0: RvAddr = 0x0;
    const OFFSET_NAME1: RvAddr = 0x4;
    const OFFSET_VERSION0: RvAddr = 0x8;
    const OFFSET_VERSION1: RvAddr = 0xC;
    const OFFSET_CFG_SHADOWED: RvAddr = 0x14;
    const OFFSET_CMD: RvAddr = 0x18;
    const OFFSET_STATUS: RvAddr = 0x1C;
    const OFFSET_MSG_FIFO: RvAddr = 0x800;

    #[ignore] // disabled as the RTL does not seem to have these registers
    #[test]
    fn test_name() {
        let mut sha3 = HashSha3::new(&Clock::new(), KeyVault::new());

        let name0 = sha3.read(RvSize::Word, OFFSET_NAME0).unwrap();
        let name0 = String::from_utf8_lossy(&name0.to_le_bytes()).to_string();
        assert_eq!(name0, "hmac");

        let name1 = sha3.read(RvSize::Word, OFFSET_NAME1).unwrap();
        let name1 = String::from_utf8_lossy(&name1.to_le_bytes()).to_string();
        assert_eq!(name1, "sha3");
    }

    #[ignore] // disabled as the RTL does not seem to have these registers
    #[test]
    fn test_version() {
        let mut sha3 = HashSha3::new(&Clock::new(), KeyVault::new());

        let version0 = sha3.read(RvSize::Word, OFFSET_VERSION0).unwrap();
        let version0 = String::from_utf8_lossy(&version0.to_le_bytes()).to_string();
        assert_eq!(version0, "1.00");

        let version1 = sha3.read(RvSize::Word, OFFSET_VERSION1).unwrap();
        let version1 = String::from_utf8_lossy(&version1.to_le_bytes()).to_string();
        assert_eq!(version1, "\0\0\0\0");
    }

    #[test]
    fn test_status() {
        let mut sha3 = HashSha3::new(&Clock::new(), KeyVault::new());
        let status = InMemoryRegister::<u32, Status::Register>::new(
            sha3.read(RvSize::Word, OFFSET_STATUS).unwrap(),
        );

        assert!(status.is_set(Status::SHA3_IDLE));
        assert!(status.is_set(Status::FIFO_EMPTY));
        assert!(!status.is_set(Status::FIFO_FULL));
        assert_eq!(status.read(Status::FIFO_DEPTH), 0);
    }

    #[test]
    fn test_cfg_shadowed() {
        let mut sha3 = HashSha3::new(&Clock::new(), KeyVault::new());

        sha3.write(
            RvSize::Word,
            OFFSET_CFG_SHADOWED,
            (CfgShadowed::KSTRENGTH.val(Sha3Strength::L256.into())
                + CfgShadowed::MODE.val(Sha3Mode::SHAKE.into()))
            .into(),
        )
        .unwrap();

        let cfg = InMemoryRegister::<u32, CfgShadowed::Register>::new(
            sha3.read(RvSize::Word, OFFSET_CFG_SHADOWED).unwrap(),
        );

        assert_eq!(cfg.read(CfgShadowed::KSTRENGTH), Sha3Strength::L256.into());
        assert_eq!(cfg.read(CfgShadowed::MODE), Sha3Mode::SHAKE.into());
    }

    #[test]
    fn test_digest_no_cfg() {
        let mut sha3 = HashSha3::new(&Clock::new(), KeyVault::new());

        let data: u32 = 0xDEADBEEF;
        sha3.write(RvSize::Word, OFFSET_MSG_FIFO, data).unwrap();

        let status = InMemoryRegister::<u32, Status::Register>::new(
            sha3.read(RvSize::Word, OFFSET_STATUS).unwrap(),
        );

        assert!(status.is_set(Status::SHA3_IDLE));

        // Cmd should fail since cfg is not set.
        assert!(sha3
            .write(RvSize::Word, OFFSET_CMD, CmdType::Start.into())
            .is_err());
    }
}
