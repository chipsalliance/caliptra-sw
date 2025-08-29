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
use caliptra_emu_types::{RvData, RvSize};
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

fn u32_to_u8_le(input: &[u32]) -> Vec<u8> {
    input.iter().flat_map(|n| n.to_le_bytes()).collect()
}

fn u32_to_u8_be(input: &[u32]) -> Vec<u8> {
    input.iter().flat_map(|n| n.to_be_bytes()).collect()
}

fn digest_to_state(input: [u8; 200]) -> [u32; 50] {
    let mut output = [0u32; 50];
    for (i, chunk) in input.chunks(4).enumerate() {
        let mut array = [0u8; 4];
        array.copy_from_slice(chunk);
        output[i] = u32::from_le_bytes(array);
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
const SHA3_MSG_FIFO_SIZE: usize = 2048 / 32;
// TODO: I think this value is wrong.
const SHA3_MSG_FIFO_MAX_DEPTH: usize = 32;

/// SHA3 Peripheral
#[derive(Bus)]
#[poll_fn(poll)]
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
    #[register(offset = 0x0000_001C, write_fn = on_write_alert_test)]
    alert_test: ReadWriteRegister<u32, AlertTest::Register>,

    /// CFG_REGWEN register
    #[register(offset = 0x0000_0020, write_fn = on_write_cfg_regwen)]
    cfg_regwen: ReadOnlyRegister<u32, CfgRegWen::Register>,

    /// CFG_SHADOWED register
    #[register(offset = 0x0000_0024, write_fn = on_write_cfg_shadowed)]
    cfg_shadowed: ReadWriteRegister<u32, CfgShadowed::Register>,

    /// CMD register
    #[register(offset = 0x0000_0028, write_fn = on_write_cmd)]
    cmd: ReadWriteRegister<u32, Cmd::Register>,

    /// STATUS register
    #[register(offset = 0x0000_002C)]
    status: ReadOnlyRegister<u32, Status::Register>,

    /// ERR_CODE memory
    #[register(offset = 0x0000_00D0)]
    err_code: ReadOnlyRegister<u32, ErrCode::Register>,

    /// STATE memory
    #[register_array(offset = 0x0000_0200)]
    state: [u32; SHA3_STATE_MEMORY_SIZE],

    /// MSG_FIFO memory
    #[register_array(offset = 0x0000_0C00, item_size = 4, len = 64, write_fn = on_write_msg_fifo)]
    msg_fifo: [u32; SHA3_MSG_FIFO_SIZE],

    /// SHA3 engine
    sha3: Sha3,

    /// Key Vault
    #[allow(dead_code)]
    key_vault: KeyVault,

    /// Timer
    #[allow(dead_code)]
    timer: Timer,
    // /// Operation complete action
    // op_complete_action: Option<ActionHandle>,

    // /// Key read complete action
    // op_key_read_complete_action: Option<ActionHandle>,

    // /// Block read complete action
    // op_block_read_complete_action: Option<ActionHandle>,

    // /// Tag write complete action
    // op_tag_write_complete_action: Option<ActionHandle>,
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
            cfg_regwen: ReadOnlyRegister::new(0),
            cfg_shadowed: ReadWriteRegister::new(0),
            cmd: ReadWriteRegister::new(0),
            status: ReadOnlyRegister::new(
                (Status::SHA3_IDLE::SET + Status::FIFO_EMPTY::SET).into(),
            ),
            err_code: ReadOnlyRegister::new(0),
            state: [0; SHA3_STATE_MEMORY_SIZE],
            msg_fifo: [0; SHA3_MSG_FIFO_SIZE],
            key_vault,
            timer: Timer::new(clock),
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

    /// On Write callback for `cfg regwen` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    pub fn on_write_cfg_regwen(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        self.cfg_regwen.reg.set(val);

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

        if !self.cfg_regwen.reg.is_set(CfgRegWen::EN) {
            self.status
                .reg
                .modify(Status::ALERT_RECOV_CTRL_UPDATE_ERR::SET);
            Err(BusError::StoreAccessFault)?
        }

        // TODO: Figure out how to implement the "two subsequent writes" feature.
        self.cfg_shadowed.reg.set(val);

        let mode = self.cfg_shadowed.reg.read(CfgShadowed::MODE);
        let strength = self.cfg_shadowed.reg.read(CfgShadowed::KSTRENGTH);
        self.sha3.set_hasher(mode.into(), strength.into());

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

        self.cmd.reg.set(val);

        let cmd: CmdType = self.cmd.reg.read(Cmd::CMD).into();
        match cmd {
            CmdType::Start => {
                if !self.sha3.has_hasher() {
                    Err(BusError::StoreAccessFault)?
                }

                self.status.reg.modify(Status::SHA3_IDLE::CLEAR);
                self.cmd.reg.write(Cmd::CMD.val(CmdType::Process.into()));

                if self.status.reg.read(Status::FIFO_EMPTY) == 0 {
                    let depth = self.status.reg.read(Status::FIFO_DEPTH) as usize;
                    let endianness = self
                        .cfg_shadowed
                        .reg
                        .read(CfgShadowed::STATE_ENDIANNESS)
                        .into();

                    let data = match endianness {
                        Endianness::Little => u32_to_u8_le(&self.msg_fifo[..depth]),
                        Endianness::Big => u32_to_u8_be(&self.msg_fifo[..depth]),
                    };

                    let res = self.sha3.update(&data);
                    if !res {
                        Err(BusError::StoreAccessFault)?
                    }
                    let res = self.sha3.finalize();

                    if !res {
                        Err(BusError::StoreAccessFault)?
                    }

                    self.state = digest_to_state(self.sha3.digest());
                }

                // Finish up.
                self.cmd.reg.write(Cmd::CMD.val(CmdType::Done.into()));
                self.status.reg.modify(Status::SHA3_IDLE::SET);
            }
            _ => Err(BusError::StoreAccessFault)?,
        }

        Ok(())
    }

    /// On Write callback for `msg_fifo` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    fn on_write_msg_fifo(&mut self, size: RvSize, idx: usize, val: RvData) -> Result<(), BusError> {
        // Writes have to be word-aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        if idx >= SHA3_MSG_FIFO_SIZE {
            Err(BusError::StoreAccessFault)?
        }

        let endianness = self
            .cfg_shadowed
            .reg
            .read(CfgShadowed::MSG_ENDIANNESS)
            .into();

        self.msg_fifo[idx] = match endianness {
            Endianness::Little => val.to_le(),
            Endianness::Big => val.to_be(),
        };

        let idle = self.status.reg.read(Status::SHA3_IDLE);
        let mut depth = self.status.reg.read(Status::FIFO_DEPTH);
        let mut full = 0;
        if depth < SHA3_MSG_FIFO_MAX_DEPTH as u32 {
            depth += 1;
        }

        if depth == SHA3_MSG_FIFO_MAX_DEPTH as u32 {
            full = 1;
        }

        self.status.reg.modify(
            Status::FIFO_EMPTY::CLEAR
                + Status::SHA3_IDLE.val(idle)
                + Status::FIFO_FULL.val(full)
                + Status::FIFO_DEPTH.val(depth),
        );

        println!("depth after: {}", self.status.reg.read(Status::FIFO_DEPTH));

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
    const OFFSET_ALERT_TEST: RvAddr = 0x1C;
    const OFFSET_CFG_REGWEN: RvAddr = 0x20;
    const OFFSET_CFG_SHADOWED: RvAddr = 0x24;
    const OFFSET_CMD: RvAddr = 0x28;
    const OFFSET_STATUS: RvAddr = 0x2C;
    const OFFSET_STATE: RvAddr = 0x200;
    const OFFSET_MSG_FIFO: RvAddr = 0xC00;

    fn read_state(sha3: &mut HashSha3) -> [u32; SHA3_STATE_MEMORY_SIZE] {
        let mut output = [0u32; SHA3_STATE_MEMORY_SIZE];
        for (i, element) in output.iter_mut().enumerate() {
            *element = sha3
                .read(RvSize::Word, OFFSET_STATE + (i * 4) as u32)
                .unwrap();
        }

        output
    }

    fn fill_msg_fifo(sha3: &mut HashSha3) {
        let data: u32 = 0xDEADBEEF;
        for i in 0..SHA3_FIFO_MAX_DEPTH {
            sha3.write(RvSize::Word, OFFSET_MSG_FIFO + (i * 4) as u32, data)
                .unwrap();
        }
    }

    fn read_msg_fifo(sha3: &mut HashSha3) -> [u32; SHA3_MSG_FIFO_SIZE] {
        let data: u32 = 0xDEADBEEF;
        for i in 0..SHA3_FIFO_MAX_DEPTH {
            sha3.write(RvSize::Word, OFFSET_MSG_FIFO + (i * 4) as u32, data)
                .unwrap();
        }
    }

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
    fn test_alert_test() {
        let mut sha3 = HashSha3::new(&Clock::new(), KeyVault::new());
        assert_eq!(
            sha3.write(
                RvSize::Word,
                OFFSET_ALERT_TEST,
                AlertTest::RECOV_OPERATION_ERR::SET.into()
            )
            .ok(),
            Some(())
        );

        let status = InMemoryRegister::<u32, Status::Register>::new(
            sha3.read(RvSize::Word, OFFSET_STATUS).unwrap(),
        );
        assert!(status.is_set(Status::ALERT_RECOV_CTRL_UPDATE_ERR));
    }

    #[test]
    fn test_cfg_shadowed() {
        let mut sha3 = HashSha3::new(&Clock::new(), KeyVault::new());
        sha3.write(RvSize::Word, OFFSET_CFG_REGWEN, CfgRegWen::EN::SET.into())
            .unwrap();

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
    fn test_cfg_shadowed_protected() {
        let mut sha3 = HashSha3::new(&Clock::new(), KeyVault::new());

        // CFG REGWEN is not set so this fails.
        assert!(sha3
            .write(
                RvSize::Word,
                OFFSET_CFG_SHADOWED,
                (CfgShadowed::KSTRENGTH.val(Sha3Strength::L256.into())
                    + CfgShadowed::MODE.val(Sha3Mode::SHAKE.into()))
                .into(),
            )
            .is_err());
    }

    #[test]
    fn test_msg_fifo() {
        let mut sha3 = HashSha3::new(&Clock::new(), KeyVault::new());

        // Ascii: 'abc'
        let abc: u32 = 0x616263;
        sha3.write(RvSize::Word, OFFSET_MSG_FIFO, abc).unwrap();

        let status = InMemoryRegister::<u32, Status::Register>::new(
            sha3.read(RvSize::Word, OFFSET_STATUS).unwrap(),
        );
        assert!(!status.is_set(Status::FIFO_EMPTY));
        assert_eq!(status.read(Status::FIFO_DEPTH), 1);

        assert_eq!(sha3.read(RvSize::Word, OFFSET_MSG_FIFO).ok(), Some(abc));
        assert_eq!(sha3.read(RvSize::Word, OFFSET_MSG_FIFO + 4).ok(), Some(0x0));

        sha3.write(RvSize::Word, OFFSET_MSG_FIFO + 4, abc).unwrap();

        let status = InMemoryRegister::<u32, Status::Register>::new(
            sha3.read(RvSize::Word, OFFSET_STATUS).unwrap(),
        );
        assert_eq!(status.read(Status::FIFO_DEPTH), 2);

        assert_eq!(sha3.read(RvSize::Word, OFFSET_MSG_FIFO + 4).ok(), Some(abc));
    }

    #[test]
    fn test_msg_fifo_be() {
        let mut sha3 = HashSha3::new(&Clock::new(), KeyVault::new());

        sha3.write(RvSize::Word, OFFSET_CFG_REGWEN, CfgRegWen::EN::SET.into())
            .unwrap();

        // Set config.
        sha3.write(
            RvSize::Word,
            OFFSET_CFG_SHADOWED,
            (CfgShadowed::KSTRENGTH.val(Sha3Strength::L256.into())
                + CfgShadowed::MODE.val(Sha3Mode::SHAKE.into())
                + CfgShadowed::MSG_ENDIANNESS.val(Endianness::Big.into()))
            .into(),
        )
        .unwrap();

        // Ascii: 'abc'
        let abc: u32 = 0x616263;
        sha3.write(RvSize::Word, OFFSET_MSG_FIFO, abc).unwrap();

        let status = InMemoryRegister::<u32, Status::Register>::new(
            sha3.read(RvSize::Word, OFFSET_STATUS).unwrap(),
        );
        assert!(!status.is_set(Status::FIFO_EMPTY));
        assert_eq!(status.read(Status::FIFO_DEPTH), 1);
        assert_eq!(
            sha3.read(RvSize::Word, OFFSET_MSG_FIFO).ok(),
            Some(abc.to_be())
        );
    }

    #[test]
    fn test_digest() {
        let mut sha3 = HashSha3::new(&Clock::new(), KeyVault::new());

        sha3.write(RvSize::Word, OFFSET_CFG_REGWEN, CfgRegWen::EN::SET.into())
            .unwrap();

        // Set config.
        sha3.write(
            RvSize::Word,
            OFFSET_CFG_SHADOWED,
            (CfgShadowed::KSTRENGTH.val(Sha3Strength::L256.into())
                + CfgShadowed::MODE.val(Sha3Mode::SHAKE.into()))
            .into(),
        )
        .unwrap();

        let data: u32 = 0xDEADBEEF;
        sha3.write(RvSize::Word, OFFSET_MSG_FIFO, data).unwrap();

        let status = InMemoryRegister::<u32, Status::Register>::new(
            sha3.read(RvSize::Word, OFFSET_STATUS).unwrap(),
        );

        assert!(status.is_set(Status::SHA3_IDLE));

        sha3.write(RvSize::Word, OFFSET_CMD, CmdType::Start.into())
            .unwrap();

        let cmd = InMemoryRegister::<u32, Cmd::Register>::new(
            sha3.read(RvSize::Word, OFFSET_CMD).unwrap(),
        );

        assert_eq!(cmd.read(Cmd::CMD), CmdType::Done.into());

        let state = read_state(&mut sha3);
        let expected = [
            0xa6ccf75e, 0x7444d41e, 0x738256cc, 0xf875257e, 0x5d569ac5, 0x295baba8, 0x6eb27544,
            0xe5797976, 0x51370c4d, 0x6d3bb40b, 0xaeba485e, 0xc1755648, 0x8b6d6d40, 0x6c6f4557,
            0x6efb0887, 0x568a3d36, 0xff90aea4, 0x14063072, 0x4f87722a, 0xbf2131c6, 0x23da26e5,
            0xf8e064e7, 0xe3494aa5, 0x22e6056f, 0xdf67219f, 0x69a9efb8, 0xa6c68a2f, 0x39688487,
            0xcb827b04, 0x41950055, 0x57511928, 0xaa71c8f3, 0xc67c0e97, 0xe27e6643, 0x3ec1e9ab,
            0x69afc305, 0x353e0db1, 0x8d1b1db0, 0x5cd3202, 0x387c7bb8, 0xdb58e59c, 0x79e41c66,
            0x2d4451c5, 0x8d7eeb0f, 0x5e2b7a9b, 0xade578f8, 0x7031fdc1, 0x43ef0cf, 0x273e6b15,
            0x4f6db8e3,
        ];

        assert_eq!(state, expected);
    }

    #[test]
    fn test_digest_no_cfg() {
        let mut sha3 = HashSha3::new(&Clock::new(), KeyVault::new());

        sha3.write(RvSize::Word, OFFSET_CFG_REGWEN, CfgRegWen::EN::SET.into())
            .unwrap();

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

    #[test]
    fn test_digest_full() {
        let mut sha3 = HashSha3::new(&Clock::new(), KeyVault::new());

        sha3.write(RvSize::Word, OFFSET_CFG_REGWEN, CfgRegWen::EN::SET.into())
            .unwrap();

        // Set config.
        sha3.write(
            RvSize::Word,
            OFFSET_CFG_SHADOWED,
            (CfgShadowed::KSTRENGTH.val(Sha3Strength::L256.into())
                + CfgShadowed::MODE.val(Sha3Mode::SHAKE.into()))
            .into(),
        )
        .unwrap();

        fill_msg_fifo(&mut sha3);

        let status = InMemoryRegister::<u32, Status::Register>::new(
            sha3.read(RvSize::Word, OFFSET_STATUS).unwrap(),
        );

        assert!(status.is_set(Status::SHA3_IDLE));
        assert!(!status.is_set(Status::FIFO_EMPTY));
        println!("fifo_depth: {}", status.read(Status::FIFO_DEPTH));
        assert!(status.is_set(Status::FIFO_FULL));

        sha3.write(RvSize::Word, OFFSET_CMD, CmdType::Start.into())
            .unwrap();

        let cmd = InMemoryRegister::<u32, Cmd::Register>::new(
            sha3.read(RvSize::Word, OFFSET_CMD).unwrap(),
        );

        assert_eq!(cmd.read(Cmd::CMD), CmdType::Done.into());

        let state = read_state(&mut sha3);
        assert!(state.iter().any(|n| *n != 0));
    }
}
