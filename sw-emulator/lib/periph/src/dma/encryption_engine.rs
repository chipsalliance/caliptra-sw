/*++

Licensed under the Apache-2.0 license.

File Name:

    encryption_engine.rs

Abstract:

    File contains Encryption Engine Implementation

--*/

use caliptra_emu_bus::{BusError, ReadWriteRegister};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvData, RvSize};
use smlang::statemachine;
use std::collections::HashMap;
use tock_registers::interfaces::Readable;
use tock_registers::register_bitfields;

#[cfg(test)]
macro_rules! assert_ctrl_eq {
    ($encryption_engine:ident, $target:expr) => {
        assert_eq!(
            $encryption_engine.read(RvSize::Word, CTRL).unwrap(),
            $target.into()
        );
    };
}

register_bitfields! [
    u32,
    Control [
        EXE OFFSET(0) NUMBITS(1) [
            RUN = 1,
        ],
        DONE OFFSET(1) NUMBITS(1) [
            DONE = 1,
        ],
        CMD OFFSET(2) NUMBITS(4) [
            LOAD_MEK = 1,
            UNLOAD_MEK = 2,
            ZEROIZE = 3,
        ],
        ERR OFFSET(16) NUMBITS(4) [
            NO_ERROR = 0,
            INVALID_COMMAND = 1,
            VENDOR_SPECIFIC_KEY_CACHE_FULL = 4,
            VENDOR_SPECIFIC_MEK_NOT_FOUND = 5,
            VENDOR_SPECIFIC_REDUNDANT_METADATA = 6,
        ],
        RDY OFFSET(31) NUMBITS(1) [
            NOT_READY = 0,
            READY = 1,
        ]
    ],
];

impl TryFrom<u32> for Control::ERR::Value {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, ()> {
        match value {
            0x0 => Ok(Control::ERR::Value::NO_ERROR),
            0x1 => Ok(Control::ERR::Value::INVALID_COMMAND),
            0x4 => Ok(Control::ERR::Value::VENDOR_SPECIFIC_KEY_CACHE_FULL),
            0x5 => Ok(Control::ERR::Value::VENDOR_SPECIFIC_MEK_NOT_FOUND),
            0x6 => Ok(Control::ERR::Value::VENDOR_SPECIFIC_REDUNDANT_METADATA),
            _ => Err(()),
        }
    }
}

impl TryFrom<u32> for Control::CMD::Value {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, ()> {
        match value {
            0x1 => Ok(Control::CMD::Value::LOAD_MEK),
            0x2 => Ok(Control::CMD::Value::UNLOAD_MEK),
            0x3 => Ok(Control::CMD::Value::ZEROIZE),
            _ => Err(()),
        }
    }
}

statemachine! {
    transitions: {
        *Idle + Initialize / initalize_encryption_engine = Initializing,
        Idle + InitFail / handle_fatal_error = Fatal,
        Initializing + InitSuccess = Ready,
        Ready + WriteCommandExecution / handle_execute = Processing,
        Ready + ProcessFail / handle_fatal_error = Fatal,
        Processing + ProcessSuccess / execution_done = WaitClear,
        WaitClear + WriteDone / handle_clear = Clearing,
        WaitClear + ClearFail / handle_fatal_error = Fatal,
        Clearing + ClearSuccess / clear_done = Ready,
    }
}

// Keep small key cache size for test
const KEY_CACHE_SIZE: usize = 8;

type Mek = [u32; 16];
type Metadata = [u32; 5];
type Auxdata = [u32; 8];

#[derive(Debug)]
struct Context {
    key_cache: HashMap<Metadata, (Auxdata, Mek)>,
    mek: Mek,
    metadata: Metadata,
    auxiliary_data: Auxdata,
    ready: bool,
    error: Control::ERR::Value,
    command: u32,
    done: bool,
    execute: bool,
    raise_fatal_error_flag: bool,
}

impl Context {
    fn new() -> Self {
        Self {
            key_cache: HashMap::new(),
            mek: [0; 16],
            metadata: [0; 5],
            auxiliary_data: [0; 8],
            ready: false,
            error: Control::ERR::Value::NO_ERROR,
            command: 0,
            done: false,
            execute: false,
            raise_fatal_error_flag: false,
        }
    }
}

impl StateMachineContext for Context {
    fn initalize_encryption_engine(&mut self) -> Result<(), ()> {
        if self.raise_fatal_error_flag {
            Err(())
        } else {
            self.key_cache.clear();
            self.ready = true;
            Ok(())
        }
    }

    fn handle_fatal_error(&mut self) -> Result<(), ()> {
        self.raise_fatal_error_flag = false;
        self.ready = false;
        Ok(())
    }

    fn handle_execute(&mut self) -> Result<(), ()> {
        if self.raise_fatal_error_flag {
            Err(())
        } else {
            match Control::CMD::Value::try_from(self.command) {
                Ok(Control::CMD::Value::LOAD_MEK) => {
                    if self.key_cache.len() >= KEY_CACHE_SIZE {
                        self.error = Control::ERR::Value::VENDOR_SPECIFIC_KEY_CACHE_FULL;
                    } else if let std::collections::hash_map::Entry::Vacant(e) =
                        self.key_cache.entry(self.metadata)
                    {
                        e.insert((self.auxiliary_data, self.mek));
                    } else {
                        self.error = Control::ERR::Value::VENDOR_SPECIFIC_REDUNDANT_METADATA;
                    }
                }
                Ok(Control::CMD::Value::UNLOAD_MEK) => {
                    match self.key_cache.remove(&self.metadata) {
                        Some(_) => (),
                        None => {
                            self.error = Control::ERR::Value::VENDOR_SPECIFIC_MEK_NOT_FOUND;
                        }
                    }
                }
                Ok(Control::CMD::Value::ZEROIZE) => {
                    self.key_cache.clear();
                }
                _ => {
                    self.error = Control::ERR::Value::INVALID_COMMAND;
                }
            }
            Ok(())
        }
    }

    fn execution_done(&mut self) -> Result<(), ()> {
        self.execute = false;
        self.done = true;
        Ok(())
    }

    fn handle_clear(&mut self) -> Result<(), ()> {
        if self.raise_fatal_error_flag {
            Err(())
        } else {
            self.mek.fill(0);
            self.metadata.fill(0);
            self.auxiliary_data.fill(0);
            Ok(())
        }
    }

    fn clear_done(&mut self) -> Result<(), ()> {
        self.execute = false;
        self.error = Control::ERR::Value::NO_ERROR;
        self.command = 0;
        self.done = false;
        self.execute = false;
        Ok(())
    }
}

/// Encryption Engine register implementation
#[allow(dead_code)]
#[derive(Bus)]
pub struct EncryptionEngine {
    #[register_array(offset = 0x0, item_size = 4, len = 16, read_fn = read_mek, write_fn = write_mek)]
    mek: Mek,

    #[register_array(offset = 0x40, write_fn = write_metadata)]
    metadata: Metadata,

    #[register_array(offset = 0x60, write_fn = write_aux)]
    auxiliary_data: Auxdata,

    #[register(offset = 0x80, write_fn = write_control, read_fn = read_control)]
    control: ReadWriteRegister<u32, Control::Register>,

    state_machine: StateMachine<Context>,
}

impl Default for EncryptionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl EncryptionEngine {
    pub fn new() -> Self {
        let mut encryption_engine = Self {
            mek: Default::default(),
            metadata: Default::default(),
            auxiliary_data: Default::default(),
            control: ReadWriteRegister::new(0),
            state_machine: StateMachine::new(Context::new()),
        };
        encryption_engine.initialize();
        encryption_engine
    }

    #[cfg(test)]
    fn new_init_fail_instance() -> Self {
        let mut encryption_engine = Self {
            mek: Default::default(),
            metadata: Default::default(),
            auxiliary_data: Default::default(),
            control: ReadWriteRegister::new(0),
            state_machine: StateMachine::new(Context::new()),
        };
        encryption_engine.set_fatal_error_flag();
        encryption_engine.initialize();
        encryption_engine
    }

    fn initialize(&mut self) {
        let _ = match self.state_machine.process_event(Events::Initialize) {
            Ok(_) => self.state_machine.process_event(Events::InitSuccess),
            _ => self.state_machine.process_event(Events::InitFail),
        };
    }

    #[cfg(test)]
    fn set_fatal_error_flag(&mut self) {
        self.state_machine.context.raise_fatal_error_flag = true;
    }

    fn write_mek(&mut self, _size: RvSize, index: usize, val: RvData) -> Result<(), BusError> {
        self.state_machine.context.mek[index] = val;
        Ok(())
    }

    fn read_mek(&self, _size: RvSize, _index: usize) -> Result<u32, BusError> {
        Ok(0u32)
    }

    fn write_metadata(&mut self, _size: RvSize, index: usize, val: RvData) -> Result<(), BusError> {
        self.state_machine.context.metadata[index] = val;
        Ok(())
    }

    fn write_aux(&mut self, _size: RvSize, index: usize, val: RvData) -> Result<(), BusError> {
        self.state_machine.context.auxiliary_data[index] = val;
        Ok(())
    }

    fn write_control(&mut self, _size: RvSize, val: u32) -> Result<(), BusError> {
        let ctrl: ReadWriteRegister<u32, Control::Register> = ReadWriteRegister::new(val);

        match self.state_machine.state() {
            States::Ready => {
                if ctrl.reg.is_set(Control::EXE) {
                    self.state_machine.context.command = ctrl.reg.read(Control::CMD);
                    let _ = match self
                        .state_machine
                        .process_event(Events::WriteCommandExecution)
                    {
                        Ok(_) => self.state_machine.process_event(Events::ProcessSuccess),
                        _ => self.state_machine.process_event(Events::ProcessFail),
                    };
                };
            }
            States::WaitClear => {
                if ctrl.reg.is_set(Control::DONE) {
                    let _ = match self.state_machine.process_event(Events::WriteDone) {
                        Ok(_) => self.state_machine.process_event(Events::ClearSuccess),
                        _ => self.state_machine.process_event(Events::ClearFail),
                    };
                };
            }
            _ => (),
        };
        Ok(())
    }

    fn read_control(&self, _size: RvSize) -> Result<u32, BusError> {
        // EXE bit
        let mut value = Control::EXE
            .val(self.state_machine.context.execute as u32)
            .value;

        // DONE bit
        value |= Control::DONE
            .val(self.state_machine.context.done as u32)
            .value;

        // CMD bit
        value |= Control::CMD.val(self.state_machine.context.command).value;

        // ERR bit
        value |= Control::ERR
            .val(self.state_machine.context.error as u32)
            .value;

        // RDY bit
        value |= Control::RDY
            .val(self.state_machine.context.ready as u32)
            .value;

        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_emu_bus::Bus;
    use caliptra_emu_types::RvAddr;

    fn write_test_metadata(encryption_engine: &mut EncryptionEngine) {
        for (i, metadata_block) in TEST_METD.iter().enumerate() {
            encryption_engine
                .write(RvSize::Word, METD + (i as u32) * 4, *metadata_block)
                .unwrap();
        }
    }

    fn write_test_mek_entry(encryption_engine: &mut EncryptionEngine) {
        for (i, mek_block) in TEST_MEK.iter().enumerate() {
            encryption_engine
                .write(RvSize::Word, MEK + (i as u32) * 4, *mek_block)
                .unwrap();
        }
        for (i, aux_block) in TEST_AUX.iter().enumerate() {
            encryption_engine
                .write(RvSize::Word, AUX + (i as u32) * 4, *aux_block)
                .unwrap();
        }
        write_test_metadata(encryption_engine);
    }

    fn execute_command(encryption_engine: &mut EncryptionEngine, command: u32) -> Result<(), ()> {
        let value = encryption_engine.read(RvSize::Word, CTRL).unwrap();

        // Check if the encryption engine is ready
        if value & Control::RDY::READY.value != Control::RDY::READY.value {
            return Err(());
        }

        // Set CMD
        let mut cmd = Control::CMD.val(command).value;

        // Set EXE
        cmd |= Control::EXE::RUN.value;

        // Write to register
        encryption_engine.write(RvSize::Word, CTRL, cmd).unwrap();

        Ok(())
    }

    fn wait_done(encryption_engine: &mut EncryptionEngine) -> Result<(), ()> {
        let mask = (Control::DONE::DONE + Control::RDY::READY).value;
        let mut value = encryption_engine.read(RvSize::Word, CTRL).unwrap();
        while value & mask == Control::RDY::READY.value {
            value = encryption_engine.read(RvSize::Word, CTRL).unwrap();
        }

        if value & Control::RDY::READY.value != Control::RDY::READY.value {
            Err(())
        } else {
            Ok(())
        }
    }

    fn clear(encryption_engine: &mut EncryptionEngine) {
        let mut v = encryption_engine.read(RvSize::Word, CTRL).unwrap();
        v |= Control::DONE::DONE.value;
        encryption_engine.write(RvSize::Word, CTRL, v).unwrap();
    }

    const CTRL: RvAddr = 0x80;
    const MEK: RvAddr = 0x0;
    const METD: RvAddr = 0x40;
    const AUX: RvAddr = 0x60;
    const TEST_MEK: [RvData; 16] = [
        0x2DBF_CFEC,
        0xD3C4_BEA0,
        0xA845_1480,
        0x63F6_6412,
        0xC055_5E3C,
        0x444E_6EF2,
        0xD44F_FCBD,
        0x4F21_0F20,
        0x964B_A9C1,
        0xAD83_D565,
        0x0A80_1129,
        0xD422_85EB,
        0x7BB4_C922,
        0x9CF6_601E,
        0xC5FC_FB60,
        0xC2B9_13E7,
    ];
    const TEST_METD: [RvData; 5] = [
        0xE423_EC96,
        0x223E_9950,
        0x270E_DF29,
        0x7E01_531C,
        0xF670_775B,
    ];
    const TEST_AUX: [RvData; 8] = [
        0x47FC_B1CB,
        0xD4FA_EF14,
        0x534C_B830,
        0x6492_7C79,
        0xA8FD_7B98,
        0x5EA1_49A6,
        0xAC38_3AD9,
        0x738C_4A3F,
    ];

    #[test]
    fn test_encryption_engine_initialization_success() {
        let mut ee = EncryptionEngine::new();

        // Check if encryption engine is ready
        assert_ctrl_eq!(ee, Control::RDY::READY);
    }

    #[test]
    fn test_encryption_engine_read_mek_register_after_write() {
        let mut ee = EncryptionEngine::new();

        // Write (METD, AUX, MEK) into SFRs
        write_test_mek_entry(&mut ee);

        // Check if MEK SFRs are not readable
        let mek = ee.read(RvSize::Word, MEK).unwrap();
        assert_eq!(mek, 0);
    }

    #[test]
    fn test_encryption_engine_load_mek_success() {
        let mut ee = EncryptionEngine::new();

        // Write (METD, AUX, MEK) into SFRs
        write_test_mek_entry(&mut ee);

        // Execute "Load MEK" command
        let result = execute_command(&mut ee, Control::CMD::Value::LOAD_MEK as u32);
        assert_eq!(result, Ok(()));

        // Wait until the execution is done and check CTRL SFR
        wait_done(&mut ee).unwrap();
        assert_ctrl_eq!(
            ee,
            Control::RDY::READY + Control::DONE::DONE + Control::CMD::LOAD_MEK
        );

        // Clear SFRs
        clear(&mut ee);
        assert_ctrl_eq!(ee, Control::RDY::READY);

        // Check if the MEK is loaded
        let entry_count = ee.state_machine.context.key_cache.len();
        assert_eq!(entry_count, 1);
    }

    #[test]
    fn test_encryption_engine_load_mek_fail() {
        let mut ee = EncryptionEngine::new();

        // Write (METD, AUX, MEK) into SFRs
        write_test_mek_entry(&mut ee);

        // Execute "Load MEK" command
        let result = execute_command(&mut ee, Control::CMD::Value::LOAD_MEK as u32);
        assert_eq!(result, Ok(()));

        // Wait until the execution is done and check CTRL SFR
        wait_done(&mut ee).unwrap();
        assert_ctrl_eq!(
            ee,
            Control::RDY::READY + Control::DONE::DONE + Control::CMD::LOAD_MEK
        );

        // Clear SFRs
        clear(&mut ee);
        assert_ctrl_eq!(ee, Control::RDY::READY);

        // Check if the MEK is loaded
        let entry_count = ee.state_machine.context.key_cache.len();
        assert_eq!(entry_count, 1);

        // Reloading the same METD will result into a vendor-specific error in the sw-emulator environment
        // Write (METD, AUX, MEK) into SFRs
        write_test_mek_entry(&mut ee);

        // Execute "Load MEK" command
        let result = execute_command(&mut ee, Control::CMD::Value::LOAD_MEK as u32);
        assert_eq!(result, Ok(()));

        // Wait until the execution is done and check CTRL SFR
        wait_done(&mut ee).unwrap();
        assert_ctrl_eq!(
            ee,
            Control::RDY::READY
                + Control::DONE::DONE
                + Control::CMD::LOAD_MEK
                + Control::ERR::VENDOR_SPECIFIC_REDUNDANT_METADATA
        );

        // Clear SFRs
        clear(&mut ee);
        assert_ctrl_eq!(ee, Control::RDY::READY);

        // Check if the MEK is not loaded
        let entry_count = ee.state_machine.context.key_cache.len();
        assert_eq!(entry_count, 1);
    }

    #[test]
    fn test_encryption_engine_unload_mek_success() {
        let mut ee = EncryptionEngine::new();

        // Write (METD, AUX, MEK) into SFRs
        write_test_mek_entry(&mut ee);

        // Execute "Load MEK" command
        let result = execute_command(&mut ee, Control::CMD::Value::LOAD_MEK as u32);
        assert_eq!(result, Ok(()));

        // Wait until the execution is done and check CTRL SFR
        wait_done(&mut ee).unwrap();
        assert_ctrl_eq!(
            ee,
            Control::RDY::READY + Control::DONE::DONE + Control::CMD::LOAD_MEK
        );

        // Clear SFRs
        clear(&mut ee);
        assert_ctrl_eq!(ee, Control::RDY::READY);

        // Check if the MEK is loaded
        let entry_count = ee.state_machine.context.key_cache.len();
        assert_eq!(entry_count, 1);

        // Write (METD', AUX, MEK) into SFRs
        write_test_mek_entry(&mut ee);
        ee.write(RvSize::Word, METD, 0x0).unwrap(); // This modifies first 4-byte block of METD into 0x0000_0000

        // Execute "Load MEK" command
        let result = execute_command(&mut ee, Control::CMD::Value::LOAD_MEK as u32);
        assert_eq!(result, Ok(()));

        // Wait until the execution is done and check CTRL SFR
        wait_done(&mut ee).unwrap();
        assert_ctrl_eq!(
            ee,
            Control::RDY::READY + Control::DONE::DONE + Control::CMD::LOAD_MEK
        );

        // Clear SFRs
        clear(&mut ee);
        assert_ctrl_eq!(ee, Control::RDY::READY);

        // Check if the MEK is loaded
        let entry_count = ee.state_machine.context.key_cache.len();
        assert_eq!(entry_count, 2);

        // Write (METD) into SFR
        write_test_metadata(&mut ee);

        // Execute "Unload MEK" command
        let result = execute_command(&mut ee, Control::CMD::Value::UNLOAD_MEK as u32);
        assert_eq!(result, Ok(()));

        // Wait until the execution is done and check CTRL SFR
        wait_done(&mut ee).unwrap();
        assert_ctrl_eq!(
            ee,
            Control::RDY::READY + Control::DONE::DONE + Control::CMD::UNLOAD_MEK
        );

        // Clear SFRs
        clear(&mut ee);
        assert_ctrl_eq!(ee, Control::RDY::READY);

        // Check if the appropriate MEK is unloaded
        let entry_count = ee.state_machine.context.key_cache.len();
        let meta = TEST_METD.as_slice();
        assert_eq!(entry_count, 1);
        assert!(!ee.state_machine.context.key_cache.contains_key(meta));
    }

    #[test]
    fn test_encryption_engine_unload_mek_fail() {
        let mut ee = EncryptionEngine::new();

        // Write (METD, AUX, MEK) into SFRs
        write_test_mek_entry(&mut ee);

        // Execute "Load MEK" command
        let result = execute_command(&mut ee, Control::CMD::Value::LOAD_MEK as u32);
        assert_eq!(result, Ok(()));

        // Wait until the execution is done and check CTRL SFR
        wait_done(&mut ee).unwrap();
        assert_ctrl_eq!(
            ee,
            Control::RDY::READY + Control::DONE::DONE + Control::CMD::LOAD_MEK
        );

        // Clear SFRs
        clear(&mut ee);
        assert_ctrl_eq!(ee, Control::RDY::READY);

        // Check if the MEK is loaded
        let entry_count = ee.state_machine.context.key_cache.len();
        assert_eq!(entry_count, 1);

        // Write (METD') into SFR
        write_test_metadata(&mut ee);
        ee.write(RvSize::Word, METD, 0x0).unwrap(); // This modifies first 4-byte block of METD into 0x0000_0000

        // Execute "Unload MEK" command
        let result = execute_command(&mut ee, Control::CMD::Value::UNLOAD_MEK as u32);
        assert_eq!(result, Ok(()));

        // Wait until the execution is done and check CTRL SFR
        wait_done(&mut ee).unwrap();
        assert_ctrl_eq!(
            ee,
            Control::RDY::READY
                + Control::DONE::DONE
                + Control::CMD::UNLOAD_MEK
                + Control::ERR::VENDOR_SPECIFIC_MEK_NOT_FOUND
        );

        // Clear SFRs
        clear(&mut ee);
        assert_ctrl_eq!(ee, Control::RDY::READY);

        // Check if the MEK is not unloaded
        let entry_count = ee.state_machine.context.key_cache.len();
        assert_eq!(entry_count, 1);
    }

    #[test]
    fn test_encryption_engine_zeroize_success() {
        let mut ee = EncryptionEngine::new();

        // Write (METD, AUX, MEK) into SFRs
        write_test_mek_entry(&mut ee);

        // Execute "Load MEK" command
        let result = execute_command(&mut ee, Control::CMD::Value::LOAD_MEK as u32);
        assert_eq!(result, Ok(()));

        // Wait until the execution is done and check CTRL SFR
        wait_done(&mut ee).unwrap();
        assert_ctrl_eq!(
            ee,
            Control::RDY::READY + Control::DONE::DONE + Control::CMD::LOAD_MEK
        );

        // Clear SFRs
        clear(&mut ee);
        assert_ctrl_eq!(ee, Control::RDY::READY);

        // Check if the MEK is loaded
        let entry_count = ee.state_machine.context.key_cache.len();
        assert_eq!(entry_count, 1);

        // Write (METD', AUX, MEK) into SFRs
        write_test_mek_entry(&mut ee);
        ee.write(RvSize::Word, METD, 0x0).unwrap(); // This modifies first 4-byte block of METD into 0x0000_0000

        // Execute "Load MEK" command
        let result = execute_command(&mut ee, Control::CMD::Value::LOAD_MEK as u32);
        assert_eq!(result, Ok(()));

        // Wait until the execution is done and check CTRL SFR
        wait_done(&mut ee).unwrap();
        assert_ctrl_eq!(
            ee,
            Control::RDY::READY + Control::DONE::DONE + Control::CMD::LOAD_MEK
        );

        // Clear SFRs
        clear(&mut ee);
        assert_ctrl_eq!(ee, Control::RDY::READY);

        // Check if the MEK is loaded
        let entry_count = ee.state_machine.context.key_cache.len();
        assert_eq!(entry_count, 2);

        // Execute "Zeroize" command
        let result = execute_command(&mut ee, Control::CMD::Value::ZEROIZE as u32);
        assert_eq!(result, Ok(()));

        // Wait until the execution is done and check CTRL SFR
        wait_done(&mut ee).unwrap();
        assert_ctrl_eq!(
            ee,
            Control::RDY::READY + Control::DONE::DONE + Control::CMD::ZEROIZE
        );

        // Clear SFRs
        clear(&mut ee);
        assert_ctrl_eq!(ee, Control::RDY::READY);

        // Check if the key cache is cleared
        let entry_count = ee.state_machine.context.key_cache.len();
        assert_eq!(entry_count, 0);
    }

    #[test]
    fn test_encryption_engine_key_cache_overflow() {
        let mut ee = EncryptionEngine::new();

        // Fill key cache
        for i in 0..KEY_CACHE_SIZE {
            // Write (METD', AUX, MEK) into SFRs
            write_test_mek_entry(&mut ee);
            ee.write(RvSize::Word, METD, i as u32).unwrap(); // This modifies first 4-byte block of METD into i

            // Execute "Load MEK" command
            let result = execute_command(&mut ee, Control::CMD::Value::LOAD_MEK as u32);
            assert_eq!(result, Ok(()));

            // Wait until the execution is done and check CTRL SFR
            wait_done(&mut ee).unwrap();
            assert_ctrl_eq!(
                ee,
                Control::RDY::READY + Control::DONE::DONE + Control::CMD::LOAD_MEK
            );

            // Clear SFRs
            clear(&mut ee);
            assert_ctrl_eq!(ee, Control::RDY::READY);
        }

        // Check if the key cache is full
        let entry_count = ee.state_machine.context.key_cache.len();
        assert_eq!(entry_count, KEY_CACHE_SIZE);

        // Write (METD, AUX, MEK) into SFRs
        write_test_mek_entry(&mut ee);

        // Execute "Load MEK" command
        let result = execute_command(&mut ee, Control::CMD::Value::LOAD_MEK as u32);
        assert_eq!(result, Ok(()));

        // Wait until the execution is done and check CTRL SFR
        wait_done(&mut ee).unwrap();
        assert_ctrl_eq!(
            ee,
            Control::RDY::READY
                + Control::DONE::DONE
                + Control::CMD::LOAD_MEK
                + Control::ERR::VENDOR_SPECIFIC_KEY_CACHE_FULL
        );

        // Clear SFRs
        clear(&mut ee);
        assert_ctrl_eq!(ee, Control::RDY::READY);

        // Check if the key cache is still full
        let entry_count = ee.state_machine.context.key_cache.len();
        assert_eq!(entry_count, KEY_CACHE_SIZE);
    }

    #[test]
    fn test_encryption_engine_invalid_command() {
        let mut ee = EncryptionEngine::new();

        // Write (METD, AUX, MEK) into SFRs
        write_test_mek_entry(&mut ee);

        // Execute an invalid command
        let result = execute_command(&mut ee, 0xFu32);
        assert_eq!(result, Ok(()));

        // Wait until the execution is done and check CTRL SFR
        wait_done(&mut ee).unwrap();
        assert_ctrl_eq!(
            ee,
            Control::RDY::READY
                + Control::DONE::DONE
                + Control::CMD.val(0xFu32)
                + Control::ERR::INVALID_COMMAND
        );

        // Clear SFRs
        clear(&mut ee);
        assert_ctrl_eq!(ee, Control::RDY::READY);
    }

    #[test]
    fn test_encryption_engine_reuse_without_clear() {
        let mut ee = EncryptionEngine::new();

        // Write (METD, AUX, MEK) into SFRs
        write_test_mek_entry(&mut ee);

        // Execute "Load MEK" command
        let result = execute_command(&mut ee, Control::CMD::Value::LOAD_MEK as u32);
        assert_eq!(result, Ok(()));

        // Wait until the execution is done and check CTRL SFR
        wait_done(&mut ee).unwrap();
        assert_ctrl_eq!(
            ee,
            Control::RDY::READY + Control::DONE::DONE + Control::CMD::LOAD_MEK
        );

        // Check if the MEK is loaded
        let entry_count = ee.state_machine.context.key_cache.len();
        assert_eq!(entry_count, 1);

        // Execute "Zeroize" command
        let result = execute_command(&mut ee, Control::CMD::Value::ZEROIZE as u32);
        assert_eq!(result, Ok(()));

        // Wait until the execution is done and check CTRL SFR
        wait_done(&mut ee).unwrap();

        // Check if zeroization was not effective
        let entry_count = ee.state_machine.context.key_cache.len();
        assert_eq!(entry_count, 1);
    }

    #[test]
    fn test_encryption_engine_initialization_fatal_error() {
        let mut ee = EncryptionEngine::new_init_fail_instance();

        // Check if the RDY bit is unset
        let ready_value = ee.read(RvSize::Word, CTRL).unwrap() & Control::RDY::READY.value;
        assert_eq!(ready_value, Control::RDY::NOT_READY.into());
    }

    #[test]
    fn test_encryption_engine_command_processing_fatal_error() {
        let mut ee = EncryptionEngine::new();

        ee.set_fatal_error_flag();

        // Write (METD, AUX, MEK) into SFRs
        write_test_mek_entry(&mut ee);

        // Execute "Load MEK" command
        let result = execute_command(&mut ee, Control::CMD::Value::LOAD_MEK as u32);
        assert_eq!(result, Ok(()));

        // Wait until the execution is done and check CTRL SFR
        wait_done(&mut ee).unwrap_err();

        // Check if the RDY bit is unset
        let ready_value = ee.read(RvSize::Word, CTRL).unwrap() & Control::RDY::READY.value;
        assert_eq!(ready_value, Control::RDY::NOT_READY.into());
    }

    #[test]
    fn test_encryption_engine_clear_fatal_error() {
        let mut ee = EncryptionEngine::new();

        // Write (METD, AUX, MEK) into SFRs
        write_test_mek_entry(&mut ee);

        // Execute "Load MEK" command
        let result = execute_command(&mut ee, Control::CMD::Value::LOAD_MEK as u32);
        assert_eq!(result, Ok(()));

        // Wait until the execution is done and check CTRL SFR
        wait_done(&mut ee).unwrap();
        assert_ctrl_eq!(
            ee,
            Control::RDY::READY + Control::DONE::DONE + Control::CMD::LOAD_MEK
        );

        ee.set_fatal_error_flag();

        // Clear SFRs
        clear(&mut ee);

        // Check if the RDY bit is unset
        let ready_value = ee.read(RvSize::Word, CTRL).unwrap() & Control::RDY::READY.value;
        assert_eq!(ready_value, Control::RDY::NOT_READY.into());
    }
}
