// Licensed under the Apache-2.0 license

use std::{
    error::Error,
    fmt::Display,
    io::{stdout, ErrorKind, Write},
};

use caliptra_emu_bus::Bus;

pub mod mmio;
mod model_emulated;

#[cfg(feature = "verilator")]
mod model_verilated;
mod output;
mod rv32_builder;

pub use caliptra_hw_model_types::{DeviceLifecycle, Fuses, SecurityState, U4};
pub use mmio::BusMmio;
use output::ExitStatus;
pub use output::Output;

pub use model_emulated::ModelEmulated;

#[cfg(feature = "verilator")]
pub use model_verilated::ModelVerilated;

use caliptra_emu_types::RvSize;

/// Ideally, general-purpose functions would return `impl HwModel` instead of
/// `DefaultHwModel` to prevent users from calling functions that aren't
/// available on all HwModel implementations.  Unfortunately, rust-analyzer
/// (used by IDEs) can't fully resolve associated types from `impl Trait`, so
/// such functions should use `DefaultHwModel` until they fix that. Users should
/// treat `DefaultHwModel` as if it were `impl HwModel`.
#[cfg(not(feature = "verilator"))]
pub type DefaultHwModel = ModelEmulated;

#[cfg(feature = "verilator")]
pub type DefaultHwModel = ModelVerilated;

/// Constructs an HwModel based on the cargo features and environment
/// variables. Most test cases that need to construct a HwModel should use this
/// function over HwModel::new_unbooted().
///
/// The model returned by this function does not have any fuses programmed and
/// is not yet ready to execute code in the microcontroller. Most test cases
/// should use [`new`] instead.
pub fn new_unbooted(params: InitParams) -> Result<DefaultHwModel, Box<dyn Error>> {
    DefaultHwModel::new_unbooted(params)
}

/// Constructs an HwModel based on the cargo features and environment variables,
/// and boot it to the point where CPU execution can occur. This includes
/// programming the fuses, initializing the boot_fsm state machine, and
/// (optionally) uploading firmware. Most test cases that need to construct a
/// HwModel should use this function over [`HwModel::new()`] and
/// [`crate::new_unbooted`].
pub fn new(params: BootParams) -> Result<DefaultHwModel, Box<dyn Error>> {
    DefaultHwModel::new(params)
}

pub struct InitParams<'a> {
    // The contents of the boot ROM
    pub rom: &'a [u8],

    // The initial contents of the DCCM SRAM
    pub dccm: &'a [u8],

    // The initial contents of the ICCM SRAM
    pub iccm: &'a [u8],

    pub log_writer: Box<dyn std::io::Write>,

    pub security_state: SecurityState,
}
impl<'a> Default for InitParams<'a> {
    fn default() -> Self {
        Self {
            rom: Default::default(),
            dccm: Default::default(),
            iccm: Default::default(),
            log_writer: Box::new(stdout()),
            security_state: *SecurityState::default()
                .set_device_lifecycle(DeviceLifecycle::Unprovisioned),
        }
    }
}

#[derive(Default)]
pub struct BootParams<'a> {
    pub init_params: InitParams<'a>,
    pub fuses: Fuses,
    pub fw_image: Option<&'a [u8]>,
}

#[derive(Debug)]
pub enum ModelError {
    MailboxErr,
    NotReadyForFwErr,
    ReadyForFirmwareTimeout { cycles: u32 },
}
impl Error for ModelError {}
impl Display for ModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModelError::MailboxErr => write!(f, "Mailbox error"),
            ModelError::NotReadyForFwErr => write!(f, "Not ready for firmware"),
            ModelError::ReadyForFirmwareTimeout { cycles } => write!(
                f,
                "Ready-for-firmware signal not received after {cycles} cycles"
            ),
        }
    }
}

/// Firmware Load Command Opcode
const FW_LOAD_CMD_OPCODE: u32 = 0x4657_4C44;

// Represents a emulator or simulation of the caliptra hardware, to be called
// from tests. Typically, test cases should use [`crate::new()`] to create a model
// based on the cargo features (and any model-specific environment variables).
pub trait HwModel {
    type TBus<'a>: Bus
    where
        Self: 'a;

    /// Create a model. Most high-level tests should use [`new()`]
    /// instead.
    fn new_unbooted(params: InitParams) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized;

    /// Create a model, and boot it to the point where CPU execution can
    /// occur. This includes programming the fuses, initializing the
    /// boot_fsm state machine, and (optionally) uploading firmware.
    fn new(run_params: BootParams) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized,
    {
        let mut hw: Self = HwModel::new_unbooted(run_params.init_params)?;

        hw.init_fuses(&run_params.fuses);

        hw.soc_ifc().cptra_bootfsm_go().write(|w| w.go(true));

        hw.step();

        if let Some(fw_image) = run_params.fw_image {
            const MAX_WAIT_CYCLES: u32 = 12_000_000;
            let mut cycles = 0;
            while !hw.ready_for_fw() {
                hw.step();
                cycles += 1;
                if cycles > MAX_WAIT_CYCLES {
                    return Err(ModelError::ReadyForFirmwareTimeout { cycles }.into());
                }
            }
            writeln!(
                hw.output().logger(),
                "ready_for_fw high after {cycles} cycles"
            )
            .unwrap();
            hw.upload_firmware(fw_image)?;
        }

        Ok(hw)
    }

    /// The APB bus from the SoC to Caliptra
    ///
    /// WARNING: Reading or writing to this bus may involve the Caliptra
    /// microcontroller executing a few instructions
    fn apb_bus(&mut self) -> Self::TBus<'_>;

    /// Step execution ahead one clock cycle.
    fn step(&mut self);

    /// Any UART-ish output written by the microcontroller will be available here.
    fn output(&mut self) -> &mut Output;

    /// Execute until the result of `predicate` becomes true.
    fn step_until(&mut self, mut predicate: impl FnMut(&mut Self) -> bool) {
        while !predicate(self) {
            self.step();
        }
    }

    /// Returns true if the microcontroller has signalled that it is ready for
    /// firmware to be written to the mailbox. For RTL implementations, this
    /// should come via a caliptra_top wire rather than an APB register.
    fn ready_for_fw(&self) -> bool;

    /// Initializes the fuse values and locks them in until the next reset. This
    /// function can only be called during early boot, shortly after the model
    /// is created with `new_unbooted()`.
    ///
    /// # Panics
    ///
    /// If the cptra_fuse_wr_done has already been written, or the
    /// hardware prevents cptra_fuse_wr_done from being set.
    fn init_fuses(&mut self, fuses: &Fuses) {
        assert!(
            !self.soc_ifc().cptra_fuse_wr_done().read().done(),
            "Fuses are already locked in place (according to cptra_fuse_wr_done)"
        );

        self.soc_ifc().fuse_uds_seed().write(&fuses.uds_seed);
        self.soc_ifc()
            .fuse_field_entropy()
            .write(&fuses.field_entropy);
        self.soc_ifc()
            .fuse_key_manifest_pk_hash()
            .write(&fuses.key_manifest_pk_hash);
        self.soc_ifc()
            .fuse_key_manifest_pk_hash_mask()
            .write(|w| w.mask(fuses.key_manifest_pk_hash_mask.into()));
        self.soc_ifc()
            .fuse_owner_pk_hash()
            .write(&fuses.owner_pk_hash);
        self.soc_ifc()
            .fuse_fmc_key_manifest_svn()
            .write(|_| fuses.fmc_key_manifest_svn);
        self.soc_ifc().fuse_runtime_svn().write(&fuses.runtime_svn);
        self.soc_ifc()
            .fuse_anti_rollback_disable()
            .write(|w| w.dis(fuses.anti_rollback_disable));
        self.soc_ifc()
            .fuse_idevid_cert_attr()
            .write(&fuses.idevid_cert_attr);
        self.soc_ifc()
            .fuse_idevid_manuf_hsm_id()
            .write(&fuses.idevid_manuf_hsm_id);
        self.soc_ifc()
            .fuse_life_cycle()
            .write(|w| w.life_cycle(fuses.life_cycle.into()));

        self.soc_ifc().cptra_fuse_wr_done().write(|w| w.done(true));
        assert!(self.soc_ifc().cptra_fuse_wr_done().read().done());
    }

    fn step_until_exit_success(&mut self) -> std::io::Result<()> {
        self.copy_output_until_exit_success(std::io::Sink::default())
    }

    fn copy_output_until_exit_success(
        &mut self,
        mut w: impl std::io::Write,
    ) -> std::io::Result<()> {
        loop {
            if !self.output().peek().is_empty() {
                w.write_all(self.output().take(usize::MAX).as_bytes())?;
            }
            match self.output().exit_status() {
                Some(ExitStatus::Passed) => return Ok(()),
                Some(ExitStatus::Failed) => {
                    return Err(std::io::Error::new(
                        ErrorKind::Other,
                        "firmware exited with failure",
                    ))
                }
                None => {}
            }
            self.step();
        }
    }

    fn copy_output_until_non_fatal_error(
        &mut self,
        expected_fw_nonfatal_error: u32,
        mut w: impl std::io::Write,
    ) -> std::io::Result<()> {
        loop {
            if self.soc_ifc().cptra_fw_error_non_fatal().read() == expected_fw_nonfatal_error {
                return Ok(());
            }

            if !self.output().peek().is_empty() {
                w.write_all(self.output().take(usize::MAX).as_bytes())?;
            }
            match self.output().exit_status() {
                Some(ExitStatus::Passed) | Some(ExitStatus::Failed) => {
                    return Err(std::io::Error::new(
                        ErrorKind::Other,
                        "firmware exited unexpectedly",
                    ))
                }
                None => {}
            }
            self.step();
        }
    }

    /// Execute until the output contains `expected_output`.
    fn step_until_output(&mut self, expected_output: &str) -> Result<(), Box<dyn Error>> {
        self.step_until(|m| m.output().peek().len() >= expected_output.len());
        if &self.output().peek()[..expected_output.len()] != expected_output {
            return Err(format!(
                "expected output {:?}, was {:?}",
                expected_output,
                self.output().peek()
            )
            .into());
        }
        Ok(())
    }

    /// A register block that can be used to manipulate the soc_ifc peripheral
    /// over the simulated SoC->Caliptra APB bus.
    fn soc_ifc(&mut self) -> caliptra_registers::soc_ifc::RegisterBlock<BusMmio<Self::TBus<'_>>> {
        unsafe {
            caliptra_registers::soc_ifc::RegisterBlock::new_with_mmio(
                0x3003_0000 as *mut u32,
                BusMmio::new(self.apb_bus()),
            )
        }
    }

    /// A register block that can be used to manipulate the mbox peripheral
    /// over the simulated SoC->Caliptra APB bus.
    fn soc_mbox(&mut self) -> caliptra_registers::mbox::RegisterBlock<BusMmio<Self::TBus<'_>>> {
        unsafe {
            caliptra_registers::mbox::RegisterBlock::new_with_mmio(
                0x3002_0000 as *mut u32,
                BusMmio::new(self.apb_bus()),
            )
        }
    }

    fn tracing_hint(&mut self, enable: bool);

    /// Upload firmware to the mailbox.
    fn upload_firmware(&mut self, firmware: &[u8]) -> Result<(), ModelError> {
        if self.soc_mbox().lock().read().lock() {
            return Err(ModelError::MailboxErr);
        }
        if !self.soc_mbox().lock().read().lock() {
            return Err(ModelError::MailboxErr);
        }
        #[cfg(feature = "verilator")]
        if !self.soc_ifc().cptra_flow_status().read().ready_for_fw() {
            return Err(ModelError::NotReadyForFwErr);
        }

        self.soc_mbox().cmd().write(|_| FW_LOAD_CMD_OPCODE);

        self.soc_mbox().dlen().write(|_| firmware.len() as u32);

        let word_size = RvSize::Word as usize;
        let remainder = firmware.len() % word_size;
        let n = firmware.len() - remainder;

        for idx in (0..n).step_by(word_size) {
            let val = u32::from_le_bytes(firmware[idx..idx + word_size].try_into().unwrap());
            self.soc_mbox().datain().write(|_| val);
        }

        // Handle the remainder bytes.
        if remainder > 0 {
            let mut last_word = firmware[n] as u32;
            for idx in 1..remainder {
                last_word |= (firmware[n + idx] as u32) << (idx << 3);
            }
            self.soc_mbox().datain().write(|_| last_word);
        }

        // Set Execute Bit
        self.soc_mbox().execute().write(|w| w.execute(true));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{mmio::Rv32GenMmio, BootParams, HwModel, InitParams};
    use caliptra_emu_bus::Bus;
    use caliptra_emu_types::RvSize;
    use caliptra_registers::soc_ifc;

    use crate as caliptra_hw_model;

    const MBOX_ADDR_BASE: u32 = 0x3002_0000;
    const MBOX_ADDR_LOCK: u32 = MBOX_ADDR_BASE;
    const MBOX_ADDR_CMD: u32 = MBOX_ADDR_BASE + 0x0000_0008;

    fn gen_image_fw_ready() -> Vec<u8> {
        let rv32_gen = Rv32GenMmio::new();
        let soc_ifc =
            unsafe { soc_ifc::RegisterBlock::new_with_mmio(0x3003_0000 as *mut u32, &rv32_gen) };

        soc_ifc.cptra_flow_status().write(|w| w.ready_for_fw(true));
        rv32_gen.build()
    }
    fn gen_image_hi() -> Vec<u8> {
        let rv32_gen = Rv32GenMmio::new();
        let soc_ifc =
            unsafe { soc_ifc::RegisterBlock::new_with_mmio(0x3003_0000 as *mut u32, &rv32_gen) };
        soc_ifc
            .cptra_generic_output_wires()
            .at(0)
            .write(|_| b'h'.into());
        soc_ifc
            .cptra_generic_output_wires()
            .at(0)
            .write(|_| b'i'.into());
        soc_ifc.cptra_generic_output_wires().at(0).write(|_| 0xff);
        rv32_gen.build()
    }

    #[test]
    fn test_apb() {
        let mut model = caliptra_hw_model::new_unbooted(InitParams {
            ..Default::default()
        })
        .unwrap();

        model.soc_ifc().cptra_fuse_wr_done().write(|w| w.done(true));
        model.soc_ifc().cptra_bootfsm_go().write(|w| w.go(true));

        assert_eq!(
            model.apb_bus().read(RvSize::Word, MBOX_ADDR_LOCK).unwrap(),
            0
        );

        assert_eq!(
            model.apb_bus().read(RvSize::Word, MBOX_ADDR_LOCK).unwrap(),
            1
        );

        model
            .apb_bus()
            .write(RvSize::Word, MBOX_ADDR_CMD, 4242)
            .unwrap();
        assert_eq!(
            model.apb_bus().read(RvSize::Word, MBOX_ADDR_CMD).unwrap(),
            4242
        );
    }

    #[test]
    fn test_mbox() {
        // Same as test_apb, but uses higher-level register interface
        let mut model = caliptra_hw_model::new_unbooted(InitParams {
            ..Default::default()
        })
        .unwrap();

        model.soc_ifc().cptra_fuse_wr_done().write(|w| w.done(true));
        model.soc_ifc().cptra_bootfsm_go().write(|w| w.go(true));

        assert!(!model.soc_mbox().lock().read().lock());
        assert!(model.soc_mbox().lock().read().lock());

        model.soc_mbox().cmd().write(|_| 4242);
        assert_eq!(model.soc_mbox().cmd().read(), 4242);
    }

    #[test]
    fn test_execution() {
        let mut model = caliptra_hw_model::new(BootParams {
            init_params: InitParams {
                rom: &gen_image_hi(),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
        model.step_until_output("hi").unwrap();
    }

    #[test]
    fn test_output_failure() {
        let mut model = caliptra_hw_model::new(BootParams {
            init_params: InitParams {
                rom: &gen_image_hi(),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            model.step_until_output("ha").err().unwrap().to_string(),
            "expected output \"ha\", was \"hi\""
        );
    }

    #[test]
    pub fn test_upload_firmware() {
        let firmware: Vec<u8> = [
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
        ]
        .into();

        let mut model = caliptra_hw_model::new(BootParams {
            init_params: InitParams {
                rom: &gen_image_fw_ready(),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();

        // Wait for ROM to request firmware.
        model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());

        assert!(model.upload_firmware(&firmware).is_ok());

        assert_eq!(
            model.soc_mbox().cmd().read(),
            caliptra_hw_model::FW_LOAD_CMD_OPCODE
        );
        assert_eq!(model.soc_mbox().dlen().read(), firmware.len() as u32);

        // Read the data out of the mailbox.
        let mut temp: Vec<u32> = Vec::new();
        let mut word_count = (firmware.len() + 3) >> 2;
        while word_count > 0 {
            let word = model.soc_mbox().dataout().read();
            temp.push(word);
            word_count -= 1;
        }
        let fw_img_from_mb: Vec<u8> = temp.iter().flat_map(|val| val.to_le_bytes()).collect();
        assert_eq!(firmware, fw_img_from_mb[..firmware.len()]);
    }
}
