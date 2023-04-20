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

#[derive(Debug, Eq, PartialEq)]
pub enum ModelError {
    MailboxCmdFailed,
    UnableToLockMailbox,
    BufferTooLargeForMailbox,
    UploadFirmwareUnexpectedResponse,
    UnknownCommandStatus(u32),
    NotReadyForFwErr,
    ReadyForFirmwareTimeout { cycles: u32 },
}
impl Error for ModelError {}
impl Display for ModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModelError::MailboxCmdFailed => write!(f, "Mailbox command failed"),
            ModelError::UnableToLockMailbox => write!(f, "Unable to lock mailbox"),
            ModelError::BufferTooLargeForMailbox => write!(f, "Buffer too large for mailbox"),
            ModelError::UploadFirmwareUnexpectedResponse => {
                write!(f, "Received unexpected response after uploading firmware")
            }
            ModelError::UnknownCommandStatus(status) => write!(
                f,
                "Received unknown command status from mailbox peripheral: 0x{status:x}"
            ),
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

        writeln!(hw.output().logger(), "writing to cptra_bootfsm_go")?;
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
            writeln!(hw.output().logger(), "ready_for_fw is high")?;
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

    /// Executes `cmd` with request data `buf`. Returns `Ok(Some(_))` if
    /// the uC responded with data, `Ok(None)` if the uC indicated success
    /// without data, Err(ModelError::MailboxCmdFailed) if the microcontroller
    /// responded with an error, or other model errors if there was a problem
    /// communicating with the mailbox.
    fn mailbox_execute(
        &mut self,
        cmd: u32,
        buf: &[u8],
    ) -> std::result::Result<Option<Vec<u8>>, ModelError> {
        const MAILBOX_SIZE: u32 = 128 * 1024;

        if self.soc_mbox().lock().read().lock() {
            return Err(ModelError::UnableToLockMailbox);
        }
        let Ok(input_len) = u32::try_from(buf.len()) else {
            return Err(ModelError::BufferTooLargeForMailbox);
        };
        if input_len > MAILBOX_SIZE {
            return Err(ModelError::BufferTooLargeForMailbox);
        }

        self.soc_mbox().cmd().write(|_| cmd);
        self.soc_mbox().dlen().write(|_| input_len);

        writeln!(
            self.output().logger(),
            "<<< Executing mbox cmd 0x{cmd:08x} ({input_len} bytes) from SoC"
        )
        .unwrap();
        let mut remaining = buf;
        while remaining.len() >= 4 {
            // Panic is impossible because the subslice is always 4 bytes
            let word = u32::from_le_bytes(remaining[..4].try_into().unwrap());
            self.soc_mbox().datain().write(|_| word);
            remaining = &remaining[4..];
        }
        if !remaining.is_empty() {
            let mut word_bytes = [0u8; 4];
            word_bytes[..remaining.len()].copy_from_slice(remaining);
            let word = u32::from_le_bytes(word_bytes);
            self.soc_mbox().datain().write(|_| word);
        }

        // Ask the microcontroller to execute this command
        self.soc_mbox().execute().write(|w| w.execute(true));

        // Wait for the microcontroller to finish executing
        while self.soc_mbox().status().read().status().cmd_busy() {
            self.step();
        }
        let status = self.soc_mbox().status().read().status();
        if status.cmd_failure() {
            writeln!(self.output().logger(), ">>> mbox cmd response: failed").unwrap();
            self.soc_mbox().execute().write(|w| w.execute(false));
            return Err(ModelError::MailboxCmdFailed);
        }
        if status.cmd_complete() {
            writeln!(self.output().logger(), ">>> mbox cmd response: success").unwrap();
            self.soc_mbox().execute().write(|w| w.execute(false));
            return Ok(None);
        }
        if !status.data_ready() {
            return Err(ModelError::UnknownCommandStatus(status as u32));
        }

        let mut result = vec![];
        let mut dlen = self.soc_mbox().dlen().read();

        writeln!(
            self.output().logger(),
            ">>> mbox cmd response data ({dlen} bytes)"
        )
        .unwrap();
        while dlen >= 4 {
            result.extend_from_slice(&self.soc_mbox().dataout().read().to_le_bytes());
            dlen -= 4;
        }
        if dlen > 0 {
            // Unwrap cannot panic because dlen is less than 4
            result.extend_from_slice(
                &self.soc_mbox().dataout().read().to_le_bytes()[..usize::try_from(dlen).unwrap()],
            );
        }

        self.soc_mbox().execute().write(|w| w.execute(false));
        // mbox_fsm_ps isn't updated immediately after execute is cleared (!?),
        // so step an extra clock cycle to wait for fm_ps to update
        self.step();
        assert!(self.soc_mbox().status().read().mbox_fsm_ps().mbox_idle());
        Ok(Some(result))
    }

    /// Upload firmware to the mailbox.
    fn upload_firmware(&mut self, firmware: &[u8]) -> Result<(), ModelError> {
        let response = self.mailbox_execute(FW_LOAD_CMD_OPCODE, firmware)?;
        if response.is_some() {
            return Err(ModelError::UploadFirmwareUnexpectedResponse);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{mmio::Rv32GenMmio, BootParams, HwModel, InitParams, ModelError};
    use caliptra_builder::FwId;
    use caliptra_emu_bus::Bus;
    use caliptra_emu_types::RvSize;
    use caliptra_registers::soc_ifc;

    use crate as caliptra_hw_model;

    const MBOX_ADDR_BASE: u32 = 0x3002_0000;
    const MBOX_ADDR_LOCK: u32 = MBOX_ADDR_BASE;
    const MBOX_ADDR_CMD: u32 = MBOX_ADDR_BASE + 0x0000_0008;

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
    pub fn test_mailbox_execute() {
        let message: [u8; 10] = [0x90, 0x5e, 0x1f, 0xad, 0x8b, 0x60, 0xb0, 0xbf, 0x1c, 0x7e];

        let rom = caliptra_builder::build_firmware_rom(&FwId {
            crate_name: "caliptra-hw-model-test-fw",
            bin_name: "mailbox_responder",
            features: &["emu"],
        })
        .unwrap();

        let mut model = caliptra_hw_model::new(BootParams {
            init_params: InitParams {
                rom: &rom,
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();

        // Send command that echoes the command and input message
        assert_eq!(
            model.mailbox_execute(0x1000_0000, &message),
            Ok(Some(
                [[0x00, 0x00, 0x00, 0x10].as_slice(), &message].concat()
            )),
        );

        // Send command that echoes the command and input message
        assert_eq!(
            model.mailbox_execute(0x1000_0000, &message[..8]),
            Ok(Some(vec![
                0x00, 0x00, 0x00, 0x10, 0x90, 0x5e, 0x1f, 0xad, 0x8b, 0x60, 0xb0, 0xbf
            ])),
        );

        // Send command that returns 7 bytes of output
        assert_eq!(
            model.mailbox_execute(0x1000_1000, &[]),
            Ok(Some(vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd]))
        );

        // Send command that returns 7 bytes of output, and doesn't consume input
        assert_eq!(
            model.mailbox_execute(0x1000_1000, &[42]),
            Ok(Some(vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd])),
        );

        // Send command that returns 0 bytes of output
        assert_eq!(model.mailbox_execute(0x1000_2000, &[]), Ok(Some(vec![])));

        // Send command that returns success with no output
        assert_eq!(model.mailbox_execute(0x2000_0000, &[]), Ok(None));

        // Send command that returns failure
        assert_eq!(
            model.mailbox_execute(0x4000_0000, &message),
            Err(ModelError::MailboxCmdFailed)
        );
    }
}
