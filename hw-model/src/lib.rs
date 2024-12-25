// Licensed under the Apache-2.0 license

use api::CaliptraApiError;
use caliptra_api as api;
use caliptra_api::SocManager;
use caliptra_api_types as api_types;
use caliptra_emu_bus::Bus;
use core::panic;
use std::path::PathBuf;
use std::str::FromStr;
use std::{
    error::Error,
    fmt::Display,
    io::{stdout, ErrorKind, Write},
};

use caliptra_hw_model_types::{
    ErrorInjectionMode, EtrngResponse, HexBytes, HexSlice, RandomEtrngResponses, RandomNibbles,
    DEFAULT_CPTRA_OBF_KEY,
};
use zerocopy::{AsBytes, FromBytes, LayoutVerified, Unalign};

use caliptra_registers::mbox;
use caliptra_registers::mbox::enums::{MboxFsmE, MboxStatusE};
use caliptra_registers::soc_ifc::regs::{
    CptraItrngEntropyConfig0WriteVal, CptraItrngEntropyConfig1WriteVal,
};

use rand::{rngs::StdRng, SeedableRng};
use sha2::Digest;

pub mod mmio;
mod model_emulated;

mod bus_logger;
#[cfg(feature = "verilator")]
mod model_verilated;

#[cfg(feature = "fpga_realtime")]
mod model_fpga_realtime;

mod output;
mod rv32_builder;

pub use api::mailbox::mbox_write_fifo;
pub use api_types::{DbgManufServiceRegReq, DeviceLifecycle, Fuses, SecurityState, U4};
pub use caliptra_emu_bus::BusMmio;
pub use caliptra_emu_cpu::{CodeRange, ImageInfo, StackInfo, StackRange};
use output::ExitStatus;
pub use output::Output;

pub use model_emulated::ModelEmulated;

#[cfg(feature = "verilator")]
pub use model_verilated::ModelVerilated;
use ureg::MmioMut;

pub enum ShaAccMode {
    Sha384Stream,
    Sha512Stream,
}

#[cfg(feature = "fpga_realtime")]
pub use model_fpga_realtime::ModelFpgaRealtime;
#[cfg(feature = "fpga_realtime")]
pub use model_fpga_realtime::OpenOcdError;

/// Ideally, general-purpose functions would return `impl HwModel` instead of
/// `DefaultHwModel` to prevent users from calling functions that aren't
/// available on all HwModel implementations.  Unfortunately, rust-analyzer
/// (used by IDEs) can't fully resolve associated types from `impl Trait`, so
/// such functions should use `DefaultHwModel` until they fix that. Users should
/// treat `DefaultHwModel` as if it were `impl HwModel`.
#[cfg(all(not(feature = "verilator"), not(feature = "fpga_realtime")))]
pub type DefaultHwModel = ModelEmulated;

#[cfg(feature = "verilator")]
pub type DefaultHwModel = ModelVerilated;

#[cfg(feature = "fpga_realtime")]
pub type DefaultHwModel = ModelFpgaRealtime;

pub const DEFAULT_APB_PAUSER: u32 = 0x01;

/// Constructs an HwModel based on the cargo features and environment
/// variables. Most test cases that need to construct a HwModel should use this
/// function over HwModel::new_unbooted().
///
/// The model returned by this function does not have any fuses programmed and
/// is not yet ready to execute code in the microcontroller. Most test cases
/// should use [`new`] instead.
pub fn new_unbooted(params: InitParams) -> Result<DefaultHwModel, Box<dyn Error>> {
    let summary = params.summary();
    DefaultHwModel::new_unbooted(params).map(|hw| {
        println!(
            "Using hardware-model {} trng={:?}",
            hw.type_name(),
            hw.trng_mode()
        );
        println!("{summary:#?}");
        hw
    })
}

/// Constructs an HwModel based on the cargo features and environment variables,
/// and boot it to the point where CPU execution can occur. This includes
/// programming the fuses, initializing the boot_fsm state machine, and
/// (optionally) uploading firmware. Most test cases that need to construct a
/// HwModel should use this function over [`HwModel::new()`] and
/// [`crate::new_unbooted`].
pub fn new(
    init_params: InitParams,
    boot_params: BootParams,
) -> Result<DefaultHwModel, Box<dyn Error>> {
    DefaultHwModel::new(init_params, boot_params)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrngMode {
    // soc_ifc_reg.CPTRA_HW_CONFIG.iTRNG_en will be true.
    // When running with the verlated hw-model, the itrng compile-time feature
    // must be enabled or initialization will fail.
    Internal,

    // soc_ifc_reg.CPTRA_HW_CONFIG.iTRNG_en will be false.
    // When running with the verlated hw-model, the itrng compile-time feature
    // must be disabled or initialization will fail.
    External,
}
impl TrngMode {
    pub fn resolve(mode: Option<Self>) -> Self {
        if let Some(mode) = mode {
            mode
        } else if cfg!(feature = "itrng") {
            TrngMode::Internal
        } else {
            TrngMode::External
        }
    }
}

const EXPECTED_CALIPTRA_BOOT_TIME_IN_CYCLES: u64 = 40_000_000; // 40 million cycles

pub struct InitParams<'a> {
    // The contents of the boot ROM
    pub rom: &'a [u8],

    // The initial contents of the DCCM SRAM
    pub dccm: &'a [u8],

    // The initial contents of the ICCM SRAM
    pub iccm: &'a [u8],

    pub log_writer: Box<dyn std::io::Write>,

    pub security_state: SecurityState,

    pub dbg_manuf_service: DbgManufServiceRegReq,

    pub debug_intent: bool,

    // The silicon obfuscation key passed to caliptra_top.
    pub cptra_obf_key: [u32; 8],

    // 4-bit nibbles of raw entropy to feed into the internal TRNG (ENTROPY_SRC
    // peripheral).
    pub itrng_nibbles: Box<dyn Iterator<Item = u8> + Send>,

    // Pre-conditioned TRNG responses to return over the soc_ifc CPTRA_TRNG_DATA
    // registers in response to requests via CPTRA_TRNG_STATUS
    pub etrng_responses: Box<dyn Iterator<Item = EtrngResponse> + Send>,

    // When None, use the itrng compile-time feature to decide which mode to use.
    pub trng_mode: Option<TrngMode>,

    // If true (and the HwModel supports it), initialize the SRAM with random
    // data. This will likely result in a ECC double-bit error if the CPU
    // attempts to read uninitialized memory.
    pub random_sram_puf: bool,

    // A trace path to use. If None, the CPTRA_TRACE_PATH environment variable
    // will be used
    pub trace_path: Option<PathBuf>,

    // Information about the stack Caliptra is using. When set the emulator will check if the stack
    // overflows.
    pub stack_info: Option<StackInfo>,
}
impl<'a> Default for InitParams<'a> {
    fn default() -> Self {
        let seed = std::env::var("CPTRA_TRNG_SEED")
            .ok()
            .and_then(|s| u64::from_str(&s).ok());
        let itrng_nibbles: Box<dyn Iterator<Item = u8> + Send> = if let Some(seed) = seed {
            Box::new(RandomNibbles(StdRng::seed_from_u64(seed)))
        } else {
            Box::new(RandomNibbles(StdRng::from_entropy()))
        };
        let etrng_responses: Box<dyn Iterator<Item = EtrngResponse> + Send> =
            if let Some(seed) = seed {
                Box::new(RandomEtrngResponses(StdRng::seed_from_u64(seed)))
            } else {
                Box::new(RandomEtrngResponses::new_from_stdrng())
            };
        Self {
            rom: Default::default(),
            dccm: Default::default(),
            iccm: Default::default(),
            log_writer: Box::new(stdout()),
            security_state: *SecurityState::default()
                .set_device_lifecycle(DeviceLifecycle::Unprovisioned),
            dbg_manuf_service: Default::default(),
            debug_intent: false,
            cptra_obf_key: DEFAULT_CPTRA_OBF_KEY,
            itrng_nibbles,
            etrng_responses,
            trng_mode: Some(if cfg!(feature = "itrng") {
                TrngMode::Internal
            } else {
                TrngMode::External
            }),
            random_sram_puf: true,
            trace_path: None,
            stack_info: None,
        }
    }
}

impl<'a> InitParams<'a> {
    fn summary(&self) -> InitParamsSummary {
        InitParamsSummary {
            rom_sha384: sha2::Sha384::digest(self.rom).into(),
            obf_key: self.cptra_obf_key,
            security_state: self.security_state,
        }
    }
}

pub struct InitParamsSummary {
    rom_sha384: [u8; 48],
    obf_key: [u32; 8],
    security_state: SecurityState,
}
impl std::fmt::Debug for InitParamsSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitParamsSummary")
            .field("rom_sha384", &HexBytes(&self.rom_sha384))
            .field("obf_key", &HexSlice(&self.obf_key))
            .field("security_state", &self.security_state)
            .finish()
    }
}

fn trace_path_or_env(trace_path: Option<PathBuf>) -> Option<PathBuf> {
    if let Some(trace_path) = trace_path {
        return Some(trace_path);
    }
    std::env::var("CPTRA_TRACE_PATH").ok().map(PathBuf::from)
}

pub struct BootParams<'a> {
    pub fuses: Fuses,
    pub active_mode: bool,
    pub fw_image: Option<&'a [u8]>,
    pub initial_dbg_manuf_service_reg: u32,
    pub initial_repcnt_thresh_reg: Option<CptraItrngEntropyConfig1WriteVal>,
    pub initial_adaptp_thresh_reg: Option<CptraItrngEntropyConfig0WriteVal>,
    pub valid_axi_user: Vec<u32>,
    pub wdt_timeout_cycles: u64,
}

impl<'a> Default for BootParams<'a> {
    fn default() -> Self {
        Self {
            fuses: Default::default(),
            active_mode: false,
            fw_image: Default::default(),
            initial_dbg_manuf_service_reg: Default::default(),
            initial_repcnt_thresh_reg: Default::default(),
            initial_adaptp_thresh_reg: Default::default(),
            valid_axi_user: vec![0, 1, 2, 3, 4],
            wdt_timeout_cycles: EXPECTED_CALIPTRA_BOOT_TIME_IN_CYCLES,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ModelError {
    MailboxCmdFailed(u32),
    UnableToSetPauser,
    UnableToLockMailbox,
    BufferTooLargeForMailbox,
    UploadFirmwareUnexpectedResponse,
    UnknownCommandStatus(u32),
    NotReadyForFwErr,
    ReadyForFirmwareTimeout {
        cycles: u32,
    },
    ProvidedIccmTooLarge,
    ProvidedDccmTooLarge,
    UnexpectedMailboxFsmStatus {
        expected: u32,
        actual: u32,
    },
    UnableToLockSha512Acc,
    UploadMeasurementResponseError,
    UnableToReadMailbox,
    MailboxNoResponseData,
    MailboxReqTypeTooSmall,
    MailboxRespTypeTooSmall,
    MailboxUnexpectedResponseLen {
        expected_min: u32,
        expected_max: u32,
        actual: u32,
    },
    MailboxRespInvalidChecksum {
        expected: u32,
        actual: u32,
    },
    MailboxRespInvalidFipsStatus(u32),
    MailboxTimeout,
    ReadBufferTooSmall,
    FuseDoneNotSet,
    FusesAlreadyInitialized,
    StashMeasurementFailed,
}

impl From<CaliptraApiError> for ModelError {
    fn from(error: CaliptraApiError) -> Self {
        match error {
            CaliptraApiError::UnableToLockMailbox => ModelError::UnableToLockMailbox,
            CaliptraApiError::UnableToReadMailbox => ModelError::UnableToReadMailbox,
            CaliptraApiError::BufferTooLargeForMailbox => ModelError::BufferTooLargeForMailbox,
            CaliptraApiError::UnknownCommandStatus(code) => ModelError::UnknownCommandStatus(code),
            CaliptraApiError::MailboxTimeout => ModelError::MailboxTimeout,
            CaliptraApiError::MailboxCmdFailed(code) => ModelError::MailboxCmdFailed(code),
            CaliptraApiError::UnexpectedMailboxFsmStatus { expected, actual } => {
                ModelError::UnexpectedMailboxFsmStatus { expected, actual }
            }
            CaliptraApiError::MailboxRespInvalidFipsStatus(status) => {
                ModelError::MailboxRespInvalidFipsStatus(status)
            }
            CaliptraApiError::MailboxRespInvalidChecksum { expected, actual } => {
                ModelError::MailboxRespInvalidChecksum { expected, actual }
            }
            CaliptraApiError::MailboxRespTypeTooSmall => ModelError::MailboxRespTypeTooSmall,
            CaliptraApiError::MailboxReqTypeTooSmall => ModelError::MailboxReqTypeTooSmall,
            CaliptraApiError::MailboxNoResponseData => ModelError::MailboxNoResponseData,
            CaliptraApiError::MailboxUnexpectedResponseLen {
                expected_min,
                expected_max,
                actual,
            } => ModelError::MailboxUnexpectedResponseLen {
                expected_min,
                expected_max,
                actual,
            },
            CaliptraApiError::UploadFirmwareUnexpectedResponse => {
                ModelError::UploadFirmwareUnexpectedResponse
            }
            CaliptraApiError::UploadMeasurementResponseError => {
                ModelError::UploadMeasurementResponseError
            }
            caliptra_api::CaliptraApiError::ReadBuffTooSmall => ModelError::ReadBufferTooSmall,
            caliptra_api::CaliptraApiError::FuseDoneNotSet => ModelError::FuseDoneNotSet,
            caliptra_api::CaliptraApiError::FusesAlreadyIniitalized => {
                ModelError::FusesAlreadyInitialized
            }
            caliptra_api::CaliptraApiError::StashMeasurementFailed => {
                ModelError::StashMeasurementFailed
            }
            caliptra_api::CaliptraApiError::UnableToSetPauser => ModelError::UnableToSetPauser,
        }
    }
}
impl Error for ModelError {}
impl Display for ModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModelError::MailboxCmdFailed(err) => write!(f, "Mailbox command failed. fw_err={err}"),
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
            ModelError::ProvidedDccmTooLarge => write!(f, "Provided DCCM image too large"),
            ModelError::ProvidedIccmTooLarge => write!(f, "Provided ICCM image too large"),
            ModelError::UnexpectedMailboxFsmStatus { expected, actual } => write!(
                f,
                "Expected mailbox FSM status to be {expected}, was {actual}"
            ),
            ModelError::UnableToLockSha512Acc => write!(f, "Unable to lock sha512acc"),
            ModelError::UploadMeasurementResponseError => {
                write!(f, "Error in response after uploading measurement")
            }
            ModelError::UnableToReadMailbox => write!(f, "Unable to read mailbox regs"),
            ModelError::MailboxNoResponseData => {
                write!(f, "Expected response data but none was found")
            }
            ModelError::MailboxReqTypeTooSmall => {
                write!(f, "Mailbox request type too small to contain header")
            }
            ModelError::MailboxRespTypeTooSmall => {
                write!(f, "Mailbox response type too small to contain header")
            }
            ModelError::MailboxUnexpectedResponseLen {
                expected_min,
                expected_max,
                actual,
            } => {
                write!(
                    f,
                    "Expected mailbox response lenth min={expected_min} max={expected_max}, was {actual}"
                )
            }
            ModelError::MailboxRespInvalidChecksum { expected, actual } => {
                write!(
                    f,
                    "Mailbox response had invalid checksum: expected {expected}, was {actual}"
                )
            }
            ModelError::MailboxRespInvalidFipsStatus(status) => {
                write!(
                    f,
                    "Mailbox response had non-success FIPS status: 0x{status:x}"
                )
            }
            ModelError::MailboxTimeout => {
                write!(f, "Mailbox timed out in busy state")
            }

            ModelError::ReadBufferTooSmall => {
                write!(f, "Cant read mailbox because read buffer too small")
            }

            ModelError::FuseDoneNotSet => {
                write!(f, "Fuse Wr Done bit not set")
            }

            ModelError::FusesAlreadyInitialized => {
                write!(f, "Fuses already initialized")
            }
            ModelError::StashMeasurementFailed => {
                write!(f, "Stash measurement request failed")
            }
            ModelError::UnableToSetPauser => {
                write!(f, "Valid PAUSER locked")
            }
        }
    }
}

pub struct MailboxRequest {
    pub cmd: u32,
    pub data: Vec<u8>,
}

pub struct MailboxRecvTxn<'a, TModel: HwModel> {
    model: &'a mut TModel,
    pub req: MailboxRequest,
}
impl<'a, Model: HwModel> MailboxRecvTxn<'a, Model> {
    pub fn respond_success(self) {
        self.complete(MboxStatusE::CmdComplete);
    }
    pub fn respond_failure(self) {
        self.complete(MboxStatusE::CmdFailure);
    }
    pub fn respond_with_data(self, data: &[u8]) -> Result<(), ModelError> {
        let mbox = self.model.soc_mbox();
        let mbox_fsm_ps = mbox.status().read().mbox_fsm_ps();
        if !mbox_fsm_ps.mbox_execute_soc() {
            return Err(ModelError::UnexpectedMailboxFsmStatus {
                expected: MboxFsmE::MboxExecuteSoc as u32,
                actual: mbox_fsm_ps as u32,
            });
        }
        mbox_write_fifo(&mbox, data)?;
        drop(mbox);
        self.complete(MboxStatusE::DataReady);
        Ok(())
    }

    fn complete(self, status: MboxStatusE) {
        self.model
            .soc_mbox()
            .status()
            .write(|w| w.status(|_| status));
        // mbox_fsm_ps isn't updated immediately after execute is cleared (!?),
        // so step an extra clock cycle to wait for fm_ps to update
        self.model.step();
    }
}

fn mbox_read_fifo(mbox: mbox::RegisterBlock<impl MmioMut>) -> Vec<u8> {
    let dlen = mbox.dlen().read() as usize;

    let mut buf = vec![0; dlen];
    buf.resize(dlen, 0);

    let _ = caliptra_api::mailbox::mbox_read_fifo(mbox, buf.as_mut_slice());

    buf
}

/// Firmware Load Command Opcode
const FW_LOAD_CMD_OPCODE: u32 = 0x4657_4C44;

/// Stash Measurement Command Opcode.
const STASH_MEASUREMENT_CMD_OPCODE: u32 = 0x4D45_4153;

// Represents a emulator or simulation of the caliptra hardware, to be called
// from tests. Typically, test cases should use [`crate::new()`] to create a model
// based on the cargo features (and any model-specific environment variables).
pub trait HwModel: SocManager {
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
    fn new(init_params: InitParams, boot_params: BootParams) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized,
    {
        let init_params_summary = init_params.summary();

        let mut hw: Self = HwModel::new_unbooted(init_params)?;
        let hw_rev_id = hw.soc_ifc().cptra_hw_rev_id().read();
        println!(
            "Using hardware-model {} trng={:?} hw_rev_id={{cptra_generation=0x{:04x}, soc_stepping_id={:04x}}}",
            hw.type_name(), hw.trng_mode(),  hw_rev_id.cptra_generation(), hw_rev_id.soc_stepping_id()
        );
        println!("{init_params_summary:#?}");

        hw.boot(boot_params)?;

        Ok(hw)
    }

    fn boot(&mut self, boot_params: BootParams) -> Result<(), Box<dyn Error>>
    where
        Self: Sized,
    {
        HwModel::init_fuses(self, &boot_params.fuses);

        self.soc_ifc()
            .cptra_dbg_manuf_service_reg()
            .write(|_| boot_params.initial_dbg_manuf_service_reg);

        self.soc_ifc()
            .cptra_wdt_cfg()
            .at(0)
            .write(|_| boot_params.wdt_timeout_cycles as u32);

        self.soc_ifc()
            .cptra_wdt_cfg()
            .at(1)
            .write(|_| (boot_params.wdt_timeout_cycles >> 32) as u32);

        if let Some(reg) = boot_params.initial_repcnt_thresh_reg {
            self.soc_ifc()
                .cptra_i_trng_entropy_config_1()
                .write(|_| reg);
        }

        if let Some(reg) = boot_params.initial_adaptp_thresh_reg {
            self.soc_ifc()
                .cptra_i_trng_entropy_config_0()
                .write(|_| reg);
        }

        // Set up the PAUSER as valid for the mailbox (using index 0)
        self.setup_mailbox_users(boot_params.valid_axi_user.as_slice())
            .map_err(ModelError::from)?;

        writeln!(self.output().logger(), "writing to cptra_bootfsm_go")?;
        self.soc_ifc().cptra_bootfsm_go().write(|w| w.go(true));

        self.step();

        if let Some(fw_image) = boot_params.fw_image {
            const MAX_WAIT_CYCLES: u32 = 20_000_000;
            let mut cycles = 0;
            while !self.ready_for_fw() {
                // If GENERATE_IDEVID_CSR was set then we need to clear cptra_dbg_manuf_service_reg
                // once the CSR is ready to continue making progress.
                //
                // Generally the CSR should be read from the mailbox at this point, but to
                // accommodate test cases that ignore the CSR mailbox, we will ignore it here.
                if self.soc_ifc().cptra_flow_status().read().idevid_csr_ready() {
                    self.soc_ifc().cptra_dbg_manuf_service_reg().write(|_| 0);
                }

                self.step();
                cycles += 1;
                if cycles > MAX_WAIT_CYCLES {
                    return Err(ModelError::ReadyForFirmwareTimeout { cycles }.into());
                }
            }
            writeln!(self.output().logger(), "ready_for_fw is high")?;
            self.cover_fw_mage(fw_image);
            if boot_params.active_mode {
                self.upload_firmware_rri(fw_image)?;
            } else {
                self.upload_firmware(fw_image)?;
            }
        }

        Ok(())
    }

    /// The type name of this model
    fn type_name(&self) -> &'static str;

    /// The TRNG mode used by this model.
    fn trng_mode(&self) -> TrngMode;

    /// Trigger a warm reset and advance the boot
    fn warm_reset_flow(&mut self, fuses: &Fuses) {
        self.warm_reset();

        HwModel::init_fuses(self, fuses);
        self.soc_ifc().cptra_bootfsm_go().write(|w| w.go(true));
    }

    /// The AXI bus from the SoC to Caliptra
    ///
    /// WARNING: Reading or writing to this bus may involve the Caliptra
    /// microcontroller executing a few instructions
    fn axi_bus(&mut self) -> Self::TBus<'_>;

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

    /// Toggle reset pins and wait for ready_for_fuses
    fn warm_reset(&mut self) {
        // To be overridden by HwModel implementations that support this
        panic!("warm_reset unimplemented");
    }

    /// Toggle reset/pwrgood pins and wait for ready_for_fuses
    fn cold_reset(&mut self) {
        // To be overridden by HwModel implementations that support this
        panic!("cold_reset unimplemented");
    }

    /// Returns true if the microcontroller has signalled that it is ready for
    /// firmware to be written to the mailbox. For RTL implementations, this
    /// should come via a caliptra_top wire rather than an AXI register.
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
        println!("Initializing fuses");
        if let Err(e) = caliptra_api::SocManager::init_fuses(self, fuses) {
            panic!(
                "{}",
                format!("Fuse initializaton error: {}", ModelError::from(e))
            );
        }
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

    fn step_until_exit_failure(&mut self) -> std::io::Result<()> {
        loop {
            match self.output().exit_status() {
                Some(ExitStatus::Failed) => return Ok(()),
                Some(ExitStatus::Passed) => {
                    return Err(std::io::Error::new(
                        ErrorKind::Other,
                        "firmware exited with success when failure was expected",
                    ))
                }
                None => {}
            }
            self.step();
        }
    }

    /// Execute until the output buffer starts with `expected_output`
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

    /// Execute until the output buffer starts with `expected_output`, and remove it
    /// from the output buffer.
    fn step_until_output_and_take(&mut self, expected_output: &str) -> Result<(), Box<dyn Error>> {
        self.step_until_output(expected_output)?;
        self.output().take(expected_output.len());
        Ok(())
    }

    // Execute (at least) until the output provided substr is written to the
    // output. Additional data may be present in the output after the provided
    // substr, which often happens with the fpga_realtime hardware model.
    //
    // This function will not match any data in the output that was written
    // before this function was called.
    fn step_until_output_contains(&mut self, substr: &str) -> Result<(), Box<dyn Error>> {
        self.output().set_search_term(substr);
        self.step_until(|m| m.output().search_matched());
        Ok(())
    }

    fn step_until_boot_status(
        &mut self,
        expected_status_u32: u32,
        ignore_intermediate_status: bool,
    ) {
        // Since the boot takes less than 30M cycles, we know something is wrong if
        // we're stuck at the same state for that duration.
        const MAX_WAIT_CYCLES: u32 = 30_000_000;

        let mut cycle_count = 0u32;
        let initial_boot_status_u32 = self.soc_ifc().cptra_boot_status().read();
        loop {
            let actual_status_u32 = self.soc_ifc().cptra_boot_status().read();
            if expected_status_u32 == actual_status_u32 {
                break;
            }

            if !ignore_intermediate_status && actual_status_u32 != initial_boot_status_u32 {
                panic!(
                    "Expected the next boot_status to be  \
                    ({expected_status_u32}), but status changed from \
                    {initial_boot_status_u32} to {actual_status_u32})"
                );
            }
            self.step();
            cycle_count += 1;
            if cycle_count >= MAX_WAIT_CYCLES {
                panic!(
                    "Expected boot_status to be  \
                    ({expected_status_u32}), but was stuck at ({actual_status_u32})"
                );
            }
        }
    }

    fn step_until_fatal_error(&mut self, expected_error: u32, max_wait_cycles: u32) {
        let mut cycle_count = 0u32;
        let initial_error = self.soc_ifc().cptra_fw_error_fatal().read();
        loop {
            let actual_error = self.soc_ifc().cptra_fw_error_fatal().read();
            if actual_error == expected_error {
                break;
            }

            if actual_error != initial_error {
                panic!(
                    "Expected the fatal error to be  \
                    ({expected_error}), but error changed from \
                    {initial_error} to {actual_error})"
                );
            }
            self.step();
            cycle_count += 1;
            if cycle_count >= max_wait_cycles {
                panic!(
                    "Expected fatal error to be  \
                    ({expected_error}), but was stuck at ({initial_error})"
                );
            }
        }
    }

    fn cover_fw_mage(&mut self, _image: &[u8]) {}

    fn tracing_hint(&mut self, enable: bool);

    fn ecc_error_injection(&mut self, _mode: ErrorInjectionMode) {}

    fn set_axi_user(&mut self, axi_user: u32);

    /// Executes a typed request and (if success), returns the typed response.
    /// The checksum field of the request is calculated, and the checksum of the
    /// response is validated.
    fn mailbox_execute_req<R: api::mailbox::Request>(
        &mut self,
        req: R,
    ) -> std::result::Result<R::Resp, ModelError> {
        let mut response = R::Resp::new_zeroed();

        self.mailbox_exec_req(req, response.as_bytes_mut())
            .map_err(ModelError::from)
    }

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
        self.start_mailbox_execute(cmd, buf)?;
        self.finish_mailbox_execute()
    }

    /// Send a command to the mailbox but don't wait for the response
    fn start_mailbox_execute(
        &mut self,
        cmd: u32,
        buf: &[u8],
    ) -> std::result::Result<(), ModelError> {
        // Read a 0 to get the lock
        if self.soc_mbox().lock().read().lock() {
            return Err(ModelError::UnableToLockMailbox);
        }

        // Mailbox lock value should read 1 now
        // If not, the reads are likely being blocked by the AXI_USER check or some other issue
        if !(self.soc_mbox().lock().read().lock()) {
            return Err(ModelError::UnableToReadMailbox);
        }

        writeln!(
            self.output().logger(),
            "<<< Executing mbox cmd 0x{cmd:08x} ({} bytes) from SoC",
            buf.len(),
        )
        .unwrap();

        self.soc_mbox().cmd().write(|_| cmd);
        mbox_write_fifo(&self.soc_mbox(), buf).map_err(ModelError::from)?;

        // Ask the microcontroller to execute this command
        self.soc_mbox().execute().write(|w| w.execute(true));

        Ok(())
    }

    /// Wait for the response to a previous call to `start_mailbox_execute()`.
    fn finish_mailbox_execute(&mut self) -> std::result::Result<Option<Vec<u8>>, ModelError> {
        // Wait for the microcontroller to finish executing
        let mut timeout_cycles = 40000000; // 100ms @400MHz
        while self.soc_mbox().status().read().status().cmd_busy() {
            self.step();
            timeout_cycles -= 1;
            if timeout_cycles == 0 {
                return Err(ModelError::MailboxTimeout);
            }
        }
        let status = self.soc_mbox().status().read().status();
        if status.cmd_failure() {
            writeln!(self.output().logger(), ">>> mbox cmd response: failed").unwrap();
            self.soc_mbox().execute().write(|w| w.execute(false));
            let soc_ifc = self.soc_ifc();
            return Err(ModelError::MailboxCmdFailed(
                if soc_ifc.cptra_fw_error_fatal().read() != 0 {
                    soc_ifc.cptra_fw_error_fatal().read()
                } else {
                    soc_ifc.cptra_fw_error_non_fatal().read()
                },
            ));
        }
        if status.cmd_complete() {
            writeln!(self.output().logger(), ">>> mbox cmd response: success").unwrap();
            self.soc_mbox().execute().write(|w| w.execute(false));
            return Ok(None);
        }
        if !status.data_ready() {
            return Err(ModelError::UnknownCommandStatus(status as u32));
        }

        let dlen = self.soc_mbox().dlen().read();
        writeln!(
            self.output().logger(),
            ">>> mbox cmd response data ({dlen} bytes)"
        )
        .unwrap();
        let result = mbox_read_fifo(self.soc_mbox());

        self.soc_mbox().execute().write(|w| w.execute(false));

        if cfg!(not(feature = "fpga_realtime")) {
            // Don't check for mbox_idle() unless the hw-model supports
            // fine-grained timing control; the firmware may proceed to lock the
            // mailbox shortly after the mailbox transcation finishes (for example, to
            // test the sha2_512_384_acc peripheral).

            // mbox_fsm_ps isn't updated immediately after execute is cleared (!?),
            // so step an extra clock cycle to wait for fm_ps to update
            self.step();
            assert!(self.soc_mbox().status().read().mbox_fsm_ps().mbox_idle());
        }
        Ok(Some(result))
    }

    /// Streams `data` to the sha512acc SoC interface. If `sha384` computes
    /// the sha384 hash of `data`, else computes sha512 hash.
    ///
    /// Returns the computed digest if the sha512acc lock can be acquired.
    /// Else, returns an error.
    fn compute_sha512_acc_digest(
        &mut self,
        data: &[u8],
        mode: ShaAccMode,
    ) -> Result<Vec<u8>, ModelError> {
        self.soc_sha512_acc().control().write(|w| w.zeroize(true));

        if self.soc_sha512_acc().lock().read().lock() {
            return Err(ModelError::UnableToLockSha512Acc);
        }

        self.soc_sha512_acc()
            .dlen()
            .write(|_| data.len().try_into().unwrap());

        self.soc_sha512_acc().mode().write(|w| {
            w.mode(|w| match mode {
                ShaAccMode::Sha384Stream => w.sha_stream_384(),
                ShaAccMode::Sha512Stream => w.sha_stream_512(),
            })
        });

        // Unwrap cannot fail, count * sizeof(u32) is always smaller than data.len()
        let (prefix_words, suffix_bytes) =
            LayoutVerified::<_, [Unalign<u32>]>::new_slice_unaligned_from_prefix(
                data,
                data.len() / 4,
            )
            .unwrap();

        for word in prefix_words.into_slice() {
            self.soc_sha512_acc()
                .datain()
                .write(|_| word.get().swap_bytes());
        }

        if !suffix_bytes.is_empty() {
            let mut word = [0u8; 4];
            word[..suffix_bytes.len()].copy_from_slice(suffix_bytes);
            self.soc_sha512_acc()
                .datain()
                .write(|_| u32::from_be_bytes(word));
        }

        self.soc_sha512_acc().execute().write(|w| w.execute(true));

        self.step_until(|m| m.soc_sha512_acc().status().read().valid());

        self.soc_sha512_acc().lock().write(|w| w.lock(true)); // clear lock

        Ok(self.soc_sha512_acc().digest().read().as_bytes().to_vec())
    }

    /// Upload firmware to the mailbox.
    fn upload_firmware(&mut self, firmware: &[u8]) -> Result<(), ModelError> {
        let response = self.mailbox_execute(FW_LOAD_CMD_OPCODE, firmware)?;
        if response.is_some() {
            return Err(ModelError::UploadFirmwareUnexpectedResponse);
        }
        Ok(())
    }

    /// HW-model function to place the image in rri
    fn put_firmware_in_rri(&mut self, firmware: &[u8]) -> Result<(), ModelError>;

    /// Upload fw image to RRI.
    fn upload_firmware_rri(&mut self, firmware: &[u8]) -> Result<(), ModelError> {
        self.put_firmware_in_rri(firmware)?;
        // TODO Add method to inform caliptra to start fetching from the RRI
        Ok(())
    }

    fn wait_for_mailbox_receive(&mut self) -> Result<MailboxRecvTxn<Self>, ModelError>
    where
        Self: Sized,
    {
        loop {
            if let Some(txn) = self.try_mailbox_receive()? {
                let req = txn.req;
                return Ok(MailboxRecvTxn { model: self, req });
            }
        }
    }

    fn try_mailbox_receive(&mut self) -> Result<Option<MailboxRecvTxn<Self>>, ModelError>
    where
        Self: Sized,
    {
        if !self
            .soc_mbox()
            .status()
            .read()
            .mbox_fsm_ps()
            .mbox_execute_soc()
        {
            self.step();
            return Ok(None);
        }
        let cmd = self.soc_mbox().cmd().read();
        let data = mbox_read_fifo(self.soc_mbox());
        Ok(Some(MailboxRecvTxn {
            model: self,
            req: MailboxRequest { cmd, data },
        }))
    }

    /// Upload measurement to the mailbox.
    fn upload_measurement(&mut self, measurement: &[u8]) -> Result<(), ModelError> {
        let response = self.mailbox_execute(STASH_MEASUREMENT_CMD_OPCODE, measurement)?;

        // We expect a response
        let response = response.ok_or(ModelError::UploadMeasurementResponseError)?;

        // Get response as a response header struct
        let response = api::mailbox::StashMeasurementResp::read_from(response.as_slice())
            .ok_or(ModelError::UploadMeasurementResponseError)?;

        // Verify checksum and FIPS status
        if !api::verify_checksum(
            response.hdr.chksum,
            0x0,
            &response.as_bytes()[core::mem::size_of_val(&response.hdr.chksum)..],
        ) {
            return Err(ModelError::UploadMeasurementResponseError);
        }

        if response.hdr.fips_status != api::mailbox::MailboxRespHeader::FIPS_STATUS_APPROVED {
            return Err(ModelError::UploadMeasurementResponseError);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        mmio::Rv32GenMmio, BootParams, DefaultHwModel, HwModel, InitParams, ModelError, ShaAccMode,
    };
    use caliptra_api::mailbox::{self, CommandId, MailboxReqHeader, MailboxRespHeader};
    use caliptra_api::soc_mgr::SocManager;
    use caliptra_builder::firmware;
    use caliptra_emu_bus::Bus;
    use caliptra_emu_types::RvSize;
    use caliptra_registers::{mbox::enums::MboxStatusE, soc_ifc};
    use zerocopy::{AsBytes, FromBytes};

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
        soc_ifc
            .cptra_generic_output_wires()
            .at(0)
            .write(|_| 0x100 | u32::from(b'i'));
        soc_ifc.cptra_generic_output_wires().at(0).write(|_| 0xff);
        rv32_gen.into_inner().empty_loop().build()
    }

    #[test]
    fn test_axi() {
        let mut model = caliptra_hw_model::new_unbooted(InitParams {
            rom: &gen_image_hi(),
            ..Default::default()
        })
        .unwrap();

        model.soc_ifc().cptra_fuse_wr_done().write(|w| w.done(true));
        model.soc_ifc().cptra_bootfsm_go().write(|w| w.go(true));

        // Set up the AXI_USER as valid for the mailbox (using index 0)
        model
            .soc_ifc()
            .cptra_mbox_valid_axi_user()
            .at(0)
            .write(|_| 0x1);
        model
            .soc_ifc()
            .cptra_mbox_axi_user_lock()
            .at(0)
            .write(|w| w.lock(true));

        assert_eq!(
            model.axi_bus().read(RvSize::Word, MBOX_ADDR_LOCK).unwrap(),
            0
        );

        assert_eq!(
            model.axi_bus().read(RvSize::Word, MBOX_ADDR_LOCK).unwrap(),
            1
        );

        model
            .axi_bus()
            .write(RvSize::Word, MBOX_ADDR_CMD, 4242)
            .unwrap();
        assert_eq!(
            model.axi_bus().read(RvSize::Word, MBOX_ADDR_CMD).unwrap(),
            4242
        );
    }

    #[test]
    fn test_mbox() {
        // Same as test_axi, but uses higher-level register interface
        let mut model = caliptra_hw_model::new_unbooted(InitParams {
            rom: &gen_image_hi(),
            ..Default::default()
        })
        .unwrap();

        model.soc_ifc().cptra_fuse_wr_done().write(|w| w.done(true));
        model.soc_ifc().cptra_bootfsm_go().write(|w| w.go(true));

        // Set up the AXI_USER as valid for the mailbox (using index 0)
        model
            .soc_ifc()
            .cptra_mbox_valid_axi_user()
            .at(0)
            .write(|_| 0x1);
        model
            .soc_ifc()
            .cptra_mbox_axi_user_lock()
            .at(0)
            .write(|w| w.lock(true));

        assert!(!model.soc_mbox().lock().read().lock());
        assert!(model.soc_mbox().lock().read().lock());

        model.soc_mbox().cmd().write(|_| 4242);
        assert_eq!(model.soc_mbox().cmd().read(), 4242);
    }

    #[test]
    /// Violate the mailbox protocol by having the sender trying to write to mailbox in execute state.
    fn test_mbox_negative() {
        let mut model = caliptra_hw_model::new_unbooted(InitParams {
            rom: &gen_image_hi(),
            ..Default::default()
        })
        .unwrap();

        model.soc_ifc().cptra_fuse_wr_done().write(|w| w.done(true));
        model.soc_ifc().cptra_bootfsm_go().write(|w| w.go(true));

        // Set up the AXI_USER as valid for the mailbox (using index 0)
        model
            .soc_ifc()
            .cptra_mbox_valid_axi_user()
            .at(0)
            .write(|_| 0x1);
        model
            .soc_ifc()
            .cptra_mbox_axi_user_lock()
            .at(0)
            .write(|w| w.lock(true));

        assert!(!model.soc_mbox().lock().read().lock());
        assert!(model.soc_mbox().lock().read().lock());

        model.soc_mbox().cmd().write(|_| 4242);
        assert_eq!(model.soc_mbox().cmd().read(), 4242);

        model.soc_mbox().execute().write(|w| w.execute(true));
        model.soc_mbox().dlen().write(|_| [1, 2, 3].len() as u32);
        assert_eq!([1, 2, 3].len() as u32, model.soc_mbox().dlen().read());
        let _ = caliptra_hw_model::mbox_write_fifo(&model.soc_mbox(), &[1, 2, 3]);
        let buf = caliptra_hw_model::mbox_read_fifo(model.soc_mbox());
        assert_eq!(buf, &[0, 0, 0]);
    }

    #[test]
    // Currently only possible on verilator
    // SW emulator does not support axi_user
    // For FPGA, test case needs to be reworked to capture SIGBUS from linux environment
    #[cfg(feature = "verilator")]
    fn test_mbox_axi_user() {
        let mut model = caliptra_hw_model::new_unbooted(InitParams {
            rom: &gen_image_hi(),
            ..Default::default()
        })
        .unwrap();

        model.soc_ifc().cptra_fuse_wr_done().write(|w| w.done(true));
        model.soc_ifc().cptra_bootfsm_go().write(|w| w.go(true));

        // Set up the AXI_USER as valid for the mailbox (using index 0)
        model
            .soc_ifc()
            .cptra_mbox_valid_axi_user()
            .at(0)
            .write(|_| 0x1);
        model
            .soc_ifc()
            .cptra_mbox_axi_user_lock()
            .at(0)
            .write(|w| w.lock(true));

        // Set the AXI_USER to something invalid
        model.set_axi_user(0x2);

        assert!(!model.soc_mbox().lock().read().lock());
        // Should continue to read 0 because the reads are being blocked by valid AXI_USER
        assert!(!model.soc_mbox().lock().read().lock());

        // Set the AXI_USER back to valid
        model.set_axi_user(0x1);

        // Should read 0 the first time still for lock available
        assert!(!model.soc_mbox().lock().read().lock());
        // Should read 1 now for lock taken
        assert!(model.soc_mbox().lock().read().lock());

        model.soc_mbox().cmd().write(|_| 4242);
        assert_eq!(model.soc_mbox().cmd().read(), 4242);
    }

    #[test]
    fn test_execution() {
        let mut model = caliptra_hw_model::new(
            InitParams {
                rom: &gen_image_hi(),
                ..Default::default()
            },
            BootParams::default(),
        )
        .unwrap();
        model.step_until_output("hii").unwrap();
    }

    #[test]
    fn test_output_failure() {
        let mut model = caliptra_hw_model::new(
            InitParams {
                rom: &gen_image_hi(),
                ..Default::default()
            },
            BootParams::default(),
        )
        .unwrap();

        if cfg!(feature = "fpga_realtime") {
            // The fpga_realtime model can't pause execution precisely, so just assert the
            // entire output of the program.
            assert_eq!(
                model.step_until_output("haa").err().unwrap().to_string(),
                "expected output \"haa\", was \"hii\""
            );
        } else {
            assert_eq!(
                model.step_until_output("ha").err().unwrap().to_string(),
                "expected output \"ha\", was \"hi\""
            );
        }
    }

    #[test]
    pub fn test_mailbox_execute() {
        let message: [u8; 10] = [0x90, 0x5e, 0x1f, 0xad, 0x8b, 0x60, 0xb0, 0xbf, 0x1c, 0x7e];

        let rom =
            caliptra_builder::build_firmware_rom(&firmware::hw_model_tests::MAILBOX_RESPONDER)
                .unwrap();

        let mut model = caliptra_hw_model::new(
            InitParams {
                rom: &rom,
                ..Default::default()
            },
            BootParams::default(),
        )
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
            Err(ModelError::MailboxCmdFailed(0))
        );
    }

    #[test]
    /// Test SocManager maiLbox API.
    fn test_negative_soc_mgr_mbox_users() {
        let mut model = caliptra_hw_model::new_unbooted(InitParams {
            rom: &gen_image_hi(),
            ..Default::default()
        })
        .unwrap();

        model.soc_ifc().cptra_fuse_wr_done().write(|w| w.done(true));
        model.soc_ifc().cptra_bootfsm_go().write(|w| w.go(true));

        // Set up the PAUSER as valid for the mailbox (using index 0)
        model
            .soc_ifc()
            .cptra_mbox_valid_axi_user()
            .at(0)
            .write(|_| 0x1);
        model
            .soc_ifc()
            .cptra_mbox_axi_user_lock()
            .at(0)
            .write(|w| w.lock(true));

        assert_eq!(
            model.setup_mailbox_users(&[1]),
            Err(caliptra_api::CaliptraApiError::UnableToSetPauser)
        );
    }

    #[test]
    /// Test SocManager maiLbox API.
    fn test_soc_mgr_mbox_api() {
        use caliptra_api::CaliptraApiError;
        let message: [u8; 10] = [0x90, 0x5e, 0x1f, 0xad, 0x8b, 0x60, 0xb0, 0xbf, 0x1c, 0x7e];

        let rom =
            caliptra_builder::build_firmware_rom(&firmware::hw_model_tests::MAILBOX_RESPONDER)
                .unwrap();

        let mut model = caliptra_hw_model::new(
            InitParams {
                rom: &rom,
                ..Default::default()
            },
            BootParams::default(),
        )
        .unwrap();

        // Send command that echoes the command and input message
        let mut resp_data = [0u8; 128];

        assert_eq!(
            model.mailbox_exec(0x1000_0000, &message, &mut resp_data),
            Ok(Some(
                [[0x00, 0x00, 0x00, 0x10].as_slice(), &message]
                    .concat()
                    .as_bytes()
            )),
        );

        // Send command that echoes the command and input message
        let mut resp_data = [0u8; 128];
        assert_eq!(
            model.mailbox_exec(0x1000_0000, &message[..8], resp_data.as_bytes_mut()),
            Ok(Some(
                [0x00, 0x00, 0x00, 0x10, 0x90, 0x5e, 0x1f, 0xad, 0x8b, 0x60, 0xb0, 0xbf].as_slice()
            )),
        );

        // Send command that returns 7 bytes of output, and doesn't consume input
        // Send command that echoes the command and input message
        let mut resp_data = [0u8; 128];

        assert_eq!(
            model.mailbox_exec(0x1000_1000, &[42], resp_data.as_bytes_mut()),
            Ok(Some([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd].as_slice())),
        );

        // Send command that returns success with no output
        assert_eq!(
            model.mailbox_exec(0x2000_0000, &[], resp_data.as_bytes_mut()),
            Ok(None)
        );

        // Send command that returns failure
        assert_eq!(
            model.mailbox_exec(0x4000_0000, &message, resp_data.as_bytes_mut()),
            Err(CaliptraApiError::MailboxCmdFailed(0))
        );
    }

    #[test]
    pub fn test_mailbox_receive() {
        let rom = caliptra_builder::build_firmware_rom(&firmware::hw_model_tests::MAILBOX_SENDER)
            .unwrap();

        let mut model = caliptra_hw_model::new(
            InitParams {
                rom: &rom,
                ..Default::default()
            },
            BootParams::default(),
        )
        .unwrap();

        // Test 8-byte request, respond-with-success
        let txn = model.wait_for_mailbox_receive().unwrap();
        assert_eq!(txn.req.cmd, 0xe000_0000);
        assert_eq!(
            txn.req.data,
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
        txn.respond_success();
        model.step_until(|m| m.soc_ifc().cptra_fw_extended_error_info().at(0).read() != 0);
        assert_eq!(
            &model.soc_ifc().cptra_fw_extended_error_info().read()[..2],
            &[MboxStatusE::CmdComplete as u32, 8]
        );
        // Signal that we're ready to move on...
        model.soc_ifc().cptra_rsvd_reg().at(0).write(|_| 1);

        // Test 3-byte request, respond with failure
        let txn = model.wait_for_mailbox_receive().unwrap();
        assert_eq!(txn.req.cmd, 0xe000_1000);
        assert_eq!(txn.req.data, [0xdd, 0xcc, 0xbb]);
        txn.respond_failure();
        model.step_until(|m| m.soc_ifc().cptra_fw_extended_error_info().at(0).read() != 0);
        assert_eq!(
            &model.soc_ifc().cptra_fw_extended_error_info().read()[..2],
            &[MboxStatusE::CmdFailure as u32, 3]
        );

        // TODO: Add test for txn.respond_with_data (this doesn't work yet due
        // to https://github.com/chipsalliance/caliptra-rtl/issues/78)
    }

    struct Sha384Test<'a> {
        msg: &'a [u8],
        expected: &'a [u8],
    }

    #[test]
    fn test_sha512_acc() {
        let rom =
            caliptra_builder::build_firmware_rom(&firmware::hw_model_tests::MAILBOX_RESPONDER)
                .unwrap();

        let mut model = caliptra_hw_model::new(
            InitParams {
                rom: &rom,
                ..Default::default()
            },
            BootParams::default(),
        )
        .unwrap();

        assert_eq!(
            model.compute_sha512_acc_digest(b"Hello", ShaAccMode::Sha384Stream),
            Err(ModelError::UnableToLockSha512Acc)
        );

        // Ask firmware to unlock mailbox for sha512acc use.
        model.mailbox_execute(0x5000_0000, &[]).unwrap();

        let tests = vec![
            Sha384Test {
                msg: &[
                    0x9d, 0xd7, 0x89, 0xea, 0x25, 0xc0, 0x47, 0x45, 0xd5, 0x7a, 0x38, 0x1f, 0x22,
                    0xde, 0x01, 0xfb, 0x0a, 0xbd, 0x3c, 0x72, 0xdb, 0xde, 0xfd, 0x44, 0xe4, 0x32,
                    0x13, 0xc1, 0x89, 0x58, 0x3e, 0xef, 0x85, 0xba, 0x66, 0x20, 0x44, 0xda, 0x3d,
                    0xe2, 0xdd, 0x86, 0x70, 0xe6, 0x32, 0x51, 0x54, 0x48, 0x01, 0x55, 0xbb, 0xee,
                    0xbb, 0x70, 0x2c, 0x75, 0x78, 0x1a, 0xc3, 0x2e, 0x13, 0x94, 0x18, 0x60, 0xcb,
                    0x57, 0x6f, 0xe3, 0x7a, 0x05, 0xb7, 0x57, 0xda, 0x5b, 0x5b, 0x41, 0x8f, 0x6d,
                    0xd7, 0xc3, 0x0b, 0x04, 0x2e, 0x40, 0xf4, 0x39, 0x5a, 0x34, 0x2a, 0xe4, 0xdc,
                    0xe0, 0x56, 0x34, 0xc3, 0x36, 0x25, 0xe2, 0xbc, 0x52, 0x43, 0x45, 0x48, 0x1f,
                    0x7e, 0x25, 0x3d, 0x95, 0x51, 0x26, 0x68, 0x23, 0x77, 0x1b, 0x25, 0x17, 0x05,
                    0xb4, 0xa8, 0x51, 0x66, 0x02, 0x2a, 0x37, 0xac, 0x28, 0xf1, 0xbd,
                ],
                expected: &[
                    0xf5, 0x83, 0x5b, 0x96, 0x43, 0x74, 0x4f, 0xd3, 0x8f, 0xe7, 0x88, 0xeb, 0x91,
                    0x47, 0x23, 0xcc, 0x00, 0xcb, 0xc9, 0x56, 0x33, 0x68, 0xdd, 0x80, 0xd3, 0x0a,
                    0xac, 0x4d, 0x74, 0xc7, 0xa8, 0x3b, 0x00, 0x44, 0x0e, 0x10, 0xb4, 0x28, 0xdb,
                    0x63, 0x37, 0xac, 0x51, 0x0b, 0x70, 0x4d, 0x5d, 0x70, 0x3c, 0x0a, 0xbb, 0xa6,
                    0x14, 0xdd, 0xd9, 0xf3, 0x55, 0x6a, 0x49, 0xa9, 0xb6, 0x6c, 0xc1, 0x67,
                ],
            },
            Sha384Test {
                msg: &[0x74, 0x65, 0x73, 0x74], // Bytes "test"
                // Computed with sha384sum
                expected: &[
                    0x32, 0x12, 0x84, 0x76, 0xa5, 0x0a, 0x7b, 0x0f, 0x42, 0xce, 0x2f, 0x81, 0x6b,
                    0x70, 0xc4, 0x8d, 0xe0, 0x50, 0xae, 0x3c, 0xa1, 0xca, 0x64, 0x2a, 0x49, 0x22,
                    0x78, 0x6a, 0xc4, 0xef, 0xe8, 0xbf, 0xcb, 0x1c, 0xef, 0xb7, 0xd1, 0x55, 0x62,
                    0x12, 0xfe, 0x7d, 0x04, 0x96, 0xa9, 0xa0, 0x17, 0xdf, 0x2b, 0x26, 0xbc, 0xd5,
                    0xa3, 0x97, 0xb7, 0xa2, 0xc9, 0xa9, 0xfe, 0xc4, 0x9a, 0x82, 0x9e, 0xc9,
                ],
            },
            Sha384Test {
                msg: &[0x74, 0x65], // Bytes "te"
                // Computed with sha384sum
                expected: &[
                    0x1a, 0x88, 0x9c, 0x7c, 0x64, 0x5c, 0x9e, 0x54, 0x8a, 0xc9, 0x49, 0x9a, 0xca,
                    0xd3, 0xea, 0xf4, 0x6c, 0x6c, 0x7e, 0x90, 0xf4, 0x98, 0x7f, 0xfc, 0xd7, 0x0a,
                    0x64, 0x8f, 0x4b, 0x58, 0x83, 0xf7, 0xcc, 0xca, 0x60, 0xf4, 0x75, 0xdd, 0xa3,
                    0x6f, 0x20, 0x18, 0xd7, 0x55, 0xf8, 0xfc, 0x9a, 0x19, 0xf0, 0xc8, 0x23, 0x0f,
                    0xdf, 0xe0, 0x8a, 0xa4, 0xda, 0xc0, 0x83, 0x95, 0xe6, 0xa0, 0x2d, 0xa5,
                ],
            },
        ];

        for test in tests {
            assert_eq!(
                model
                    .compute_sha512_acc_digest(test.msg, ShaAccMode::Sha384Stream)
                    .unwrap(),
                test.expected
            );
        }
    }

    #[test]
    pub fn test_soc_mgr_exec_req() {
        const NO_DATA_CMD: u32 = 0x2000_0000;
        const SET_RESPONSE_CMD: u32 = 0x3000_0000;
        const GET_RESPONSE_CMD: u32 = 0x3000_0001;

        #[repr(C)]
        #[derive(AsBytes, FromBytes, Default)]
        struct TestReq {
            hdr: MailboxReqHeader,
            data: [u8; 4],
        }
        impl mailbox::Request for TestReq {
            const ID: CommandId = CommandId(GET_RESPONSE_CMD);
            type Resp = TestResp;
        }
        #[repr(C)]
        #[derive(AsBytes, Debug, FromBytes, PartialEq, Eq)]
        struct TestResp {
            hdr: MailboxRespHeader,
            data: [u8; 4],
        }
        impl mailbox::Response for TestResp {}

        #[repr(C)]
        #[derive(AsBytes, FromBytes, Default)]
        struct TestReqNoData {
            hdr: MailboxReqHeader,
            data: [u8; 4],
        }
        impl mailbox::Request for TestReqNoData {
            const ID: CommandId = CommandId(NO_DATA_CMD);
            type Resp = TestResp;
        }

        fn set_response(model: &mut DefaultHwModel, data: &[u8]) {
            model.mailbox_execute(SET_RESPONSE_CMD, data).unwrap();
        }

        let rom =
            caliptra_builder::build_firmware_rom(&firmware::hw_model_tests::MAILBOX_RESPONDER)
                .unwrap();
        let mut model = caliptra_hw_model::new(
            InitParams {
                rom: &rom,
                ..Default::default()
            },
            BootParams::default(),
        )
        .unwrap();

        // Success
        set_response(
            &mut model,
            &[
                0x2d, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, b'H', b'I', b'!', b'!',
            ],
        );

        let mut packet = [0u8; 256];
        let resp = model
            .mailbox_exec_req(
                TestReq {
                    data: *b"Hi!!",
                    ..Default::default()
                },
                &mut packet,
            )
            .unwrap();
        model
            .step_until_output_and_take("|dcfeffff48692121|")
            .unwrap();
        assert_eq!(
            resp,
            TestResp {
                hdr: MailboxRespHeader {
                    chksum: 0xffffff2d,
                    fips_status: 0
                },
                data: *b"HI!!",
            },
        );

        // Set wrong length in response
        set_response(
            &mut model,
            &[
                0x2d, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, b'H', b'I', b'!',
            ],
        );
        let resp = model
            .mailbox_exec_req(
                TestReq {
                    data: *b"Hi!!",
                    ..Default::default()
                },
                &mut packet,
            )
            .map_err(ModelError::from);
        assert_eq!(
            resp,
            Err(ModelError::MailboxUnexpectedResponseLen {
                expected_min: 12,
                expected_max: 12,
                actual: 11
            })
        );

        // Set bad checksum in response
        set_response(
            &mut model,
            &[
                0x2e, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, b'H', b'I', b'!', b'!',
            ],
        );
        let resp = model
            .mailbox_exec_req(
                TestReq {
                    data: *b"Hi!!",
                    ..Default::default()
                },
                packet.as_bytes_mut(),
            )
            .map_err(ModelError::from);
        assert_eq!(
            resp,
            Err(ModelError::MailboxRespInvalidChecksum {
                expected: 0xffffff2e,
                actual: 0xffffff2d
            })
        );

        // Set bad FIPS status in response
        set_response(
            &mut model,
            &[
                0x0c, 0xff, 0xff, 0xff, 0x01, 0x20, 0x00, 0x00, b'H', b'I', b'!', b'!',
            ],
        );
        let mut packet = [0u8; 12];
        let resp = model
            .mailbox_exec_req(
                TestReq {
                    data: *b"Hi!!",
                    ..Default::default()
                },
                &mut packet,
            )
            .map_err(ModelError::from);
        assert_eq!(resp, Err(ModelError::MailboxRespInvalidFipsStatus(0x2001)));

        // Set no data in response
        let resp = model
            .mailbox_exec_req(
                TestReqNoData {
                    data: *b"Hi!!",
                    ..Default::default()
                },
                &mut packet,
            )
            .map_err(ModelError::from);
        assert_eq!(resp, Err(ModelError::MailboxNoResponseData));
    }

    #[test]
    pub fn test_mailbox_execute_req() {
        const NO_DATA_CMD: u32 = 0x2000_0000;
        const SET_RESPONSE_CMD: u32 = 0x3000_0000;
        const GET_RESPONSE_CMD: u32 = 0x3000_0001;

        #[repr(C)]
        #[derive(AsBytes, FromBytes, Default)]
        struct TestReq {
            hdr: MailboxReqHeader,
            data: [u8; 4],
        }
        impl mailbox::Request for TestReq {
            const ID: CommandId = CommandId(GET_RESPONSE_CMD);
            type Resp = TestResp;
        }
        #[repr(C)]
        #[derive(AsBytes, Debug, FromBytes, PartialEq, Eq)]
        struct TestResp {
            hdr: MailboxRespHeader,
            data: [u8; 4],
        }
        impl mailbox::Response for TestResp {}

        #[repr(C)]
        #[derive(AsBytes, FromBytes, Default)]
        struct TestReqNoData {
            hdr: MailboxReqHeader,
            data: [u8; 4],
        }
        impl mailbox::Request for TestReqNoData {
            const ID: CommandId = CommandId(NO_DATA_CMD);
            type Resp = TestResp;
        }

        fn set_response(model: &mut DefaultHwModel, data: &[u8]) {
            model.mailbox_execute(SET_RESPONSE_CMD, data).unwrap();
        }

        let rom =
            caliptra_builder::build_firmware_rom(&firmware::hw_model_tests::MAILBOX_RESPONDER)
                .unwrap();
        let mut model = caliptra_hw_model::new(
            InitParams {
                rom: &rom,
                ..Default::default()
            },
            BootParams::default(),
        )
        .unwrap();

        // Success
        set_response(
            &mut model,
            &[
                0x2d, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, b'H', b'I', b'!', b'!',
            ],
        );
        let resp = model
            .mailbox_execute_req(TestReq {
                data: *b"Hi!!",
                ..Default::default()
            })
            .unwrap();
        model
            .step_until_output_and_take("|dcfeffff48692121|")
            .unwrap();
        assert_eq!(
            resp,
            TestResp {
                hdr: MailboxRespHeader {
                    chksum: 0xffffff2d,
                    fips_status: 0
                },
                data: *b"HI!!",
            },
        );

        // Set wrong length in response
        set_response(
            &mut model,
            &[
                0x2d, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, b'H', b'I', b'!',
            ],
        );
        let resp = model.mailbox_execute_req(TestReq {
            data: *b"Hi!!",
            ..Default::default()
        });
        assert_eq!(
            resp,
            Err(ModelError::MailboxUnexpectedResponseLen {
                expected_min: 12,
                expected_max: 12,
                actual: 11
            })
        );

        // Set bad checksum in response
        set_response(
            &mut model,
            &[
                0x2e, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, b'H', b'I', b'!', b'!',
            ],
        );
        let resp = model.mailbox_execute_req(TestReq {
            data: *b"Hi!!",
            ..Default::default()
        });
        assert_eq!(
            resp,
            Err(ModelError::MailboxRespInvalidChecksum {
                expected: 0xffffff2e,
                actual: 0xffffff2d
            })
        );

        // Set bad FIPS status in response
        set_response(
            &mut model,
            &[
                0x0c, 0xff, 0xff, 0xff, 0x01, 0x20, 0x00, 0x00, b'H', b'I', b'!', b'!',
            ],
        );
        let resp = model.mailbox_execute_req(TestReq {
            data: *b"Hi!!",
            ..Default::default()
        });
        assert_eq!(resp, Err(ModelError::MailboxRespInvalidFipsStatus(0x2001)));

        // Set no data in response
        let resp = model.mailbox_execute_req(TestReqNoData {
            data: *b"Hi!!",
            ..Default::default()
        });
        assert_eq!(resp, Err(ModelError::MailboxNoResponseData));
    }

    #[test]
    #[cfg(any(feature = "verilator", feature = "fpga_realtime"))]
    pub fn test_cold_reset() {
        let mut model = caliptra_hw_model::new(
            InitParams {
                rom: &gen_image_hi(),
                ..Default::default()
            },
            BootParams::default(),
        )
        .unwrap();
        model.step_until_output("hii").unwrap();

        model.cold_reset();

        model.boot(BootParams::default()).unwrap();

        model.step_until_output("hii").unwrap();
    }
}
