// Licensed under the Apache-2.0 license

#![no_std]

pub mod dice;
pub mod info;
mod update;
mod verify;

// Used by runtime tests
pub(crate) mod fips;
pub mod mailbox;

use mailbox::Mailbox;
pub mod packet;
pub use fips::{FipsModule, VersionResponse};
use info::FwInfoCmd;
use packet::Packet;

use caliptra_common::memory_layout::{
    FHT_ORG, FHT_SIZE, FMCALIAS_TBS_ORG, FMCALIAS_TBS_SIZE, FUSE_LOG_ORG, FUSE_LOG_SIZE,
    LDEVID_TBS_ORG, LDEVID_TBS_SIZE, MAN1_ORG, MAN1_SIZE, MAN2_ORG, MAN2_SIZE, PCR_LOG_ORG,
    PCR_LOG_SIZE,
};
use caliptra_common::{cprintln, FirmwareHandoffTable};
use caliptra_drivers::{CaliptraError, CaliptraResult, DataVault, Ecc384};
use caliptra_drivers::{Hmac384, Sha256, Sha384, Sha384Acc, Trng};
use caliptra_image_types::ImageManifest;
use caliptra_registers::mbox::enums::MboxStatusE;
use caliptra_registers::{
    csrng::CsrngReg, dv::DvReg, ecc::EccReg, entropy_src::EntropySrcReg, hmac::HmacReg,
    mbox::MboxCsr, sha256::Sha256Reg, sha512::Sha512Reg, sha512_acc::Sha512AccCsr,
    soc_ifc::SocIfcReg, soc_ifc_trng::SocIfcTrngReg,
};
use zerocopy::{AsBytes, FromBytes};

const RUNTIME_BOOT_STATUS_BASE: u32 = 0x600;

/// Statuses used by ROM to log dice derivation progress.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RtBootStatus {
    // RtAlias Statuses
    RtReadyForCommands = RUNTIME_BOOT_STATUS_BASE,
}

impl From<RtBootStatus> for u32 {
    /// Converts to this type from the input type.
    fn from(status: RtBootStatus) -> u32 {
        status as u32
    }
}

#[derive(PartialEq, Eq)]
pub struct CommandId(pub u32);

impl CommandId {
    pub const FIRMWARE_LOAD: Self = Self(0x46574C44); // "FWLD"
    pub const GET_IDEV_CSR: Self = Self(0x49444556); // "IDEV"
    pub const GET_LDEV_CERT: Self = Self(0x4C444556); // "LDEV"
    pub const ECDSA384_VERIFY: Self = Self(0x53494756); // "SIGV"
    pub const STASH_MEASUREMENT: Self = Self(0x4D454153); // "MEAS"
    pub const INVOKE_DPE: Self = Self(0x44504543); // "DPEC"
    pub const FW_INFO: Self = Self(0x494E464F); // "INFO"

    pub const TEST_ONLY_GET_LDEV_CERT: Self = Self(0x4345524c); // "CERL"
    pub const TEST_ONLY_GET_FMC_ALIAS_CERT: Self = Self(0x43455246); // "CERF"
    pub const TEST_ONLY_HMAC384_VERIFY: Self = Self(0x484D4143); // "HMAC"

    /// FIPS module commands.
    /// The status command.
    pub const VERSION: Self = Self(0x4650_5652); // "FPVR"
    /// The self-test command.
    pub const SELF_TEST: Self = Self(0x4650_4C54); // "FPST"
    /// The shutdown command.
    pub const SHUTDOWN: Self = Self(0x4650_5344); // "FPSD"
}
impl From<u32> for CommandId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}
impl From<CommandId> for u32 {
    fn from(value: CommandId) -> Self {
        value.0
    }
}

pub struct Drivers<'a> {
    pub mbox: Mailbox,
    pub sha_acc: Sha512AccCsr,
    pub ecdsa: Ecc384,
    pub hmac: Hmac384,
    pub data_vault: DataVault,
    pub soc_ifc: SocIfcReg,
    pub regions: MemoryRegions,
    pub sha256: Sha256,

    // SHA2-384 Engine
    pub sha384: Sha384,

    // SHA2-384 Accelerator
    pub sha384_acc: Sha384Acc,

    /// Hmac384 Engine
    pub hmac384: Hmac384,

    /// Cryptographically Secure Random Number Generator
    pub trng: Trng,

    /// Ecc384 Engine
    pub ecc384: Ecc384,

    pub fht: &'a mut FirmwareHandoffTable,

    /// A copy of the ImageHeader for the currently running image
    pub manifest: ImageManifest,
}
impl<'a> Drivers<'a> {
    /// # Safety
    ///
    /// Callers must ensure that this function is called only once, and that
    /// any concurrent access to these register blocks does not conflict with
    /// these drivers.
    pub unsafe fn new_from_registers(fht: &'a mut FirmwareHandoffTable) -> CaliptraResult<Self> {
        let manifest_slice = unsafe {
            let ptr = MAN1_ORG as *mut u32;
            core::slice::from_raw_parts_mut(ptr, core::mem::size_of::<ImageManifest>() / 4)
        };
        let manifest = ImageManifest::read_from(manifest_slice.as_bytes())
            .ok_or(CaliptraError::RUNTIME_NO_MANIFEST)?;
        let trng = Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )?;

        Ok(Self {
            mbox: Mailbox::new(MboxCsr::new()),
            sha_acc: Sha512AccCsr::new(),
            ecdsa: Ecc384::new(EccReg::new()),
            hmac: Hmac384::new(HmacReg::new()),
            data_vault: DataVault::new(DvReg::new()),
            soc_ifc: SocIfcReg::new(),
            regions: MemoryRegions::new(),
            sha256: Sha256::new(Sha256Reg::new()),
            sha384: Sha384::new(Sha512Reg::new()),
            sha384_acc: Sha384Acc::new(Sha512AccCsr::new()),
            hmac384: Hmac384::new(HmacReg::new()),
            ecc384: Ecc384::new(EccReg::new()),
            trng,
            fht,
            manifest,
        })
    }
}
#[repr(C)]
#[derive(AsBytes, FromBytes)]
pub struct EcdsaVerifyCmd {
    pub chksum: i32,
    pub pub_key_x: [u8; 48],
    pub pub_key_y: [u8; 48],
    pub signature_r: [u8; 48],
    pub signature_s: [u8; 48],
}

impl Default for EcdsaVerifyCmd {
    fn default() -> Self {
        Self {
            chksum: 0,
            pub_key_x: [0u8; 48],
            pub_key_y: [0u8; 48],
            signature_r: [0u8; 48],
            signature_s: [0u8; 48],
        }
    }
}

#[repr(C)]
#[derive(AsBytes, FromBytes)]
pub struct HmacVerifyCmd {
    pub chksum: i32,
    pub key: [u8; 48],
    pub tag: [u8; 48],
    pub len: u32,
    pub msg: [u8; 256],
}

impl Default for HmacVerifyCmd {
    fn default() -> Self {
        Self {
            chksum: 0,
            key: [0u8; 48],
            tag: [0u8; 48],
            len: 0,
            msg: [0u8; 256],
        }
    }
}

fn wait_for_cmd(_mbox: &mut Mailbox) {
    // TODO: Enable interrupts?
    //#[cfg(feature = "riscv")]
    //unsafe {
    //core::arch::asm!("wfi");
    //}
}

fn handle_command(drivers: &mut Drivers) -> CaliptraResult<MboxStatusE> {
    // For firmware update, don't read data from the mailbox
    if drivers.mbox.cmd() == CommandId::FIRMWARE_LOAD.into() {
        update::handle_impactless_update(drivers)?;

        // If the handler succeeds but does not invoke reset that is
        // unexpected. Denote that the update failed.
        return Err(CaliptraError::RUNTIME_UNEXPECTED_UPDATE_RETURN);
    }

    // Get the command bytes
    let packet = Packet::copy_from_mbox(drivers)?;
    let cmd_bytes = packet.as_bytes()?;

    cprintln!(
        "[rt] Received command=0x{:x}, len={}",
        packet.cmd,
        packet.len
    );

    match CommandId::from(packet.cmd) {
        // FIRMWARE_LOAD expected to already be handled
        CommandId::FIRMWARE_LOAD => Err(CaliptraError::RUNTIME_UNEXPECTED_UPDATE_RETURN),
        CommandId::GET_IDEV_CSR => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        CommandId::GET_LDEV_CERT => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        CommandId::ECDSA384_VERIFY => {
            verify::handle_ecdsa_verify(drivers, cmd_bytes)?;
            Ok(MboxStatusE::CmdComplete)
        }
        CommandId::STASH_MEASUREMENT => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        CommandId::INVOKE_DPE => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        CommandId::FW_INFO => {
            let resp = FwInfoCmd::execute(drivers);
            drivers.mbox.write_response(resp.as_bytes())?;
            Ok(MboxStatusE::DataReady)
        }

        #[cfg(feature = "test_only_commands")]
        CommandId::TEST_ONLY_GET_LDEV_CERT => {
            let mut cert = [0u8; 1024];
            let cert_len = dice::copy_ldevid_cert(&drivers.data_vault, &mut cert)?;
            drivers.mbox.write_response(
                cert.get(..cert_len)
                    .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?,
            )?;
            Ok(MboxStatusE::DataReady)
        }
        #[cfg(feature = "test_only_commands")]
        CommandId::TEST_ONLY_GET_FMC_ALIAS_CERT => {
            let mut cert = [0u8; 1024];
            let cert_len = dice::copy_fmc_alias_cert(&drivers.data_vault, &mut cert)?;
            drivers.mbox.write_response(
                cert.get(..cert_len)
                    .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?,
            )?;
            Ok(MboxStatusE::DataReady)
        }
        #[cfg(feature = "test_only_commands")]
        CommandId::TEST_ONLY_HMAC384_VERIFY => {
            verify::handle_hmac_verify(drivers, cmd_bytes)?;
            Ok(MboxStatusE::CmdComplete)
        }

        CommandId::VERSION => FipsModule::version(drivers),
        CommandId::SELF_TEST => FipsModule::self_test(drivers),
        CommandId::SHUTDOWN => FipsModule::shutdown(drivers),
        _ => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
    }
}

pub fn handle_mailbox_commands(drivers: &mut Drivers) {
    // Indicator to SOC that RT firmware is ready
    drivers
        .soc_ifc
        .regs_mut()
        .cptra_flow_status()
        .write(|w| w.ready_for_runtime(true));
    caliptra_drivers::report_boot_status(RtBootStatus::RtReadyForCommands.into());
    loop {
        wait_for_cmd(&mut drivers.mbox);

        if drivers.mbox.is_cmd_ready() {
            match handle_command(drivers) {
                Ok(status) => {
                    drivers.mbox.set_status(status);
                }
                Err(e) => {
                    caliptra_drivers::report_fw_error_non_fatal(e.into());
                    drivers.mbox.set_status(MboxStatusE::CmdFailure);
                }
            }
        }
    }
}

pub struct MemoryRegions {
    man1: &'static mut [u8],
    man2: &'static mut [u8],
    fht: &'static mut [u8],
    ldevid_tbs: &'static mut [u8],
    fmcalias_tbs: &'static mut [u8],
    pcr_log: &'static mut [u8],
    fuse_log: &'static mut [u8],
}

impl MemoryRegions {
    // Create a new instance of MemoryRegions with slices based on memory addresses and sizes
    fn new() -> Self {
        Self {
            man1: unsafe { create_slice(MAN1_ORG, MAN1_SIZE as usize) },
            man2: unsafe { create_slice(MAN2_ORG, MAN2_SIZE as usize) },
            fht: unsafe { create_slice(FHT_ORG, FHT_SIZE as usize) },
            ldevid_tbs: unsafe { create_slice(LDEVID_TBS_ORG, LDEVID_TBS_SIZE as usize) },
            fmcalias_tbs: unsafe { create_slice(FMCALIAS_TBS_ORG, FMCALIAS_TBS_SIZE as usize) },
            pcr_log: unsafe { create_slice(PCR_LOG_ORG, PCR_LOG_SIZE) },
            fuse_log: unsafe { create_slice(FUSE_LOG_ORG, FUSE_LOG_SIZE) },
        }
    }
    fn zeroize(&mut self) {
        self.man1.fill(0);
        self.man2.fill(0);
        self.fht.fill(0);
        self.ldevid_tbs.fill(0);
        self.fmcalias_tbs.fill(0);
        self.pcr_log.fill(0);
        self.fuse_log.fill(0);
    }
}

// Helper function to create a mutable slice from a memory region
unsafe fn create_slice(org: u32, size: usize) -> &'static mut [u8] {
    let ptr = org as *mut u8;
    core::slice::from_raw_parts_mut(ptr, size)
}
