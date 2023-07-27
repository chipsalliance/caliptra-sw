// Licensed under the Apache-2.0 license

#![no_std]

pub mod dice;
mod update;
mod verify;

// Used by runtime tests
pub(crate) mod fips;
pub mod mailbox;
use mailbox::Mailbox;

pub mod mailbox_api;
pub use mailbox_api::{
    CommandId,
    MailboxResp,
    MailboxReqHeader,
    MailboxRespHeader,
    GetIdevCsrResp,
    GetLdevCsrResp,
    EcdsaVerifyCmdReq,
    StashMeasurementReq,
    StashMeasurementResp,
    InvokeDpeCommandReq,
    InvokeDpeCommandResp,
    TestGetFmcAliasCertResp,
};

pub mod packet;
pub use fips::{FipsModule, VersionResponse};
use packet::Packet;

use caliptra_common::memory_layout::{
    FHT_ORG, FHT_SIZE, FMCALIAS_TBS_ORG, FMCALIAS_TBS_SIZE, FUSE_LOG_ORG, FUSE_LOG_SIZE,
    LDEVID_TBS_ORG, LDEVID_TBS_SIZE, MAN1_ORG, MAN1_SIZE, MAN2_ORG, MAN2_SIZE, PCR_LOG_ORG,
    PCR_LOG_SIZE,
};
use caliptra_common::{cprintln, FirmwareHandoffTable};
use caliptra_drivers::{CaliptraError, CaliptraResult, DataVault, Ecc384};
use caliptra_registers::{
    dv::DvReg,
    ecc::EccReg,
    mbox::{enums::MboxStatusE, MboxCsr},
    sha512_acc::Sha512AccCsr,
    soc_ifc::SocIfcReg,
};

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

pub struct Drivers<'a> {
    pub mbox: Mailbox,
    pub sha_acc: Sha512AccCsr,
    pub ecdsa: Ecc384,
    pub data_vault: DataVault,
    pub soc_ifc: SocIfcReg,
    pub regions: MemoryRegions,
    pub fht: &'a mut FirmwareHandoffTable,
}
impl<'a> Drivers<'a> {
    /// # Safety
    ///
    /// Callers must ensure that this function is called only once, and that
    /// any concurrent access to these register blocks does not conflict with
    /// these drivers.
    pub unsafe fn new_from_registers(fht: &'a mut FirmwareHandoffTable) -> Self {
        Self {
            mbox: Mailbox::new(MboxCsr::new()),
            sha_acc: Sha512AccCsr::new(),
            ecdsa: Ecc384::new(EccReg::new()),
            data_vault: DataVault::new(DvReg::new()),
            soc_ifc: SocIfcReg::new(),
            regions: MemoryRegions::new(),
            fht,
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

/// Handles the pending mailbox command and writes the repsonse back to the mailbox
///
/// Returns the mailbox status (DataReady when we send a response) or an error
fn handle_command(drivers: &mut Drivers) -> CaliptraResult<MboxStatusE> {
    // For firmware update, don't read data from the mailbox
    if drivers.mbox.cmd() == CommandId::FIRMWARE_LOAD.into() {
        update::handle_impactless_update(drivers)?;

        // If the handler succeeds but does not invoke reset that is
        // unexpected. Denote that the update failed.
        return Err(CaliptraError::RUNTIME_UNEXPECTED_UPDATE_RETURN);
    }

    // Get the command bytes
    let req_packet = Packet::copy_from_mbox(drivers)?;
    let cmd_bytes = req_packet.as_bytes()?;

    cprintln!(
        "[rt] Received command=0x{:x}, len={}",
        req_packet.cmd,
        req_packet.len
    );

    // Handle the request and generate the response
    let mut resp = match CommandId::from(req_packet.cmd) {
        CommandId::FIRMWARE_LOAD => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        CommandId::GET_IDEV_CSR => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        CommandId::GET_LDEV_CERT => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        CommandId::ECDSA384_VERIFY => verify::handle_ecdsa_verify(drivers, cmd_bytes),
        CommandId::STASH_MEASUREMENT => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        CommandId::INVOKE_DPE => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        #[cfg(feature = "test_only_commands")]
        CommandId::TEST_ONLY_GET_LDEV_CERT => dice::handle_get_ldevid_cert(&drivers.data_vault),
        #[cfg(feature = "test_only_commands")]
        CommandId::TEST_ONLY_GET_FMC_ALIAS_CERT => dice::handle_get_fmc_alias_cert(&drivers.data_vault),
        CommandId::VERSION => FipsModule::version(drivers),
        CommandId::SELF_TEST => FipsModule::self_test(drivers),
        CommandId::SHUTDOWN => FipsModule::shutdown(drivers),
        _ => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
    }?;

    // Send the response
    Packet::copy_to_mbox(drivers, &mut resp)?;

    Ok(MboxStatusE::DataReady)
}

pub fn handle_mailbox_commands(drivers: &mut Drivers) {
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
