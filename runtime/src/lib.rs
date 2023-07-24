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
    cast_bytes_to_struct,
    cast_bytes_to_struct_mut,
    CommandId,
    MailboxReqCommon,
    MailboxRespCommon,
    FIPS_STATUS_APPROVED,
    CaliptraFwLoadReq,
    GetIdevCsrResp,
    GetLdevCsrResp,
    EcdsaVerifyCmdReq,
    StashMeasurementReq,
    StashMeasurementResp,
    InvokeDpeCommandReq,
    InvokeDpeCommandResp,
};

pub mod packet;
pub use fips::FipsModule;
use packet::Packet;

use caliptra_common::{cprintln, FirmwareHandoffTable};
use caliptra_drivers::{CaliptraError, CaliptraResult, DataVault, Ecc384};
use caliptra_registers::{
    dv::DvReg,
    ecc::EccReg,
    mbox::{enums::MboxStatusE, MboxCsr},
    sha512_acc::Sha512AccCsr,
    soc_ifc::SocIfcReg,
};
use zerocopy::{FromBytes, AsBytes};

pub struct Drivers<'a> {
    pub mbox: Mailbox,
    pub sha_acc: Sha512AccCsr,
    pub ecdsa: Ecc384,
    pub data_vault: DataVault,
    pub soc_ifc: SocIfcReg,
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

fn call_handler(
        drivers: &mut Drivers,
        cmd_id: CommandId,
        cmd_payload: &[u8],
        resp_buf: &mut [u8]
) -> CaliptraResult<usize> {
    // Populate the FIPS Status, this can be overridden in specfic commands if needed
    let resp_common: &mut mailbox_api::MailboxRespCommon = mailbox_api::cast_bytes_to_struct_mut(resp_buf)?;
    resp_common.fips_status = mailbox_api::FIPS_STATUS_APPROVED;

    match cmd_id {
        CommandId::FIRMWARE_LOAD => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        CommandId::GET_IDEV_CSR => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        CommandId::GET_LDEV_CERT => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        CommandId::ECDSA384_VERIFY => {
            verify::handle_ecdsa_verify(drivers, cmd_payload)?;
            Ok(0)
        }
        CommandId::STASH_MEASUREMENT => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        CommandId::INVOKE_DPE => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        #[cfg(feature = "test_only_commands")]
        CommandId::TEST_ONLY_GET_LDEV_CERT => {
            dice::copy_ldevid_cert(&drivers.data_vault, resp_buf)
        }
        #[cfg(feature = "test_only_commands")]
        CommandId::TEST_ONLY_GET_FMC_ALIAS_CERT => {
            dice::copy_fmc_alias_cert(&drivers.data_vault, resp_buf)
        }
        CommandId::VERSION => FipsModule::version(drivers),
        CommandId::SELF_TEST => FipsModule::self_test(drivers),
        CommandId::SHUTDOWN => FipsModule::shutdown(drivers),
        _ => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
    }
}

fn handle_and_respond(drivers: &mut Drivers) -> CaliptraResult<MboxStatusE> {
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

    // Create a response packet
    // TODO: OPEN: How big is our stack? We are throwing 8k on it between these 2 packets
    let mut resp_packet = Packet::default();
    // Get the full buffer regardless of the set packet length (we don't know it yet)
    let resp_payload = &mut resp_packet.payload.as_bytes_mut();

    // Handle the request and generate the response
    resp_packet.len = call_handler(drivers, CommandId::from(req_packet.cmd), cmd_bytes, resp_payload)?;

    // Send the response
    resp_packet.copy_to_mbox(drivers)?;

    Ok(MboxStatusE::DataReady)
}

pub fn handle_mailbox_commands(drivers: &mut Drivers) {
    loop {
        wait_for_cmd(&mut drivers.mbox);

        if drivers.mbox.is_cmd_ready() {
            match handle_and_respond(drivers) {
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
