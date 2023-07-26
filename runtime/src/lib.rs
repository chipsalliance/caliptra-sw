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
    TestGetCertResp,
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

    // Some responses have a variable size
    // Leave as None otherwise
    let resp_size_ovrd: Option<usize> = None;

    // Handle the request and generate the response
    let mut resp: Option<MailboxResp> = match CommandId::from(req_packet.cmd) {
        CommandId::FIRMWARE_LOAD => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        CommandId::GET_IDEV_CSR => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        CommandId::GET_LDEV_CERT => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        CommandId::ECDSA384_VERIFY => {
            verify::handle_ecdsa_verify(drivers, cmd_bytes)?;
            Ok(None)
        }
        CommandId::STASH_MEASUREMENT => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        CommandId::INVOKE_DPE => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        #[cfg(feature = "test_only_commands")]
        CommandId::TEST_ONLY_GET_LDEV_CERT => {
            let (payload, resp_size_ovrd) = dice::handle_get_ldevid_cert(&drivers.data_vault)?;
            Ok(Some(MailboxResp::TestGetCert(payload)))
        }
        #[cfg(feature = "test_only_commands")]
        CommandId::TEST_ONLY_GET_FMC_ALIAS_CERT => {
            let (payload, resp_size_ovrd) = dice::handle_get_fmc_alias_cert(&drivers.data_vault)?;
            Ok(Some(MailboxResp::TestGetCert(payload)))
        }
        CommandId::VERSION => {
            FipsModule::version(drivers)?;
            Ok(None)
        }
        CommandId::SELF_TEST => {
            FipsModule::self_test(drivers)?;
            Ok(None)
        }
        CommandId::SHUTDOWN => {
            FipsModule::shutdown(drivers)?;
            Ok(None)
        }
        _ => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
    }?;

    // If there was no reponse payload from the handler, still send back a header
    let mut resp = match resp {
        Some(resp) => resp,
        None => MailboxResp::Header(MailboxRespHeader::default()),
    };

    // Send the response
    Packet::copy_to_mbox(drivers, &mut resp, resp_size_ovrd)?;

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
