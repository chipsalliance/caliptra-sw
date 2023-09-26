// Licensed under the Apache-2.0 license
#![cfg_attr(not(feature = "fip-self-test"), allow(unused))]
#![no_std]
pub mod dice;
mod disable;
mod dpe_crypto;
mod dpe_platform;
mod drivers;
pub mod fips;
pub mod handoff;
pub mod info;
mod invoke_dpe;
mod pcr;
mod stash_measurement;
mod update;
mod verify;

// Used by runtime tests
pub mod mailbox;
pub use drivers::Drivers;
use mailbox::Mailbox;

pub use caliptra_common::fips::FipsVersionCmd;
#[cfg(feature = "test_only_commands")]
pub use dice::{GetLdevCertCmd, TestGetFmcAliasCertCmd};
pub use disable::DisableAttestationCmd;
use dpe_crypto::DpeCrypto;
pub use dpe_platform::{DpePlatform, VENDOR_ID, VENDOR_SKU};
pub use fips::FipsShutdownCmd;
#[cfg(feature = "fips_self_test")]
pub use fips::{fips_self_test_cmd, fips_self_test_cmd::SelfTestStatus};

pub use info::{FwInfoCmd, IDevIdCertCmd, IDevIdInfoCmd};
pub use invoke_dpe::InvokeDpeCmd;
pub use pcr::{GetPcrQuoteCmd, IncrementPcrResetCounter, PcrResetCounter};
pub use stash_measurement::StashMeasurementCmd;
pub use verify::EcdsaVerifyCmd;
pub mod packet;
use caliptra_common::mailbox_api::CommandId;
use packet::Packet;

use caliptra_common::cprintln;
#[cfg(feature = "fips_self_test")]
use caliptra_common::mailbox_api::MailboxResp;

use caliptra_drivers::{CaliptraError, CaliptraResult, ResetReason};
use caliptra_registers::mbox::enums::MboxStatusE;
use dpe::{
    commands::{CommandExecution, DeriveChildCmd, DeriveChildFlags},
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    support::Support,
    DPE_PROFILE,
};

#[cfg(feature = "test_only_commands")]
use crate::verify::HmacVerifyCmd;

const RUNTIME_BOOT_STATUS_BASE: u32 = 0x600;

/// Statuses used by ROM to log dice derivation progress.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RtBootStatus {
    // RtAlias Statuses
    RtReadyForCommands = RUNTIME_BOOT_STATUS_BASE,
    RtFipSelfTestStarted = RUNTIME_BOOT_STATUS_BASE + 1,
    RtFipSelfTestComplete = RUNTIME_BOOT_STATUS_BASE + 2,
}

impl From<RtBootStatus> for u32 {
    /// Converts to this type from the input type.
    fn from(status: RtBootStatus) -> u32 {
        status as u32
    }
}

pub const DPE_SUPPORT: Support = Support::all();
pub const MAX_CERT_CHAIN_SIZE: usize = 4096;

pub struct CptraDpeTypes;

impl DpeTypes for CptraDpeTypes {
    type Crypto<'a> = DpeCrypto<'a>;
    type Platform<'a> = DpePlatform<'a>;
}

/// Run pending jobs and enter low power mode.
fn enter_idle(drivers: &mut Drivers) {
    // Run pending jobs before entering low power mode.
    #[cfg(feature = "fips_self_test")]
    if let SelfTestStatus::InProgress(execute) = drivers.self_test_status {
        if drivers.mbox.lock() == false {
            match execute(drivers) {
                Ok(_) => drivers.self_test_status = SelfTestStatus::Done,
                Err(e) => caliptra_drivers::report_fw_error_non_fatal(e.into()),
            }
        }
    }

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
    if drivers.mbox.cmd() == CommandId::FIRMWARE_LOAD {
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
        CommandId::GET_IDEV_CERT => IDevIdCertCmd::execute(cmd_bytes),
        CommandId::GET_IDEV_CSR => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        CommandId::GET_IDEV_INFO => IDevIdInfoCmd::execute(drivers),
        CommandId::GET_LDEV_CERT => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        CommandId::INCREMENT_PCR_RESET_COUNTER => {
            IncrementPcrResetCounter::execute(drivers, cmd_bytes)
        }
        CommandId::INVOKE_DPE => InvokeDpeCmd::execute(drivers, cmd_bytes),
        CommandId::QUOTE_PCRS => GetPcrQuoteCmd::execute(drivers, cmd_bytes),
        CommandId::ECDSA384_VERIFY => EcdsaVerifyCmd::execute(drivers, cmd_bytes),
        CommandId::STASH_MEASUREMENT => StashMeasurementCmd::execute(drivers, cmd_bytes),
        CommandId::DISABLE_ATTESTATION => DisableAttestationCmd::execute(drivers),
        CommandId::FW_INFO => FwInfoCmd::execute(drivers),
        #[cfg(feature = "test_only_commands")]
        CommandId::TEST_ONLY_GET_LDEV_CERT => GetLdevCertCmd::execute(drivers),
        #[cfg(feature = "test_only_commands")]
        CommandId::TEST_ONLY_GET_FMC_ALIAS_CERT => TestGetFmcAliasCertCmd::execute(drivers),
        #[cfg(feature = "test_only_commands")]
        CommandId::TEST_ONLY_HMAC384_VERIFY => HmacVerifyCmd::execute(drivers, cmd_bytes),
        CommandId::VERSION => FipsVersionCmd::execute(&drivers.soc_ifc),
        #[cfg(feature = "fips_self_test")]
        CommandId::SELF_TEST_START => match drivers.self_test_status {
            SelfTestStatus::Idle => {
                drivers.self_test_status = SelfTestStatus::InProgress(fips_self_test_cmd::execute);
                Ok(MailboxResp::default())
            }
            _ => Err(CaliptraError::RUNTIME_SELF_TEST_IN_PROGRESS),
        },
        #[cfg(feature = "fips_self_test")]
        CommandId::SELF_TEST_GET_RESULTS => match drivers.self_test_status {
            SelfTestStatus::Done => {
                drivers.self_test_status = SelfTestStatus::Idle;
                Ok(MailboxResp::default())
            }
            _ => Err(CaliptraError::RUNTIME_SELF_TEST_NOT_STARTED),
        },
        CommandId::SHUTDOWN => FipsShutdownCmd::execute(drivers),
        _ => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
    }?;

    // Send the response
    Packet::copy_to_mbox(drivers, &mut resp)?;

    Ok(MboxStatusE::DataReady)
}

pub fn handle_mailbox_commands(drivers: &mut Drivers) -> CaliptraResult<()> {
    // Indicator to SOC that RT firmware is ready
    drivers.soc_ifc.assert_ready_for_runtime();
    caliptra_drivers::report_boot_status(RtBootStatus::RtReadyForCommands.into());
    // Disable attestation if in the middle of executing an mbox cmd during warm reset
    if drivers.mbox.cmd_busy() {
        let reset_reason = drivers.soc_ifc.reset_reason();
        if reset_reason == ResetReason::WarmReset {
            let mut result = DisableAttestationCmd::execute(drivers);
            match result {
                Ok(_) => cprintln!("Disabled attestation due to cmd busy during warm reset"),
                Err(e) => {
                    cprintln!("{}", e.0);
                    return Err(CaliptraError::RUNTIME_GLOBAL_EXCEPTION);
                }
            }
        }
    }
    loop {
        enter_idle(drivers);
        if drivers.is_shutdown {
            return Err(CaliptraError::RUNTIME_SHUTDOWN);
        }

        if drivers.mbox.is_cmd_ready() {
            // TODO : Move start/stop WDT to wait_for_cmd when NMI is implemented.
            caliptra_common::wdt::start_wdt(
                &mut drivers.soc_ifc,
                caliptra_common::WdtTimeout::default(),
            );
            caliptra_drivers::report_fw_error_non_fatal(0);
            match handle_command(drivers) {
                Ok(status) => {
                    drivers.mbox.set_status(status);
                }
                Err(e) => {
                    caliptra_drivers::report_fw_error_non_fatal(e.into());
                    drivers.mbox.set_status(MboxStatusE::CmdFailure);
                }
            }
            caliptra_common::wdt::stop_wdt(&mut drivers.soc_ifc);
        }
    }
    Ok(())
}
