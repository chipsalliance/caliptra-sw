/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains exports for the Runtime library and mailbox command handling logic.

--*/
#![cfg_attr(not(feature = "fips_self_test"), allow(unused))]
#![no_std]
mod authorize_and_stash;
mod capabilities;
mod certify_key_extended;
mod cryptographic_mailbox;
pub mod dice;
mod disable;
mod dpe_crypto;
mod dpe_platform;
mod drivers;
pub mod fips;
mod get_fmc_alias_csr;
mod get_idev_csr;
mod get_image_info;
pub mod handoff;
mod hmac;
pub mod info;
mod invoke_dpe;
pub mod key_ladder;
pub mod manifest;
mod pcr;
mod populate_idev;
mod recovery_flow;
mod revoke_exported_cdi_handle;
mod set_auth_manifest;
mod sign_with_exported_ecdsa;
mod stash_measurement;
mod subject_alt_name;
mod update;
mod verify;

// Used by runtime tests
pub mod mailbox;
use authorize_and_stash::AuthorizeAndStashCmd;
use caliptra_cfi_lib_git::{cfi_assert, cfi_assert_eq, cfi_assert_ne, cfi_launder, CfiCounter};
use caliptra_common::cfi_check;
pub use drivers::{Drivers, PauserPrivileges};
use mailbox::Mailbox;

use crate::capabilities::CapabilitiesCmd;
pub use crate::certify_key_extended::CertifyKeyExtendedCmd;
pub use crate::hmac::Hmac;
use crate::revoke_exported_cdi_handle::RevokeExportedCdiHandleCmd;
use crate::sign_with_exported_ecdsa::SignWithExportedEcdsaCmd;
pub use crate::subject_alt_name::AddSubjectAltNameCmd;
pub use authorize_and_stash::{IMAGE_AUTHORIZED, IMAGE_HASH_MISMATCH, IMAGE_NOT_AUTHORIZED};
pub use caliptra_common::fips::FipsVersionCmd;
pub use dice::{GetFmcAliasCertCmd, GetLdevCertCmd, IDevIdCertCmd};
pub use disable::DisableAttestationCmd;
use dpe_crypto::DpeCrypto;
pub use dpe_platform::{DpePlatform, VENDOR_ID, VENDOR_SKU};
pub use fips::FipsShutdownCmd;
#[cfg(feature = "fips_self_test")]
pub use fips::{fips_self_test_cmd, fips_self_test_cmd::SelfTestStatus};
pub use populate_idev::PopulateIDevIdCertCmd;

pub use get_fmc_alias_csr::GetFmcAliasCsrCmd;
pub use get_idev_csr::{GetIdevCsrCmd, GetIdevMldsaCsrCmd};
pub use get_image_info::GetImageInfoCmd;
pub use info::{FwInfoCmd, IDevIdInfoCmd};
pub use invoke_dpe::InvokeDpeCmd;
pub use key_ladder::KeyLadder;
pub use pcr::IncrementPcrResetCounterCmd;
pub use set_auth_manifest::SetAuthManifestCmd;
pub use stash_measurement::StashMeasurementCmd;
pub use verify::{EcdsaVerifyCmd, LmsVerifyCmd};
pub mod packet;
use caliptra_common::mailbox_api::{AlgorithmType, CommandId, MailboxResp};
use packet::Packet;
pub mod tagging;
use tagging::{GetTaggedTciCmd, TagTciCmd};

use caliptra_common::cprintln;

use caliptra_drivers::{okmutref, CaliptraError, CaliptraResult, ResetReason};
use caliptra_registers::mbox::enums::MboxStatusE;
pub use dpe::{context::ContextState, tci::TciMeasurement, DpeInstance, U8Bool, MAX_HANDLES};
use dpe::{
    dpe_instance::{DpeEnv, DpeTypes},
    support::Support,
};

use crate::{
    dice::GetRtAliasCertCmd,
    pcr::{ExtendPcrCmd, GetPcrQuoteCmd},
};

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

pub const PL0_PAUSER_FLAG: u32 = 1;
pub const PL0_DPE_ACTIVE_CONTEXT_THRESHOLD: usize = 16;
pub const PL1_DPE_ACTIVE_CONTEXT_THRESHOLD: usize = 16;

const RESERVED_PAUSER: u32 = 0xFFFFFFFF;

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
        let lock = drivers.mbox.lock();
        if !lock {
            let result = execute(drivers);
            drivers.mbox.unlock();
            match result {
                Ok(_) => drivers.self_test_status = SelfTestStatus::Done,
                Err(e) => caliptra_common::handle_fatal_error(e.into()),
            }
        } else {
            cfi_assert!(lock);
            // Don't enter low power mode when in progress
            return;
        }
    }

    #[cfg(feature = "riscv")]
    caliptra_cpu::csr::mpmc_halt_and_enable_interrupts();
}

/// Handles the pending mailbox command and writes the repsonse back to the mailbox
///
/// # Returns
///
/// * `MboxStatusE` - the mailbox status (DataReady when we send a response)
fn handle_command(drivers: &mut Drivers) -> CaliptraResult<MboxStatusE> {
    // Drop all commands for invalid PAUSER
    if drivers.mbox.id() == RESERVED_PAUSER {
        return Err(CaliptraError::RUNTIME_CMD_RESERVED_PAUSER);
    }

    // For firmware update, don't read data from the mailbox
    if drivers.mbox.cmd() == CommandId::FIRMWARE_LOAD {
        cfi_assert_eq(drivers.mbox.cmd(), CommandId::FIRMWARE_LOAD);
        update::handle_impactless_update(drivers)?;

        // If the handler succeeds but does not invoke reset that is
        // unexpected. Denote that the update failed.
        return Err(CaliptraError::RUNTIME_UNEXPECTED_UPDATE_RETURN);
    } else {
        cfi_assert_ne(drivers.mbox.cmd(), CommandId::FIRMWARE_LOAD);
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
        CommandId::GET_IDEV_ECC384_CERT => IDevIdCertCmd::execute(cmd_bytes, AlgorithmType::Ecc384),
        CommandId::GET_IDEV_INFO => IDevIdInfoCmd::execute(drivers),
        CommandId::GET_LDEV_ECC384_CERT => GetLdevCertCmd::execute(drivers, AlgorithmType::Ecc384),
        CommandId::INVOKE_DPE => InvokeDpeCmd::execute(drivers, cmd_bytes),
        CommandId::ECDSA384_VERIFY => EcdsaVerifyCmd::execute(drivers, cmd_bytes),
        CommandId::LMS_VERIFY => LmsVerifyCmd::execute(drivers, cmd_bytes),
        CommandId::EXTEND_PCR => ExtendPcrCmd::execute(drivers, cmd_bytes),
        CommandId::STASH_MEASUREMENT => StashMeasurementCmd::execute(drivers, cmd_bytes),
        CommandId::DISABLE_ATTESTATION => DisableAttestationCmd::execute(drivers),
        CommandId::FW_INFO => FwInfoCmd::execute(drivers),
        CommandId::DPE_TAG_TCI => TagTciCmd::execute(drivers, cmd_bytes),
        CommandId::DPE_GET_TAGGED_TCI => GetTaggedTciCmd::execute(drivers, cmd_bytes),
        CommandId::POPULATE_IDEV_CERT => PopulateIDevIdCertCmd::execute(drivers, cmd_bytes),
        CommandId::GET_FMC_ALIAS_ECC384_CERT => {
            GetFmcAliasCertCmd::execute(drivers, AlgorithmType::Ecc384)
        }
        CommandId::GET_RT_ALIAS_ECC384_CERT => {
            GetRtAliasCertCmd::execute(drivers, AlgorithmType::Ecc384)
        }
        // MLDSA87 versions
        CommandId::GET_IDEV_MLDSA87_CERT => {
            IDevIdCertCmd::execute(cmd_bytes, AlgorithmType::Mldsa87)
        }
        CommandId::GET_LDEV_MLDSA87_CERT => {
            GetLdevCertCmd::execute(drivers, AlgorithmType::Mldsa87)
        }
        CommandId::GET_FMC_ALIAS_MLDSA87_CERT => {
            GetFmcAliasCertCmd::execute(drivers, AlgorithmType::Mldsa87)
        }
        CommandId::GET_RT_ALIAS_MLDSA87_CERT => {
            GetRtAliasCertCmd::execute(drivers, AlgorithmType::Mldsa87)
        }
        CommandId::ADD_SUBJECT_ALT_NAME => AddSubjectAltNameCmd::execute(drivers, cmd_bytes),
        CommandId::CERTIFY_KEY_EXTENDED => CertifyKeyExtendedCmd::execute(drivers, cmd_bytes),
        CommandId::INCREMENT_PCR_RESET_COUNTER => {
            IncrementPcrResetCounterCmd::execute(drivers, cmd_bytes)
        }
        CommandId::QUOTE_PCRS => GetPcrQuoteCmd::execute(drivers, cmd_bytes),
        CommandId::VERSION => {
            FipsVersionCmd::execute(&drivers.soc_ifc).map(MailboxResp::FipsVersion)
        }
        CommandId::CAPABILITIES => CapabilitiesCmd::execute(),
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
        CommandId::SET_AUTH_MANIFEST => SetAuthManifestCmd::execute(drivers, cmd_bytes),
        CommandId::AUTHORIZE_AND_STASH => AuthorizeAndStashCmd::execute(drivers, cmd_bytes),
        CommandId::GET_IDEV_ECC384_CSR => GetIdevCsrCmd::execute(drivers, cmd_bytes),
        CommandId::GET_IDEV_MLDSA87_CSR => GetIdevMldsaCsrCmd::execute(drivers, cmd_bytes),
        CommandId::GET_FMC_ALIAS_ECC384_CSR => GetFmcAliasCsrCmd::execute(drivers, cmd_bytes),
        CommandId::SIGN_WITH_EXPORTED_ECDSA => {
            SignWithExportedEcdsaCmd::execute(drivers, cmd_bytes)
        }
        CommandId::REVOKE_EXPORTED_CDI_HANDLE => {
            RevokeExportedCdiHandleCmd::execute(drivers, cmd_bytes)
        }
        // Cryptographic mailbox commands
        CommandId::CM_IMPORT => cryptographic_mailbox::Commands::import(drivers, cmd_bytes),
        CommandId::CM_STATUS => cryptographic_mailbox::Commands::status(drivers),
        CommandId::CM_SHA_INIT => cryptographic_mailbox::Commands::sha_init(drivers, cmd_bytes),
        CommandId::CM_SHA_UPDATE => cryptographic_mailbox::Commands::sha_update(drivers, cmd_bytes),
        CommandId::CM_SHA_FINAL => cryptographic_mailbox::Commands::sha_final(drivers, cmd_bytes),
        CommandId::CM_RANDOM_GENERATE => {
            cryptographic_mailbox::Commands::random_generate(drivers, cmd_bytes)
        }
        CommandId::CM_RANDOM_STIR => {
            cryptographic_mailbox::Commands::random_stir(drivers, cmd_bytes)
        }
        CommandId::GET_IMAGE_INFO => GetImageInfoCmd::execute(drivers, cmd_bytes),

        _ => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
    };
    let resp = okmutref(&mut resp)?;

    // Send the response
    Packet::copy_to_mbox(drivers, resp)?;

    Ok(MboxStatusE::DataReady)
}

#[cfg(feature = "riscv")]
// TODO implement in emulator
fn setup_mailbox_wfi(drivers: &mut Drivers) {
    use caliptra_drivers::IntSource;

    caliptra_cpu::csr::mie_enable_external_interrupts();

    // Set highest priority so that Int can wake CPU
    drivers.pic.int_set_max_priority(IntSource::SocIfcNotif);
    drivers.pic.int_enable(IntSource::SocIfcNotif);

    drivers.soc_ifc.enable_mbox_notif_interrupts();
}

/// Handles mailbox commands when the command is ready
pub fn handle_mailbox_commands(drivers: &mut Drivers) -> CaliptraResult<()> {
    // Indicator to SOC that RT firmware is ready
    drivers.soc_ifc.assert_ready_for_runtime();
    caliptra_drivers::report_boot_status(RtBootStatus::RtReadyForCommands.into());
    // Disable attestation if in the middle of executing an mbox cmd during warm reset
    let cmd_busy = drivers.mbox.cmd_busy();
    if cmd_busy {
        let reset_reason = drivers.soc_ifc.reset_reason();
        if reset_reason == ResetReason::WarmReset {
            cfi_assert_eq(drivers.soc_ifc.reset_reason(), ResetReason::WarmReset);
            let result = DisableAttestationCmd::execute(drivers);
            cfi_check!(result);
            match result {
                Ok(_) => {
                    cprintln!("Disabled attestation due to cmd busy during warm reset");
                    caliptra_drivers::report_fw_error_non_fatal(
                        CaliptraError::RUNTIME_CMD_BUSY_DURING_WARM_RESET.into(),
                    );
                }
                Err(e) => {
                    cprintln!("{}", e.0);
                    return Err(CaliptraError::RUNTIME_GLOBAL_EXCEPTION);
                }
            }
        }
    } else {
        cfi_assert!(!cmd_busy);
    }
    #[cfg(feature = "riscv")]
    setup_mailbox_wfi(drivers);
    caliptra_common::wdt::stop_wdt(&mut drivers.soc_ifc);
    loop {
        if drivers.is_shutdown {
            return Err(CaliptraError::RUNTIME_SHUTDOWN);
        }

        enter_idle(drivers);

        // Random delay for CFI glitch protection.
        CfiCounter::delay();

        // The hardware will set this interrupt high when the mbox_fsm_ps
        // transitions to state MBOX_EXECUTE_UC (same state as mbox.is_cmd_ready()),
        // but once cleared will not set it high again until the state
        // transitions away from MBOX_EXECUTE_UC and back.
        let cmd_ready = drivers.soc_ifc.has_mbox_notif_status();
        if cmd_ready {
            // Acknowledge the interrupt so we go back to sleep after
            // processing the mailbox. After this point, if the mailbox is
            // still in the MBOX_EXECUTE_UC state before going back to
            // sleep, we will hang.
            drivers.soc_ifc.clear_mbox_notif_status();

            if !drivers.mbox.is_cmd_ready() {
                // This is expected after boot, as the ROM did not clear the
                // interrupt status when processing FIRMWARE_LOAD
                continue;
            }

            // TODO : Move start/stop WDT to wait_for_cmd when NMI is implemented.
            caliptra_common::wdt::start_wdt(
                &mut drivers.soc_ifc,
                caliptra_common::WdtTimeout::default(),
            );
            caliptra_drivers::report_fw_error_non_fatal(0);
            let command_result = handle_command(drivers);
            cfi_check!(command_result);
            match command_result {
                Ok(status) => {
                    drivers.mbox.set_status(status);
                }
                Err(e) => {
                    caliptra_drivers::report_fw_error_non_fatal(e.into());
                    drivers.mbox.set_status(MboxStatusE::CmdFailure);
                }
            }
            caliptra_common::wdt::stop_wdt(&mut drivers.soc_ifc);
        } else {
            cfi_assert!(!cmd_ready);
        }
    }
    //    Ok(())
}
