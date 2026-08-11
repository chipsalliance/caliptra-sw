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
#[cfg(feature = "mldsa_attestation")]
mod certify_key_extended_mldsa;
pub mod dice;
mod disable;
mod dpe_crypto;
mod dpe_platform;
mod drivers;
pub mod fips;
mod get_fmc_alias_csr;
mod get_idev_csr;
#[cfg(feature = "mldsa_attestation")]
mod get_pq_csr;
#[cfg(feature = "mldsa_attestation")]
mod get_pq_info;
pub mod handoff;
mod hmac;
pub mod info;
mod invoke_dpe;
pub mod mbox_response_writer;
mod pcr;
mod populate_idev;
#[cfg(feature = "mldsa_attestation")]
mod populate_pq;
mod reallocate_dpe_context_limits;
mod revoke_exported_cdi_handle;
mod set_auth_manifest;
#[cfg(feature = "mldsa_attestation")]
mod set_pq_seed;
mod sign_with_exported_ecdsa;
#[cfg(feature = "mldsa_attestation")]
mod sign_with_exported_mldsa;
mod stash_measurement;
mod subject_alt_name;
mod update;
mod verify;

// Used by runtime tests
pub mod mailbox;
use arrayvec::ArrayVec;
use authorize_and_stash::AuthorizeAndStashCmd;
use caliptra_cfi_lib::{
    cfi_assert, cfi_assert_bool, cfi_assert_eq, cfi_assert_ne, cfi_launder, CfiCounter,
};
#[cfg(feature = "mldsa_attestation")]
use caliptra_drivers::sha384::DpeHasher;
pub use drivers::{Drivers, PauserPrivileges};
use mailbox::Mailbox;

use crate::capabilities::CapabilitiesCmd;
pub use crate::certify_key_extended::CertifyKeyExtendedCmd;
#[cfg(feature = "mldsa_attestation")]
pub use crate::certify_key_extended_mldsa::CertifyKeyExtendedMldsa87Cmd;
#[cfg(feature = "mldsa_attestation")]
pub use crate::get_pq_csr::GetPqCsrCmd;
#[cfg(feature = "mldsa_attestation")]
pub use crate::get_pq_info::GetPqInfoCmd;
pub use crate::hmac::Hmac;
pub use crate::invoke_dpe::CaliptraDpeProfile;
#[cfg(feature = "mldsa_attestation")]
pub use crate::invoke_dpe::InvokeDpeMldsa87Cmd;
use crate::revoke_exported_cdi_handle::RevokeExportedCdiHandleCmd;
use crate::sign_with_exported_ecdsa::SignWithExportedEcdsaCmd;
#[cfg(feature = "mldsa_attestation")]
use crate::sign_with_exported_mldsa::SignWithExportedMldsaCmd;
pub use crate::subject_alt_name::AddSubjectAltNameCmd;
pub use authorize_and_stash::{IMAGE_AUTHORIZED, IMAGE_HASH_MISMATCH, IMAGE_NOT_AUTHORIZED};
pub use caliptra_common::fips::FipsVersionCmd;
use crypto::CryptoSuite;
#[cfg(feature = "mldsa_attestation")]
use dice::PqCertCmd;
pub use dice::{GetFmcAliasCertCmd, GetLdevCertCmd, IDevIdCertCmd};
pub use disable::DisableAttestationCmd;
pub use dpe::State;
use dpe_crypto::DpeCrypto;
pub use dpe_platform::{DpePlatform, VENDOR_ID, VENDOR_SKU};
pub use fips::FipsShutdownCmd;
#[cfg(feature = "fips_self_test")]
pub use fips::{fips_self_test_cmd, fips_self_test_cmd::SelfTestStatus};
use platform::{Platform, MAX_OTHER_NAME_SIZE};
pub use populate_idev::PopulateIDevIdCertCmd;
#[cfg(feature = "mldsa_attestation")]
pub use populate_pq::PopulatePqCertCmd;

pub use get_fmc_alias_csr::GetFmcAliasCsrCmd;
pub use get_idev_csr::GetIdevCsrCmd;
pub use info::{FwInfoCmd, IDevIdInfoCmd};
pub use invoke_dpe::InvokeDpeCmd;
pub use mbox_response_writer::MboxResponseWriter;
pub use pcr::{GetPcrLogCmd, IncrementPcrResetCounterCmd};
pub use reallocate_dpe_context_limits::ReallocateDpeContextLimitsCmd;
pub use set_auth_manifest::SetAuthManifestCmd;
#[cfg(feature = "mldsa_attestation")]
pub use set_pq_seed::SetPqSeedCmd;
pub use stash_measurement::StashMeasurementCmd;
#[cfg(feature = "mldsa_attestation")]
pub use verify::Mldsa87VerifyCmd;
pub use verify::{EcdsaVerifyCmd, LmsVerifyCmd};
pub mod packet;
use caliptra_common::mailbox_api::{op, CommandId, MailboxReqHeader, MailboxRespHeader};
use packet::{copy_from_mbox, copy_to_mbox};
use zerocopy::{FromZeros, IntoBytes};
pub mod tagging;
use tagging::{GetTaggedTciCmd, TagTciCmd};

use caliptra_common::cprintln;

use caliptra_drivers::{CaliptraError, CaliptraResult, ResetReason};
use caliptra_registers::mbox::enums::MboxStatusE;
pub use dpe::{context::ContextState, tci::TciMeasurement, DpeInstance, U8Bool, MAX_HANDLES};
use dpe::{dpe_instance::DpeEnv, support::Support};

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

// Consists of public key (2592 bytes), signature (4627 bytes), and
// some additional room for the rest of the TBS.
#[cfg(feature = "mldsa_attestation")]
pub const MAX_MLDSA_CERT_CHAIN_SIZE: usize = 8192;

pub const PL0_PAUSER_FLAG: u32 = 1;
pub const PL0_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD: usize = 16;
pub const PL1_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD: usize = 16;
pub const PL0_DPE_ACTIVE_CONTEXT_THRESHOLD_MIN: usize = 2;

pub const CALIPTRA_LOCALITY: u32 = 0xFFFFFFFF;
const RESERVED_PAUSER: u32 = CALIPTRA_LOCALITY;

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

/// Handles the pending mailbox command and writes the response back to the mailbox.
///
/// # Returns
///
/// * `MboxStatusE` - the mailbox status (DataReady when we send a response)
#[inline(never)]
fn handle_command(drivers: &mut Drivers) -> CaliptraResult<MboxStatusE> {
    // Drop all commands for invalid PAUSER
    if drivers.mbox.user() == RESERVED_PAUSER {
        return Err(CaliptraError::RUNTIME_CMD_RESERVED_PAUSER);
    }

    // For firmware update, don't read data from the mailbox
    if drivers.mbox.cmd() == CommandId::FIRMWARE_LOAD {
        cfi_assert_eq(
            u32::from(drivers.mbox.cmd()),
            u32::from(CommandId::FIRMWARE_LOAD),
        );
        update::handle_impactless_update(drivers)?;

        // If the handler succeeds but does not invoke reset that is
        // unexpected. Denote that the update failed.
        return Err(CaliptraError::RUNTIME_UNEXPECTED_UPDATE_RETURN);
    } else {
        cfi_assert_ne(
            u32::from(drivers.mbox.cmd()),
            u32::from(CommandId::FIRMWARE_LOAD),
        );
    }

    let Some(opcode) = drivers.mbox.cmd().to_opcode() else {
        return Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND);
    };

    // Handle the request; each arm writes its response directly to MBOX SRAM.
    // Commands whose handler is feature-gated off fall through to the wildcard.
    match opcode {
        op::GET_IDEV_CERT => IDevIdCertCmd::execute(drivers),
        #[cfg(feature = "mldsa_attestation")]
        op::GET_PQ_CERT => PqCertCmd::execute(drivers),
        op::GET_IDEV_INFO => {
            copy_from_mbox(drivers, MailboxReqHeader::new_zeroed().as_mut_bytes())?;
            IDevIdInfoCmd::execute(drivers)
        }
        op::GET_LDEV_CERT => GetLdevCertCmd::execute(drivers),
        op::INVOKE_DPE => InvokeDpeCmd::execute(drivers),
        op::ECDSA384_VERIFY => EcdsaVerifyCmd::execute(drivers),
        op::LMS_VERIFY => LmsVerifyCmd::execute(drivers),
        #[cfg(feature = "mldsa_attestation")]
        op::MLDSA87_SIGNATURE_VERIFY => Mldsa87VerifyCmd::execute(drivers),
        op::EXTEND_PCR => ExtendPcrCmd::execute(drivers),
        op::STASH_MEASUREMENT => StashMeasurementCmd::execute(drivers),
        op::DISABLE_ATTESTATION => {
            copy_from_mbox(drivers, MailboxReqHeader::new_zeroed().as_mut_bytes())?;
            DisableAttestationCmd::execute(drivers)?;
            copy_to_mbox(drivers, MailboxRespHeader::default().as_mut_bytes())
        }
        op::FW_INFO => {
            copy_from_mbox(drivers, MailboxReqHeader::new_zeroed().as_mut_bytes())?;
            FwInfoCmd::execute(drivers)
        }
        op::DPE_TAG_TCI => TagTciCmd::execute(drivers),
        op::DPE_GET_TAGGED_TCI => GetTaggedTciCmd::execute(drivers),
        op::POPULATE_IDEV_CERT => PopulateIDevIdCertCmd::execute(drivers),
        #[cfg(feature = "mldsa_attestation")]
        op::POPULATE_PQ_CERT => PopulatePqCertCmd::execute(drivers),
        op::GET_FMC_ALIAS_CERT => GetFmcAliasCertCmd::execute(drivers),
        op::GET_RT_ALIAS_CERT => GetRtAliasCertCmd::execute(drivers),
        op::ADD_SUBJECT_ALT_NAME => AddSubjectAltNameCmd::execute(drivers),
        op::CERTIFY_KEY_EXTENDED => CertifyKeyExtendedCmd::execute(drivers),
        op::INCREMENT_PCR_RESET_COUNTER => IncrementPcrResetCounterCmd::execute(drivers),
        op::QUOTE_PCRS => GetPcrQuoteCmd::execute(drivers),
        op::VERSION => {
            copy_from_mbox(drivers, MailboxReqHeader::new_zeroed().as_mut_bytes())?;
            let mut resp = FipsVersionCmd::execute(&drivers.soc_ifc)?;
            copy_to_mbox(drivers, resp.as_mut_bytes())
        }
        op::CAPABILITIES => {
            copy_from_mbox(drivers, MailboxReqHeader::new_zeroed().as_mut_bytes())?;
            CapabilitiesCmd::execute(drivers)
        }
        #[cfg(feature = "fips_self_test")]
        op::SELF_TEST_START => {
            copy_from_mbox(drivers, MailboxReqHeader::new_zeroed().as_mut_bytes())?;
            match drivers.self_test_status {
                SelfTestStatus::Idle => {
                    drivers.self_test_status =
                        SelfTestStatus::InProgress(fips_self_test_cmd::execute);
                    copy_to_mbox(drivers, MailboxRespHeader::default().as_mut_bytes())
                }
                _ => Err(CaliptraError::RUNTIME_SELF_TEST_IN_PROGRESS),
            }
        }
        #[cfg(feature = "fips_self_test")]
        op::SELF_TEST_GET_RESULTS => {
            copy_from_mbox(drivers, MailboxReqHeader::new_zeroed().as_mut_bytes())?;
            match drivers.self_test_status {
                SelfTestStatus::Done => {
                    drivers.self_test_status = SelfTestStatus::Idle;
                    copy_to_mbox(drivers, MailboxRespHeader::default().as_mut_bytes())
                }
                _ => Err(CaliptraError::RUNTIME_SELF_TEST_NOT_STARTED),
            }
        }
        op::SHUTDOWN => {
            copy_from_mbox(drivers, MailboxReqHeader::new_zeroed().as_mut_bytes())?;
            FipsShutdownCmd::execute(drivers)
        }
        op::SET_AUTH_MANIFEST => SetAuthManifestCmd::execute(drivers),
        #[cfg(feature = "mldsa_attestation")]
        op::SET_PQ_SEED => SetPqSeedCmd::execute(drivers),
        #[cfg(feature = "mldsa_attestation")]
        op::INVOKE_DPE_MLDSA87 => InvokeDpeMldsa87Cmd::execute(drivers),
        #[cfg(feature = "mldsa_attestation")]
        op::GET_PQ_CSR => GetPqCsrCmd::execute(drivers),
        #[cfg(feature = "mldsa_attestation")]
        op::GET_PQ_INFO => GetPqInfoCmd::execute(drivers),
        #[cfg(feature = "mldsa_attestation")]
        op::CERTIFY_KEY_EXTENDED_MLDSA87 => CertifyKeyExtendedMldsa87Cmd::execute(drivers),
        op::AUTHORIZE_AND_STASH => AuthorizeAndStashCmd::execute(drivers),
        op::GET_IDEV_CSR => GetIdevCsrCmd::execute(drivers),
        op::GET_FMC_ALIAS_CSR => GetFmcAliasCsrCmd::execute(drivers),
        op::GET_PCR_LOG => {
            copy_from_mbox(drivers, MailboxReqHeader::new_zeroed().as_mut_bytes())?;
            GetPcrLogCmd::execute(drivers)
        }
        op::SIGN_WITH_EXPORTED_ECDSA => SignWithExportedEcdsaCmd::execute(drivers),
        op::REVOKE_EXPORTED_CDI_HANDLE => RevokeExportedCdiHandleCmd::execute(drivers),
        #[cfg(feature = "mldsa_attestation")]
        op::SIGN_WITH_EXPORTED_MLDSA => SignWithExportedMldsaCmd::execute(drivers),
        op::REALLOCATE_DPE_CONTEXT_LIMITS => ReallocateDpeContextLimitsCmd::execute(drivers),
        _ => return Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
    }?;

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
    let command_was_running = drivers.persistent_data.get().runtime_cmd_active.get();
    if command_was_running {
        let reset_reason = drivers.soc_ifc.reset_reason();
        if reset_reason == ResetReason::WarmReset {
            cfi_assert_eq(drivers.soc_ifc.reset_reason(), ResetReason::WarmReset);
            let result = DisableAttestationCmd::execute(drivers);
            if cfi_launder(result.is_ok()) {
                cfi_assert!(result.is_ok());
            } else {
                cfi_assert!(result.is_err());
            }
            match result {
                Ok(_) => {
                    cprintln!("Disabled attest - cmd busy + warm rst");
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
        cfi_assert!(!command_was_running);
    }
    #[cfg(feature = "riscv")]
    setup_mailbox_wfi(drivers);
    caliptra_common::wdt::stop_wdt(&mut drivers.soc_ifc);
    loop {
        if drivers.is_shutdown {
            return Err(CaliptraError::RUNTIME_SHUTDOWN);
        }

        // No command is executing, set the mailbox flow done to true before beginning idle.
        drivers.soc_ifc.flow_status_set_mailbox_flow_done(true);
        drivers.persistent_data.get_mut().runtime_cmd_active = U8Bool::new(false);

        enter_idle(drivers);

        // Random delay for CFI glitch protection.
        CfiCounter::delay();

        // The hardware will set this interrupt high when the mbox_fsm_ps
        // transitions to state MBOX_EXECUTE_UC (same state as mbox.is_cmd_ready()),
        // but once cleared will not set it high again until the state
        // transitions away from MBOX_EXECUTE_UC and back.
        let cmd_ready = drivers.soc_ifc.has_mbox_notif_status();
        if cmd_ready {
            // We have woken from idle and have a command ready, set the mailbox flow done to false until we return to
            // idle.
            drivers.soc_ifc.flow_status_set_mailbox_flow_done(false);
            drivers.persistent_data.get_mut().runtime_cmd_active = U8Bool::new(true);

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
            let commmand_result = handle_command(drivers);
            if cfi_launder(commmand_result.is_ok()) {
                cfi_assert!(commmand_result.is_ok());
            } else {
                cfi_assert!(commmand_result.is_err());
            }
            match commmand_result {
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
}

pub struct CaliptraDpeEnv<'a> {
    crypto: DpeCrypto<'a>,
    platform: DpePlatform<'a>,
    state: &'a mut State,
}

impl DpeEnv for CaliptraDpeEnv<'_> {
    fn crypto(&mut self) -> &mut dyn CryptoSuite {
        &mut self.crypto
    }
    fn platform(&mut self) -> &mut dyn Platform {
        &mut self.platform
    }
    fn state(&mut self) -> &mut State {
        self.state
    }
    fn get(&mut self) -> (&mut dyn CryptoSuite, &mut dyn Platform, &mut State) {
        (&mut self.crypto, &mut self.platform, self.state)
    }
}

#[inline(never)]
fn ec_dpe_env(
    drivers: &mut Drivers,
    dmtf_device_info: Option<ArrayVec<u8, { MAX_OTHER_NAME_SIZE }>>,
    ueid: Option<[u8; 17]>,
) -> CaliptraResult<CaliptraDpeEnv<'_>> {
    let hashed_rt_pub_key = drivers.compute_rt_alias_sn()?;
    let pdata = drivers.persistent_data.get_mut();
    let crypto = crate::dpe_crypto::new_ec_dpe_crypto(
        &mut drivers.sha384,
        &mut drivers.trng,
        &mut drivers.ecc384,
        &mut drivers.hmac384,
        &mut drivers.key_vault,
        &pdata.fht,
        &mut pdata.exported_cdi_slots,
    )?;
    let pl0_pauser = pdata.manifest1.header.pl0_pauser;
    let (nb, nf) = Drivers::get_cert_validity_info(&pdata.manifest1);
    Ok(CaliptraDpeEnv {
        crypto,
        platform: DpePlatform::new(
            CaliptraDpeProfile::Ecc384,
            pl0_pauser,
            hashed_rt_pub_key,
            &drivers.cert_chain,
            nb,
            nf,
            dmtf_device_info,
            ueid,
        ),
        state: &mut pdata.dpe,
    })
}

#[cfg(feature = "mldsa_attestation")]
#[inline(never)]
fn mldsa_dpe_env(
    drivers: &mut Drivers,
    dmtf_device_info: Option<ArrayVec<u8, { MAX_OTHER_NAME_SIZE }>>,
    ueid: Option<[u8; 17]>,
) -> CaliptraResult<CaliptraDpeEnv<'_>> {
    let digest = drivers.persistent_data.get().pq_devid_pub_key_digest()?;
    let pdata = drivers.persistent_data.get_mut();
    let pq_devid_cdi = pdata.pq_devid_cdi()?;
    let crypto = DpeCrypto::new_mldsa87(
        crate::dpe_crypto::CryptoEngines {
            hasher: DpeHasher::new(&mut drivers.sha384)?,
            trng: &mut drivers.trng,
            ecc384: &mut drivers.ecc384,
            hmac384: &mut drivers.hmac384,
            key_vault: &mut drivers.key_vault,
        },
        pq_devid_cdi,
        &mut pdata.exported_cdi_slots,
        &mut pdata.mldsa_exported_cdi_slots,
    )?;
    let pl0_pauser = pdata.manifest1.header.pl0_pauser;
    let (nb, nf) = Drivers::get_cert_validity_info(&pdata.manifest1);
    Ok(CaliptraDpeEnv {
        crypto,
        platform: DpePlatform::new(
            CaliptraDpeProfile::Mldsa,
            pl0_pauser,
            digest.into(),
            &drivers.mldsa_cert_chain,
            nb,
            nf,
            dmtf_device_info,
            ueid,
        ),
        state: &mut pdata.dpe,
    })
}
