/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains exports for the Runtime library and mailbox command handling logic.

--*/
#![cfg_attr(not(feature = "fips_self_test"), allow(unused))]
#![no_std]
mod activate_firmware;
mod attested_csr;
mod authorize_and_stash;
mod capabilities;
mod certify_key_extended;
mod cryptographic_mailbox;
mod debug_unlock;
pub mod dice;
mod disable;
mod dpe_crypto;
mod dpe_platform;
mod drivers;
mod fe_programming;
pub mod fips;
mod firmware_verify;
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
mod reallocate_dpe_context_limits;
mod recovery_flow;
mod revoke_exported_cdi_handle;
mod set_auth_manifest;
mod sign_with_exported_ecdsa;
mod sign_with_exported_mldsa;
mod stash_measurement;
mod subject_alt_name;
mod update;
mod verify;

// Used by runtime tests
pub mod mailbox;
use arrayvec::ArrayVec;
use authorize_and_stash::AuthorizeAndStashCmd;
use caliptra_cfi_lib_git::{cfi_assert, cfi_assert_eq, cfi_assert_ne, cfi_launder, CfiCounter};
use caliptra_common::cfi_check;
use crypto::ecdsa::curve_384::EcdsaPub384;
use crypto::ecdsa::EcdsaPubKey;
use crypto::ml_dsa::MldsaPublicKey;
use crypto::PubKey;
pub use drivers::{Drivers, PauserPrivileges};
use fe_programming::FeProgrammingCmd;
use mailbox::Mailbox;
use platform::MAX_OTHER_NAME_SIZE;
use populate_idev::PopulateIDevIdMldsa87CertCmd;
use zerocopy::{FromBytes, IntoBytes, KnownLayout};

use crate::capabilities::CapabilitiesCmd;
pub use crate::certify_key_extended::CertifyKeyExtendedCmd;
use crate::dpe_crypto::{DpeEcCrypto, DpeMldsaCrypto};
pub use crate::hmac::Hmac;
pub use crate::invoke_dpe::CaliptraDpeProfile;
use crate::revoke_exported_cdi_handle::RevokeExportedCdiHandleCmd;
use crate::sign_with_exported_ecdsa::SignWithExportedEcdsaCmd;
pub use crate::subject_alt_name::AddSubjectAltNameCmd;
pub use activate_firmware::ActivateFirmwareCmd;
pub use authorize_and_stash::{IMAGE_AUTHORIZED, IMAGE_HASH_MISMATCH, IMAGE_NOT_AUTHORIZED};
pub use caliptra_common::fips::FipsVersionCmd;
use caliptra_common::mailbox_api::{populate_checksum, FipsVersionResp};
pub use dice::{GetFmcAliasCertCmd, GetLdevCertCmd, IDevIdCertCmd};
pub use disable::DisableAttestationCmd;
pub use dpe_platform::{DpePlatform, VENDOR_ID, VENDOR_SKU};
pub use fips::FipsShutdownCmd;
#[cfg(feature = "fips_self_test")]
pub use fips::{fips_self_test_cmd, fips_self_test_cmd::SelfTestStatus};
pub use populate_idev::PopulateIDevIdEcc384CertCmd;

pub use get_fmc_alias_csr::GetFmcAliasCsrCmd;
pub use get_idev_csr::{GetIdevCsrCmd, GetIdevMldsaCsrCmd};
pub use get_image_info::GetImageInfoCmd;
pub use info::{FwInfoCmd, IDevIdInfoCmd};
pub use invoke_dpe::InvokeDpeCmd;
pub use key_ladder::KeyLadder;
pub use pcr::{GetPcrLogCmd, IncrementPcrResetCounterCmd};
pub use reallocate_dpe_context_limits::ReallocateDpeContextLimitsCmd;
pub use set_auth_manifest::SetAuthManifestCmd;
pub use stash_measurement::StashMeasurementCmd;
pub use verify::LmsVerifyCmd;
pub mod packet;
use caliptra_common::mailbox_api::{AlgorithmType, CommandId};
use packet::Packet;
pub mod tagging;
use tagging::{GetTaggedTciCmd, TagTciCmd};

use caliptra_common::cprintln;

use caliptra_drivers::{okref, AxiAddr, CaliptraError, CaliptraResult, ResetReason};
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
pub const MAX_ECC_CERT_CHAIN_SIZE: usize = 4096;
pub const MAX_MLDSA_CERT_CHAIN_SIZE: usize = 32 * 1024;

pub const PL0_PAUSER_FLAG: u32 = 1;
pub const PL0_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD: usize = 32;
pub const PL1_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD: usize = 32;
pub const PL0_DPE_ACTIVE_CONTEXT_THRESHOLD_MIN: usize = 2;

pub const CALIPTRA_LOCALITY: u32 = 0xFFFFFFFF;
const RESERVED_PAUSER: u32 = CALIPTRA_LOCALITY;

#[inline(always)]
pub(crate) fn mutrefbytes<R: FromBytes + IntoBytes + KnownLayout>(
    resp: &mut [u8],
) -> CaliptraResult<&mut R> {
    // the error should be impossible but check to avoid panic
    let (resp, _) = R::mut_from_prefix(resp).map_err(|_| CaliptraError::RUNTIME_INTERNAL)?;
    Ok(resp)
}

pub struct CptraDpeEcTypes;

impl DpeTypes for CptraDpeEcTypes {
    type Crypto<'a> = DpeEcCrypto<'a>;
    type Platform<'a> = DpePlatform<'a>;
}

pub struct CptraDpeMldsaTypes;

impl DpeTypes for CptraDpeMldsaTypes {
    type Crypto<'a> = DpeMldsaCrypto<'a>;
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

fn human_readable_command(bytes: &[u8]) -> Option<&str> {
    if bytes.len() == 4 && bytes.iter().all(|c| c.is_ascii_alphanumeric()) {
        // Safety: we just checked that all bytes are ASCII.
        Some(unsafe { core::str::from_utf8_unchecked(bytes) })
    } else {
        None
    }
}

/// Handles the pending mailbox command and writes the repsonse back to the mailbox
///
/// # Returns
///
/// * `MboxStatusE` - the mailbox status (DataReady when we send a response)
#[inline(never)]
fn handle_command(drivers: &mut Drivers) -> CaliptraResult<MboxStatusE> {
    // Drop all commands for invalid PAUSER
    if drivers.mbox.id() == RESERVED_PAUSER {
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

    if drivers.mbox.cmd() == CommandId::FIRMWARE_VERIFY {
        return firmware_verify::FirmwareVerifyCmd::execute(drivers);
    } else {
        cfi_assert_ne(
            u32::from(drivers.mbox.cmd()),
            u32::from(CommandId::FIRMWARE_VERIFY),
        );
    }

    // Get the command bytes
    let req_packet = Packet::get_from_mbox(drivers)?;
    let cmd_bytes = req_packet.as_bytes()?;
    let cmd_id = req_packet.cmd;

    if let Some(ascii) = human_readable_command(&cmd_id.to_be_bytes()) {
        cprintln!(
            "[rt] Received command=0x{:x} ({}), len={}",
            req_packet.cmd,
            ascii,
            req_packet.payload().len()
        );
    } else {
        cprintln!(
            "[rt] Received command=0x{:x}, len={}",
            req_packet.cmd,
            req_packet.payload().len()
        );
    }

    execute_command(drivers, cmd_id, cmd_bytes)
}

/// Size of the staging response buffer used by [`execute_command`] for most
/// mailbox commands. Excludes commands that need a larger response buffer
/// (e.g. `CERTIFY_KEY_EXTENDED_*`, `INVOKE_DPE_*`, `GET_ATTESTED_*_CSR`);
/// those are dispatched through dedicated `#[inline(never)]` functions so
/// their large buffers only exist on the stack for that call path.
const COMMON_RESP_BUF_SIZE: usize = size_of::<caliptra_api::mailbox::VarSizeDataResp>();

const _: () = {
    use caliptra_api::mailbox::*;
    let mut max = 0;
    let sizes = [
        size_of::<MailboxRespHeader>(),
        size_of::<GetIdevCertResp>(),
        size_of::<GetIdevEcc384InfoResp>(),
        size_of::<GetIdevMldsa87InfoResp>(),
        size_of::<GetLdevCertResp>(),
        size_of::<StashMeasurementResp>(),
        size_of::<InvokeDpeResp>(),
        size_of::<GetFmcAliasEcc384CertResp>(),
        size_of::<GetFmcAliasMlDsa87CertResp>(),
        size_of::<FipsVersionResp>(),
        size_of::<FwInfoResp>(),
        size_of::<CapabilitiesResp>(),
        size_of::<GetTaggedTciResp>(),
        size_of::<GetRtAliasCertResp>(),
        size_of::<QuotePcrsEcc384Resp>(),
        size_of::<QuotePcrsMldsa87Resp>(),
        size_of::<AuthorizeAndStashResp>(),
        size_of::<GetIdevCsrResp>(),
        size_of::<GetFmcAliasCsrResp>(),
        size_of::<SignWithExportedEcdsaResp>(),
        size_of::<RevokeExportedCdiHandleResp>(),
        size_of::<GetImageInfoResp>(),
        size_of::<GetPcrLogResp>(),
        size_of::<ReallocateDpeContextLimitsResp>(),
    ];
    let mut i = 0;
    while i < sizes.len() {
        if sizes[i] > max {
            max = sizes[i];
        }
        i += 1;
    }
    assert!(COMMON_RESP_BUF_SIZE >= max);
};

const DPE_RESP_BUF_SIZE: usize = size_of::<caliptra_api::mailbox::CertifyKeyExtendedResp>();

#[inline(never)]
fn execute_command(
    drivers: &mut Drivers,
    cmd_id: u32,
    cmd_bytes: &[u8],
) -> CaliptraResult<MboxStatusE> {
    let cmd = CommandId::from(cmd_id);

    // Commands that need a larger response buffer (or whose heavy work
    // must run without the common response buffer alive on the stack)
    // are dispatched through dedicated `#[inline(never)]` functions so
    // their buffers only exist on the stack for that call path.
    match cmd {
        CommandId::CERTIFY_KEY_EXTENDED_ECC384 => {
            execute_certify_key_extended_ecc384(drivers, cmd_bytes)
        }
        CommandId::CERTIFY_KEY_EXTENDED_MLDSA87 => {
            execute_certify_key_extended_mldsa87(drivers, cmd_bytes)
        }
        CommandId::INVOKE_DPE_ECC384 => execute_invoke_dpe_ecc384(drivers, cmd_bytes),
        CommandId::INVOKE_DPE_MLDSA87 => execute_invoke_dpe_mldsa87(drivers, cmd_bytes),
        CommandId::GET_ATTESTED_ECC384_CSR => {
            attested_csr::AttestedEccCsrCmd::execute(drivers, cmd_bytes)
        }
        CommandId::GET_ATTESTED_MLDSA87_CSR => {
            attested_csr::AttestedMldsaCsrCmd::execute(drivers, cmd_bytes)
        }
        _ => execute_command_with_common_resp(drivers, cmd, cmd_bytes),
    }
}

/// Handles mailbox commands that share the common staging response
/// buffer. Kept as a separate `#[inline(never)]` function so the buffer
/// is only allocated on the stack for these command paths, not for
/// commands dispatched through their own dedicated wrappers.
#[inline(never)]
fn execute_command_with_common_resp(
    drivers: &mut Drivers,
    cmd: CommandId,
    cmd_bytes: &[u8],
) -> CaliptraResult<MboxStatusE> {
    let resp = &mut [0u8; COMMON_RESP_BUF_SIZE][..];

    let len = match cmd {
        CommandId::ACTIVATE_FIRMWARE => {
            activate_firmware::ActivateFirmwareCmd::execute(drivers, cmd_bytes, resp)
        }
        CommandId::FIRMWARE_LOAD => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        CommandId::FIRMWARE_VERIFY => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        CommandId::GET_IDEV_ECC384_CERT => {
            IDevIdCertCmd::execute(cmd_bytes, AlgorithmType::Ecc384, resp)
        }
        CommandId::GET_IDEV_ECC384_INFO => {
            IDevIdInfoCmd::execute(drivers, AlgorithmType::Ecc384, resp)
        }

        CommandId::GET_IDEV_MLDSA87_INFO => {
            IDevIdInfoCmd::execute(drivers, AlgorithmType::Mldsa87, resp)
        }

        CommandId::GET_IDEV_MLDSA87_CERT => {
            IDevIdCertCmd::execute(cmd_bytes, AlgorithmType::Mldsa87, resp)
        }
        CommandId::GET_LDEV_ECC384_CERT => {
            GetLdevCertCmd::execute(drivers, AlgorithmType::Ecc384, resp)
        }
        CommandId::GET_LDEV_MLDSA87_CERT => {
            GetLdevCertCmd::execute(drivers, AlgorithmType::Mldsa87, resp)
        }
        // INVOKE_DPE_{ECC384,MLDSA87} are dispatched earlier (see above).
        CommandId::ECDSA384_SIGNATURE_VERIFY => {
            caliptra_common::verify::EcdsaVerifyCmd::execute(&mut drivers.ecc384, cmd_bytes)
        }
        CommandId::LMS_SIGNATURE_VERIFY => LmsVerifyCmd::execute(drivers, cmd_bytes),
        CommandId::MLDSA87_SIGNATURE_VERIFY => {
            caliptra_common::verify::MldsaVerifyCmd::execute(&mut drivers.mldsa87, cmd_bytes)
        }
        CommandId::EXTEND_PCR => ExtendPcrCmd::execute(drivers, cmd_bytes),
        CommandId::STASH_MEASUREMENT => StashMeasurementCmd::execute(drivers, cmd_bytes, resp),
        CommandId::DISABLE_ATTESTATION => DisableAttestationCmd::execute(drivers),
        CommandId::AUTHORIZE_AND_STASH => AuthorizeAndStashCmd::execute(drivers, cmd_bytes, resp),
        CommandId::CAPABILITIES => CapabilitiesCmd::execute(resp),
        CommandId::FW_INFO => FwInfoCmd::execute(drivers, resp),
        CommandId::DPE_TAG_TCI => TagTciCmd::execute(drivers, cmd_bytes),
        CommandId::DPE_GET_TAGGED_TCI => GetTaggedTciCmd::execute(drivers, cmd_bytes, resp),
        CommandId::POPULATE_IDEV_ECC384_CERT => {
            PopulateIDevIdEcc384CertCmd::execute(drivers, cmd_bytes)
        }
        CommandId::POPULATE_IDEV_MLDSA87_CERT => {
            PopulateIDevIdMldsa87CertCmd::execute(drivers, cmd_bytes)
        }
        CommandId::GET_FMC_ALIAS_ECC384_CERT => {
            GetFmcAliasCertCmd::execute(drivers, AlgorithmType::Ecc384, resp)
        }
        CommandId::GET_FMC_ALIAS_MLDSA87_CERT => {
            GetFmcAliasCertCmd::execute(drivers, AlgorithmType::Mldsa87, resp)
        }
        CommandId::GET_RT_ALIAS_ECC384_CERT => {
            GetRtAliasCertCmd::execute(drivers, AlgorithmType::Ecc384, resp)
        }
        CommandId::GET_RT_ALIAS_MLDSA87_CERT => {
            GetRtAliasCertCmd::execute(drivers, AlgorithmType::Mldsa87, resp)
        }
        CommandId::ADD_SUBJECT_ALT_NAME => AddSubjectAltNameCmd::execute(drivers, cmd_bytes),
        // CERTIFY_KEY_EXTENDED_{ECC384,MLDSA87} are dispatched earlier.
        CommandId::INCREMENT_PCR_RESET_COUNTER => {
            IncrementPcrResetCounterCmd::execute(drivers, cmd_bytes)
        }
        CommandId::QUOTE_PCRS_ECC384 => {
            GetPcrQuoteCmd::execute(drivers, AlgorithmType::Ecc384, cmd_bytes, resp)
        }
        CommandId::QUOTE_PCRS_MLDSA87 => {
            GetPcrQuoteCmd::execute(drivers, AlgorithmType::Mldsa87, cmd_bytes, resp)
        }
        CommandId::VERSION => FipsVersionCmd::execute(&drivers.soc_ifc)
            .write_to_prefix(resp)
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)
            .map(|_| core::mem::size_of::<FipsVersionResp>()),
        #[cfg(feature = "fips_self_test")]
        CommandId::SELF_TEST_START => match drivers.self_test_status {
            SelfTestStatus::Idle => {
                drivers.self_test_status = SelfTestStatus::InProgress(fips_self_test_cmd::execute);
                Ok(0)
            }
            _ => Err(CaliptraError::RUNTIME_SELF_TEST_IN_PROGRESS),
        },
        #[cfg(feature = "fips_self_test")]
        CommandId::SELF_TEST_GET_RESULTS => match drivers.self_test_status {
            SelfTestStatus::Done => {
                drivers.self_test_status = SelfTestStatus::Idle;
                Ok(0)
            }
            _ => Err(CaliptraError::RUNTIME_SELF_TEST_NOT_STARTED),
        },
        CommandId::SHUTDOWN => FipsShutdownCmd::execute(drivers),
        CommandId::SET_AUTH_MANIFEST => SetAuthManifestCmd::execute(drivers, cmd_bytes, false),
        CommandId::VERIFY_AUTH_MANIFEST => SetAuthManifestCmd::execute(drivers, cmd_bytes, true),
        CommandId::GET_IDEV_ECC384_CSR => GetIdevCsrCmd::execute(drivers, resp),
        CommandId::GET_IDEV_MLDSA87_CSR => GetIdevMldsaCsrCmd::execute(drivers, resp),
        CommandId::GET_FMC_ALIAS_ECC384_CSR => GetFmcAliasCsrCmd::execute(drivers, resp),
        CommandId::GET_FMC_ALIAS_MLDSA87_CSR => {
            get_fmc_alias_csr::GetFmcAliasMldsaCsrCmd::execute(drivers, resp)
        }
        // GET_ATTESTED_{ECC384,MLDSA87}_CSR are dispatched earlier (see above).
        CommandId::GET_PCR_LOG => GetPcrLogCmd::execute(drivers, resp),
        CommandId::SIGN_WITH_EXPORTED_ECDSA => {
            SignWithExportedEcdsaCmd::execute(drivers, cmd_bytes, resp)
        }
        CommandId::REVOKE_EXPORTED_CDI_HANDLE => {
            RevokeExportedCdiHandleCmd::execute(drivers, cmd_bytes)
        }
        CommandId::GET_IMAGE_INFO => GetImageInfoCmd::execute(drivers, cmd_bytes, resp),
        // Cryptographic mailbox commands
        CommandId::CM_IMPORT => cryptographic_mailbox::Commands::import(drivers, cmd_bytes, resp),
        CommandId::CM_DELETE => cryptographic_mailbox::Commands::delete(drivers, cmd_bytes, resp),
        CommandId::CM_CLEAR => cryptographic_mailbox::Commands::clear(drivers, resp),
        CommandId::CM_STATUS => cryptographic_mailbox::Commands::status(drivers, resp),
        CommandId::CM_SHA_INIT => {
            cryptographic_mailbox::Commands::sha_init(drivers, cmd_bytes, resp)
        }
        CommandId::CM_SHA_UPDATE => {
            cryptographic_mailbox::Commands::sha_update(drivers, cmd_bytes, resp)
        }
        CommandId::CM_SHA_FINAL => {
            cryptographic_mailbox::Commands::sha_final(drivers, cmd_bytes, resp)
        }
        CommandId::CM_RANDOM_GENERATE => {
            cryptographic_mailbox::Commands::random_generate(drivers, cmd_bytes, resp)
        }
        CommandId::CM_RANDOM_STIR => {
            cryptographic_mailbox::Commands::random_stir(drivers, cmd_bytes)
        }
        CommandId::CM_AES_ENCRYPT_INIT => {
            cryptographic_mailbox::Commands::aes_256_encrypt_init(drivers, cmd_bytes, resp)
        }
        CommandId::CM_AES_ENCRYPT_UPDATE => {
            cryptographic_mailbox::Commands::aes_256_encrypt_update(drivers, cmd_bytes, resp)
        }
        CommandId::CM_AES_DECRYPT_INIT => {
            cryptographic_mailbox::Commands::aes_256_cbc_decrypt_init(drivers, cmd_bytes, resp)
        }
        CommandId::CM_AES_DECRYPT_UPDATE => {
            cryptographic_mailbox::Commands::aes_256_cbc_decrypt_update(drivers, cmd_bytes, resp)
        }
        CommandId::CM_AES_GCM_ENCRYPT_INIT => {
            cryptographic_mailbox::Commands::aes_256_gcm_encrypt_init(drivers, cmd_bytes, resp)
        }
        CommandId::CM_AES_GCM_SPDM_ENCRYPT_INIT => {
            cryptographic_mailbox::Commands::aes_256_gcm_spdm_encrypt_init(drivers, cmd_bytes, resp)
        }
        CommandId::CM_AES_GCM_ENCRYPT_UPDATE => {
            cryptographic_mailbox::Commands::aes_256_gcm_encrypt_update(drivers, cmd_bytes, resp)
        }
        CommandId::CM_AES_GCM_ENCRYPT_FINAL => {
            cryptographic_mailbox::Commands::aes_256_gcm_encrypt_final(drivers, cmd_bytes, resp)
        }
        CommandId::CM_AES_GCM_DECRYPT_INIT => {
            cryptographic_mailbox::Commands::aes_256_gcm_decrypt_init(drivers, cmd_bytes, resp)
        }
        CommandId::CM_AES_GCM_SPDM_DECRYPT_INIT => {
            cryptographic_mailbox::Commands::aes_256_gcm_spdm_decrypt_init(drivers, cmd_bytes, resp)
        }
        CommandId::CM_AES_GCM_DECRYPT_UPDATE => {
            cryptographic_mailbox::Commands::aes_256_gcm_decrypt_update(drivers, cmd_bytes, resp)
        }
        CommandId::CM_AES_GCM_DECRYPT_FINAL => {
            cryptographic_mailbox::Commands::aes_256_gcm_decrypt_final(drivers, cmd_bytes, resp)
        }
        CommandId::CM_ECDH_GENERATE => {
            cryptographic_mailbox::Commands::ecdh_generate(drivers, cmd_bytes, resp)
        }
        CommandId::CM_ECDH_FINISH => {
            cryptographic_mailbox::Commands::ecdh_finish(drivers, cmd_bytes, resp)
        }
        CommandId::CM_HMAC => cryptographic_mailbox::Commands::hmac(drivers, cmd_bytes, resp),
        CommandId::CM_HMAC_KDF_COUNTER => {
            cryptographic_mailbox::Commands::hmac_kdf_counter(drivers, cmd_bytes, resp)
        }
        CommandId::CM_HKDF_EXTRACT => {
            cryptographic_mailbox::Commands::hkdf_extract(drivers, cmd_bytes, resp)
        }
        CommandId::CM_HKDF_EXPAND => {
            cryptographic_mailbox::Commands::hkdf_expand(drivers, cmd_bytes, resp)
        }
        CommandId::CM_MLDSA_PUBLIC_KEY => {
            cryptographic_mailbox::Commands::mldsa_public_key(drivers, cmd_bytes, resp)
        }
        CommandId::CM_MLDSA_SIGN => {
            cryptographic_mailbox::Commands::mldsa_sign(drivers, cmd_bytes, resp)
        }
        CommandId::CM_MLDSA_VERIFY => {
            cryptographic_mailbox::Commands::mldsa_verify(drivers, cmd_bytes, resp)
        }
        CommandId::CM_ECDSA_PUBLIC_KEY => {
            cryptographic_mailbox::Commands::ecdsa_public_key(drivers, cmd_bytes, resp)
        }
        CommandId::CM_ECDSA_SIGN => {
            cryptographic_mailbox::Commands::ecdsa_sign(drivers, cmd_bytes, resp)
        }
        CommandId::CM_ECDSA_VERIFY => {
            cryptographic_mailbox::Commands::ecdsa_verify(drivers, cmd_bytes, resp)
        }
        CommandId::CM_DERIVE_STABLE_KEY => {
            cryptographic_mailbox::Commands::derive_stable_key(drivers, cmd_bytes, resp)
        }
        CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_REQ => drivers.debug_unlock.handle_request(
            &mut drivers.trng,
            &drivers.soc_ifc,
            cmd_bytes,
            resp,
        ),
        CommandId::PRODUCTION_AUTH_DEBUG_UNLOCK_TOKEN => drivers.debug_unlock.handle_token(
            &mut drivers.soc_ifc,
            &mut drivers.sha2_512_384,
            &mut drivers.sha2_512_384_acc,
            &mut drivers.ecc384,
            &mut drivers.mldsa87,
            &mut drivers.dma,
            cmd_bytes,
        ),
        CommandId::FE_PROG => FeProgrammingCmd::execute(drivers, cmd_bytes),
        CommandId::REALLOCATE_DPE_CONTEXT_LIMITS => {
            ReallocateDpeContextLimitsCmd::execute(drivers, cmd_bytes, resp)
        }
        _ => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
    }?;

    finalize_response(drivers, resp, len)
}

#[inline(never)]
pub(crate) fn finalize_response(
    drivers: &mut Drivers,
    resp: &mut [u8],
    len: usize,
) -> CaliptraResult<MboxStatusE> {
    let len = len.max(8); // guarantee it is big enough to hold the header
    if len > resp.len() {
        // should be impossible
        return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
    }
    let mbox = &mut drivers.mbox;
    let resp = &mut resp[..len];
    populate_checksum(resp);
    mbox.write_response(resp)?;
    resp.fill(0);
    Ok(MboxStatusE::DataReady)
}

#[inline(never)]
fn execute_certify_key_extended_ecc384(
    drivers: &mut Drivers,
    cmd_bytes: &[u8],
) -> CaliptraResult<MboxStatusE> {
    let resp = &mut [0u8; DPE_RESP_BUF_SIZE][..];
    let len = CertifyKeyExtendedCmd::execute_ecc384(drivers, cmd_bytes, resp)?;
    finalize_response(drivers, resp, len)
}

#[inline(never)]
fn execute_certify_key_extended_mldsa87(
    drivers: &mut Drivers,
    cmd_bytes: &[u8],
) -> CaliptraResult<MboxStatusE> {
    let resp = &mut [0u8; DPE_RESP_BUF_SIZE][..];
    let len = CertifyKeyExtendedCmd::execute_mldsa87(drivers, cmd_bytes, resp)?;
    finalize_response(drivers, resp, len)
}

#[inline(never)]
fn execute_invoke_dpe_ecc384(
    drivers: &mut Drivers,
    cmd_bytes: &[u8],
) -> CaliptraResult<MboxStatusE> {
    let resp = &mut [0u8; DPE_RESP_BUF_SIZE][..];
    let len = InvokeDpeCmd::execute_ecc384(drivers, cmd_bytes, resp)?;
    finalize_response(drivers, resp, len)
}

#[inline(never)]
fn execute_invoke_dpe_mldsa87(
    drivers: &mut Drivers,
    cmd_bytes: &[u8],
) -> CaliptraResult<MboxStatusE> {
    let resp = &mut [0u8; DPE_RESP_BUF_SIZE][..];
    let len = InvokeDpeCmd::execute_mldsa87(drivers, cmd_bytes, resp)?;
    finalize_response(drivers, resp, len)
}

/// Handles an external mailbox command. If a valid external command was parsed,
/// then Some is returned and the external mailbox command will be copied into
#[inline(never)]
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

            // Clear non-fatal error before processing command
            caliptra_drivers::clear_fw_error_non_fatal(drivers.persistent_data.get_mut());

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

fn ec_dpe_env(
    drivers: &mut Drivers,
    dmtf_device_info: Option<ArrayVec<u8, { MAX_OTHER_NAME_SIZE }>>,
    ueid: Option<[u8; 17]>,
) -> CaliptraResult<DpeEnv<CptraDpeEcTypes>> {
    let hashed_rt_pub_key = drivers.compute_ecc_rt_alias_sn()?;
    let key_id_rt_cdi = Drivers::get_key_id_rt_cdi(drivers)?;
    let key_id_rt_priv_key = Drivers::get_key_id_rt_ecc_priv_key(drivers)?;
    let pdata = drivers.persistent_data.get_mut();
    let rt_pub_key = &mut pdata.fht.rt_dice_ecc_pub_key;
    let rt_pub_key = PubKey::Ecdsa(EcdsaPubKey::Ecdsa384(EcdsaPub384::from_slice(
        &rt_pub_key.x.into(),
        &rt_pub_key.y.into(),
    )));
    let crypto = DpeEcCrypto::new(
        &mut drivers.sha2_512_384,
        &mut drivers.trng,
        &mut drivers.ecc384,
        &mut drivers.hmac,
        &mut drivers.key_vault,
        rt_pub_key,
        key_id_rt_cdi,
        key_id_rt_priv_key,
        &mut pdata.exported_cdi_slots,
    );
    let pl0_pauser = pdata.manifest1.header.pl0_pauser;
    let (nb, nf) = Drivers::get_cert_validity_info(&pdata.manifest1);
    Ok(DpeEnv::<CptraDpeEcTypes> {
        crypto,
        platform: DpePlatform::new(
            CaliptraDpeProfile::Ecc384,
            pl0_pauser,
            hashed_rt_pub_key,
            drivers.ecc_cert_chain.as_slice(),
            nb,
            nf,
            dmtf_device_info,
            ueid,
        ),
        state: &mut pdata.state,
    })
}

fn mldsa_dpe_env(
    drivers: &mut Drivers,
    dmtf_device_info: Option<ArrayVec<u8, { MAX_OTHER_NAME_SIZE }>>,
    ueid: Option<[u8; 17]>,
) -> CaliptraResult<DpeEnv<CptraDpeMldsaTypes>> {
    let hashed_rt_pub_key = drivers.compute_mldsa_rt_alias_sn()?;
    let rt_pub_key = Drivers::get_key_id_rt_mldsa_pub_key(drivers);
    let rt_pub_key = okref(&rt_pub_key)?;
    let rt_pub_key = PubKey::MlDsa(MldsaPublicKey((*rt_pub_key).into()));
    let key_id_rt_cdi = Drivers::get_key_id_rt_cdi(drivers)?;
    let key_id_rt_priv_key = Drivers::get_key_id_rt_mldsa_keypair_seed(drivers)?;
    let pdata = drivers.persistent_data.get_mut();
    let crypto = DpeMldsaCrypto::new(
        &mut drivers.sha2_512_384,
        &mut drivers.trng,
        &mut drivers.mldsa87,
        &mut drivers.hmac,
        &mut drivers.key_vault,
        rt_pub_key,
        key_id_rt_cdi,
        key_id_rt_priv_key,
        &mut pdata.exported_cdi_slots,
    );
    let pl0_pauser = pdata.manifest1.header.pl0_pauser;
    let (nb, nf) = Drivers::get_cert_validity_info(&pdata.manifest1);
    Ok(DpeEnv::<CptraDpeMldsaTypes> {
        crypto,
        platform: DpePlatform::new(
            CaliptraDpeProfile::Mldsa87,
            pl0_pauser,
            hashed_rt_pub_key,
            drivers.mldsa_cert_chain.as_slice(),
            nb,
            nf,
            dmtf_device_info,
            ueid,
        ),
        state: &mut pdata.state,
    })
}
