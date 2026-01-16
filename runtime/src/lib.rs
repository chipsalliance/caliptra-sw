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
mod ocp_lock;
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
use authorize_and_stash::AuthorizeAndStashCmd;
use caliptra_cfi_lib_git::{cfi_assert, cfi_assert_eq, cfi_assert_ne, cfi_launder, CfiCounter};
use caliptra_common::cfi_check;
use caliptra_common::mailbox_api::{ExternalMailboxCmdReq, MailboxReqHeader};
pub use drivers::{Drivers, PauserPrivileges};
use fe_programming::FeProgrammingCmd;
use mailbox::Mailbox;
use populate_idev::PopulateIDevIdMldsa87CertCmd;
use zerocopy::{FromBytes, IntoBytes, KnownLayout};

use crate::capabilities::CapabilitiesCmd;
pub use crate::certify_key_extended::CertifyKeyExtendedCmd;
pub use crate::hmac::Hmac;
use crate::revoke_exported_cdi_handle::RevokeExportedCdiHandleCmd;
use crate::sign_with_exported_ecdsa::SignWithExportedEcdsaCmd;
pub use crate::subject_alt_name::AddSubjectAltNameCmd;
pub use activate_firmware::ActivateFirmwareCmd;
pub use authorize_and_stash::{IMAGE_AUTHORIZED, IMAGE_HASH_MISMATCH, IMAGE_NOT_AUTHORIZED};
pub use caliptra_common::fips::FipsVersionCmd;
use caliptra_common::mailbox_api::{populate_checksum, FipsVersionResp, MAX_RESP_SIZE};
pub use dice::{GetFmcAliasCertCmd, GetLdevCertCmd, IDevIdCertCmd};
pub use disable::DisableAttestationCmd;
use dpe_crypto::DpeCrypto;
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

use caliptra_drivers::{AxiAddr, CaliptraError, CaliptraResult, ResetReason};
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
pub const MAX_MLDSA_CERT_CHAIN_SIZE: usize = 31_000;

pub const PL0_PAUSER_FLAG: u32 = 1;
pub const PL0_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD: usize = 16;
pub const PL1_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD: usize = 16;
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

    if drivers.mbox.cmd() == CommandId::FIRMWARE_VERIFY {
        return firmware_verify::FirmwareVerifyCmd::execute(
            drivers,
            firmware_verify::VerifySrc::Mbox,
        );
    } else {
        cfi_assert_ne(drivers.mbox.cmd(), CommandId::FIRMWARE_VERIFY);
    }

    // Get the command bytes
    let req_packet = Packet::get_from_mbox(drivers)?;
    let mut cmd_bytes = req_packet.as_bytes()?;
    let mut cmd_id = req_packet.cmd;

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

    let mut external_cmd_buffer =
        [0; caliptra_common::mailbox_api::MAX_REQ_SIZE / size_of::<u32>()];

    // Check for EXTERNAL_MAILBOX_CMD and handle FIRMWARE_VERIFY specially
    if drivers.soc_ifc.subsystem_mode()
        && CommandId::from(cmd_id) == CommandId::EXTERNAL_MAILBOX_CMD
    {
        let external_cmd = ExternalMailboxCmdReq::read_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;

        if external_cmd.command_id == CommandId::FIRMWARE_VERIFY.into() {
            let axi_addr = AxiAddr {
                lo: external_cmd.axi_address_start_low,
                hi: external_cmd.axi_address_start_high,
            };
            return firmware_verify::FirmwareVerifyCmd::execute(
                drivers,
                firmware_verify::VerifySrc::External {
                    axi_address: axi_addr,
                    image_size: external_cmd.command_size,
                },
            );
        }
    }

    if let Some(ext) =
        handle_external_mailbox_cmd(cmd_id, cmd_bytes, drivers, &mut external_cmd_buffer)?
    {
        cmd_id = ext.cmd_id;
        cmd_bytes = external_cmd_buffer
            .as_bytes()
            .get(..ext.cmd_size)
            .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
    }

    // stage the response once on the stack
    let resp = &mut [0u8; MAX_RESP_SIZE][..];

    let len = match CommandId::from(cmd_id) {
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
        CommandId::INVOKE_DPE => InvokeDpeCmd::execute(drivers, cmd_bytes, resp),
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
        CommandId::CAPABILITIES => CapabilitiesCmd::execute(drivers, resp),
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
        CommandId::CERTIFY_KEY_EXTENDED => CertifyKeyExtendedCmd::execute(drivers, cmd_bytes, resp),
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
        CommandId::CM_AES_GCM_DECRYPT_DMA => {
            cryptographic_mailbox::Commands::aes_256_gcm_decrypt_dma(drivers, cmd_bytes, resp)
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
        ocp_lock_command_id @ CommandId::OCP_LOCK_GET_ALGORITHMS
        | ocp_lock_command_id @ CommandId::OCP_LOCK_INITIALIZE_MEK_SECRET
        | ocp_lock_command_id @ CommandId::OCP_LOCK_ENUMERATE_HPKE_HANDLES
        | ocp_lock_command_id @ CommandId::OCP_LOCK_ROTATE_HPKE_KEY
        | ocp_lock_command_id @ CommandId::OCP_LOCK_GENERATE_MEK
        | ocp_lock_command_id @ CommandId::OCP_LOCK_ENDORSE_HPKE_PUB_KEY
        | ocp_lock_command_id @ CommandId::OCP_LOCK_DERIVE_MEK => {
            ocp_lock::command_handler(ocp_lock_command_id, drivers, cmd_bytes, resp)
        }
        _ => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
    }?;

    let len = len.max(8); // guarantee it is big enough to hold the header
    if len > MAX_RESP_SIZE {
        // should be impossible
        return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
    }

    let mbox = &mut drivers.mbox;
    let resp = &mut resp[..len];
    // Generate response checksum
    populate_checksum(resp);
    // Send the payload
    mbox.write_response(resp)?;
    // zero the original resp buffer so as not to leak sensitive data
    resp.fill(0);
    Ok(MboxStatusE::DataReady)
}

struct ExternalCommand {
    cmd_id: u32,
    cmd_size: usize,
}

/// Handles an external mailbox command. If a valid external command was parsed,
/// then Some is returned and the external mailbox command will be copied into
/// the external_cmd_buffer argument.
fn handle_external_mailbox_cmd(
    cmd_id: u32,
    cmd_bytes: &[u8],
    drivers: &mut Drivers,
    external_cmd_buffer: &mut [u32],
) -> CaliptraResult<Option<ExternalCommand>> {
    if !drivers.soc_ifc.subsystem_mode()
        || CommandId::from(cmd_id) != CommandId::EXTERNAL_MAILBOX_CMD
    {
        return Ok(None);
    }
    let external_cmd = ExternalMailboxCmdReq::read_from_bytes(cmd_bytes)
        .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;

    let cmd_id = external_cmd.command_id;

    let axi_addr = AxiAddr {
        lo: external_cmd.axi_address_start_low,
        hi: external_cmd.axi_address_start_high,
    };

    if cmd_id == CommandId::FIRMWARE_LOAD.into() {
        cfi_assert_eq(cmd_id, CommandId::FIRMWARE_LOAD.into());
        update::handle_impactless_update(drivers)?;

        // If the handler succeeds but does not invoke reset that is
        // unexpected. Denote that the update failed.
        return Err(CaliptraError::RUNTIME_UNEXPECTED_UPDATE_RETURN);
    } else {
        cfi_assert_ne(cmd_id, CommandId::FIRMWARE_LOAD.into());
    }

    // FIRMWARE_VERIFY is handled earlier in handle_command() before this function is called
    cfi_assert_ne(cmd_id, CommandId::FIRMWARE_VERIFY.into());

    if let Some(ascii) = human_readable_command(&cmd_id.to_be_bytes()) {
        cprintln!(
            "[rt] Loading external command=0x{:x} ({}), len={} from AXI address: 0x{:x}",
            external_cmd.command_id,
            ascii,
            external_cmd.command_size,
            u64::from(axi_addr),
        );
    } else {
        cprintln!(
            "[rt] Loading external command=0x{:x}, len={} from AXI address: 0x{:x}",
            external_cmd.command_id,
            external_cmd.command_size,
            u64::from(axi_addr),
        );
    }
    // check that the command is not too large
    if external_cmd.command_size as usize > caliptra_common::mailbox_api::MAX_REQ_SIZE {
        return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
    }
    let buffer = external_cmd_buffer
        .get_mut(..external_cmd.command_size as usize / size_of::<u32>())
        .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
    drivers.dma.read_buffer(axi_addr, buffer);
    let cmd_bytes = buffer.as_bytes();

    // Verify incoming checksum
    // Make sure enough data was sent to even have a checksum
    if cmd_bytes.len() < core::mem::size_of::<MailboxReqHeader>() {
        return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
    }

    // Assumes chksum is always offset 0
    let req_hdr: &MailboxReqHeader =
        MailboxReqHeader::ref_from_bytes(&cmd_bytes[..core::mem::size_of::<MailboxReqHeader>()])
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

    if !caliptra_common::checksum::verify_checksum(
        req_hdr.chksum,
        cmd_id,
        &cmd_bytes[core::mem::size_of_val(&req_hdr.chksum)..],
    ) {
        return Err(CaliptraError::RUNTIME_INVALID_CHECKSUM);
    }

    if let Some(ascii) = human_readable_command(&cmd_id.to_be_bytes()) {
        cprintln!(
            "[rt] Received external command=0x{:x} ({}), len={}",
            cmd_id,
            ascii,
            cmd_bytes.len()
        );
    } else {
        cprintln!(
            "[rt] Received external command=0x{:x}, len={}",
            cmd_id,
            cmd_bytes.len()
        );
    }

    Ok(Some(ExternalCommand {
        cmd_id,
        cmd_size: cmd_bytes.len(),
    }))
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
    let command_was_running = drivers
        .persistent_data
        .get()
        .fw
        .dpe
        .runtime_cmd_active
        .get();
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
        drivers.persistent_data.get_mut().fw.dpe.runtime_cmd_active = U8Bool::new(false);

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
            drivers.persistent_data.get_mut().fw.dpe.runtime_cmd_active = U8Bool::new(true);

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
