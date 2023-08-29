// Licensed under the Apache-2.0 license

#![no_std]
#![cfg_attr(not(feature = "fip-self-test"), allow(unused))]

pub mod dice;
mod disable;
mod dpe_crypto;
mod dpe_platform;
pub mod fips;
pub mod handoff;
pub mod info;
mod invoke_dpe;
mod stash_measurement;
mod update;
mod verify;

// Used by runtime tests
pub mod mailbox;
use arrayvec::ArrayVec;
use crypto::{AlgLen, Crypto};
use mailbox::Mailbox;

#[cfg(feature = "test_only_commands")]
pub use dice::{GetLdevCertCmd, TestGetFmcAliasCertCmd};
pub use disable::DisableAttestationCmd;
use dpe_crypto::DpeCrypto;
pub use dpe_platform::{DpePlatform, VENDOR_ID, VENDOR_SKU};
#[cfg(feature = "fips_self_test")]
pub use fips::{fips_self_test_cmd, fips_self_test_cmd::SelfTestStatus};

pub use fips::{FipsShutdownCmd, FipsVersionCmd};
pub use info::{FwInfoCmd, IDevIdCertCmd, IDevIdInfoCmd};
pub use invoke_dpe::InvokeDpeCmd;
pub use stash_measurement::StashMeasurementCmd;
pub use verify::EcdsaVerifyCmd;
pub mod packet;
use caliptra_common::mailbox_api::CommandId;
use packet::Packet;

use caliptra_common::cprintln;
#[cfg(feature = "fips_self_test")]
use caliptra_common::mailbox_api::MailboxResp;

use caliptra_drivers::{
    CaliptraError, CaliptraResult, DataVault, Ecc384, KeyVault, Lms, PersistentDataAccessor, Sha1,
    SocIfc,
};
use caliptra_drivers::{Hmac384, PcrBank, PcrId, Sha256, Sha384, Sha384Acc, Trng};
use caliptra_registers::mbox::enums::MboxStatusE;
use caliptra_registers::{
    csrng::CsrngReg, dv::DvReg, ecc::EccReg, entropy_src::EntropySrcReg, hmac::HmacReg, kv::KvReg,
    mbox::MboxCsr, pv::PvReg, sha256::Sha256Reg, sha512::Sha512Reg, sha512_acc::Sha512AccCsr,
    soc_ifc::SocIfcReg, soc_ifc_trng::SocIfcTrngReg,
};
use dpe::{
    commands::{CommandExecution, DeriveChildCmd, DeriveChildFlags},
    context::ContextHandle,
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

pub struct Drivers {
    pub mbox: Mailbox,
    pub sha_acc: Sha512AccCsr,
    pub data_vault: DataVault,
    pub key_vault: KeyVault,
    pub soc_ifc: SocIfc,
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

    pub persistent_data: PersistentDataAccessor,

    pub lms: Lms,

    pub sha1: Sha1,

    pub dpe: DpeInstance,

    pub pcr_bank: PcrBank,

    pub cert_chain: ArrayVec<u8, MAX_CERT_CHAIN_SIZE>,

    #[cfg(feature = "fips_self_test")]
    pub self_test_status: SelfTestStatus,
}

pub struct CptraDpeTypes;

impl DpeTypes for CptraDpeTypes {
    type Crypto<'a> = DpeCrypto<'a>;
    type Platform<'a> = DpePlatform<'a>;
}

impl Drivers {
    /// # Safety
    ///
    /// Callers must ensure that this function is called only once, and that
    /// any concurrent access to these register blocks does not conflict with
    /// these drivers.
    pub unsafe fn new_from_registers() -> CaliptraResult<Self> {
        let mut trng = Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )?;

        let mut sha384 = Sha384::new(Sha512Reg::new());
        let mut ecc384 = Ecc384::new(EccReg::new());
        let mut hmac384 = Hmac384::new(HmacReg::new());
        let mut key_vault = KeyVault::new(KvReg::new());

        let mut persistent_data = PersistentDataAccessor::new();

        let locality = persistent_data.get().manifest1.header.pl0_pauser;
        let rt_pub_key = persistent_data.get().fht.rt_dice_pub_key;
        let mut crypto = DpeCrypto::new(
            &mut sha384,
            &mut trng,
            &mut ecc384,
            &mut hmac384,
            &mut key_vault,
            rt_pub_key,
        );
        // Skip hashing first 0x04 byte of der encoding
        let hashed_rt_pub_key = crypto
            .hash(AlgLen::Bit384, &rt_pub_key.to_der()[1..])
            .map_err(|_| CaliptraError::RUNTIME_INITIALIZE_DPE_FAILED)?;
        let mut data_vault = DataVault::new(DvReg::new());
        let mut cert_chain = Self::create_cert_chain(&mut data_vault, &mut persistent_data)?;
        let env = DpeEnv::<CptraDpeTypes> {
            crypto,
            platform: DpePlatform::new(locality, hashed_rt_pub_key, &mut cert_chain),
        };
        let mut pcr_bank = PcrBank::new(PvReg::new());
        let dpe = Self::initialize_dpe(env, &mut pcr_bank, locality)?;

        Ok(Self {
            mbox: Mailbox::new(MboxCsr::new()),
            sha_acc: Sha512AccCsr::new(),
            data_vault,
            key_vault,
            soc_ifc: SocIfc::new(SocIfcReg::new()),
            sha256: Sha256::new(Sha256Reg::new()),
            sha384,
            sha384_acc: Sha384Acc::new(Sha512AccCsr::new()),
            hmac384,
            ecc384,
            sha1: Sha1::default(),
            lms: Lms::default(),
            trng,
            persistent_data,
            dpe,
            pcr_bank,
            #[cfg(feature = "fips_self_test")]
            self_test_status: SelfTestStatus::Idle,
            cert_chain,
        })
    }

    fn initialize_dpe(
        mut env: DpeEnv<CptraDpeTypes>,
        pcr_bank: &mut PcrBank,
        locality: u32,
    ) -> CaliptraResult<DpeInstance> {
        let mut dpe = DpeInstance::new(&mut env, DPE_SUPPORT)
            .map_err(|_| CaliptraError::RUNTIME_INITIALIZE_DPE_FAILED)?;
        let data = <[u8; DPE_PROFILE.get_hash_size()]>::from(&pcr_bank.read_pcr(PcrId::PcrId1));
        DeriveChildCmd {
            handle: ContextHandle::default(),
            data,
            flags: DeriveChildFlags::MAKE_DEFAULT
                | DeriveChildFlags::CHANGE_LOCALITY
                | DeriveChildFlags::INPUT_ALLOW_CA
                | DeriveChildFlags::INPUT_ALLOW_X509,
            tci_type: u32::from_be_bytes(*b"RTJM"),
            target_locality: locality,
        }
        .execute(&mut dpe, &mut env, locality)
        .map_err(|_| CaliptraError::RUNTIME_INITIALIZE_DPE_FAILED)?;
        Ok(dpe)
    }

    fn create_cert_chain(
        data_vault: &mut DataVault,
        persistent_data: &mut PersistentDataAccessor,
    ) -> CaliptraResult<ArrayVec<u8, MAX_CERT_CHAIN_SIZE>> {
        let mut cert = [0u8; MAX_CERT_CHAIN_SIZE];
        let ldevid_cert_size = dice::copy_ldevid_cert(data_vault, persistent_data.get(), &mut cert)
            .map_err(|_| CaliptraError::RUNTIME_CERT_CHAIN_CREATION_FAILED)?;
        if ldevid_cert_size > cert.len() {
            return Err(CaliptraError::RUNTIME_CERT_CHAIN_CREATION_FAILED);
        }
        let fmcalias_cert_size = dice::copy_fmc_alias_cert(
            data_vault,
            persistent_data.get(),
            &mut cert[ldevid_cert_size..],
        )
        .map_err(|_| CaliptraError::RUNTIME_CERT_CHAIN_CREATION_FAILED)?;
        if ldevid_cert_size + fmcalias_cert_size > cert.len() {
            return Err(CaliptraError::RUNTIME_CERT_CHAIN_CREATION_FAILED);
        }
        let rtalias_cert_size = dice::copy_rt_alias_cert(
            data_vault,
            persistent_data.get(),
            &mut cert[ldevid_cert_size + fmcalias_cert_size..],
        )
        .map_err(|_| CaliptraError::RUNTIME_CERT_CHAIN_CREATION_FAILED)?;
        let cert_chain_size = ldevid_cert_size + fmcalias_cert_size + rtalias_cert_size;
        if cert_chain_size > cert.len() {
            return Err(CaliptraError::RUNTIME_CERT_CHAIN_CREATION_FAILED);
        }
        let mut cert_chain = ArrayVec::<u8, MAX_CERT_CHAIN_SIZE>::new();
        for i in 0..cert_chain_size {
            cert_chain
                .try_push(
                    *cert
                        .get(i)
                        .ok_or(CaliptraError::RUNTIME_CERT_CHAIN_CREATION_FAILED)?,
                )
                .map_err(|_| CaliptraError::RUNTIME_CERT_CHAIN_CREATION_FAILED)?;
        }
        Ok(cert_chain)
    }
}

/// Run pending jobs and enter low power mode.
fn goto_idle(drivers: &mut Drivers) {
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
        CommandId::INVOKE_DPE => InvokeDpeCmd::execute(drivers, cmd_bytes),
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
        CommandId::VERSION => FipsVersionCmd::execute(drivers),
        #[cfg(feature = "fips_self_test")]
        CommandId::SELF_TEST => match drivers.self_test_status {
            SelfTestStatus::Idle => {
                drivers.self_test_status = SelfTestStatus::InProgress(fips_self_test_cmd::execute);
                Ok(MailboxResp::default())
            }
            SelfTestStatus::Done => {
                drivers.self_test_status = SelfTestStatus::Idle;
                Ok(MailboxResp::default())
            }
            _ => Err(CaliptraError::RUNTIME_SELF_TEST_IN_PROGREESS),
        },
        CommandId::SHUTDOWN => FipsShutdownCmd::execute(drivers),
        _ => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
    }?;

    // Send the response
    Packet::copy_to_mbox(drivers, &mut resp)?;

    Ok(MboxStatusE::DataReady)
}

pub fn handle_mailbox_commands(drivers: &mut Drivers) -> ! {
    // Indicator to SOC that RT firmware is ready
    drivers.soc_ifc.assert_ready_for_runtime();
    caliptra_drivers::report_boot_status(RtBootStatus::RtReadyForCommands.into());
    loop {
        goto_idle(drivers);
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
        } else {
        }
    }
}
