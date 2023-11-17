// Licensed under the Apache-2.0 license

#![cfg_attr(not(feature = "fip-self-test"), allow(unused))]

#[cfg(feature = "fips_self_test")]
pub use crate::fips::{fips_self_test_cmd, fips_self_test_cmd::SelfTestStatus};

use crate::{
    dice, CptraDpeTypes, DisableAttestationCmd, DpeCrypto, DpePlatform, Mailbox, DPE_SUPPORT,
    MAX_CERT_CHAIN_SIZE,
};

use arrayvec::ArrayVec;
use caliptra_drivers::{
    cprint, cprintln, pcr_log::RT_FW_JOURNEY_PCR, Array4x12, CaliptraError, CaliptraResult,
    DataVault, Ecc384, KeyVault, Lms, PersistentDataAccessor, ResetReason, Sha1, SocIfc,
};
use caliptra_drivers::{Hmac384, PcrBank, PcrId, Sha256, Sha256Alg, Sha384, Sha384Acc, Trng};
use caliptra_registers::mbox::enums::MboxStatusE;
use caliptra_registers::{
    csrng::CsrngReg, dv::DvReg, ecc::EccReg, entropy_src::EntropySrcReg, hmac::HmacReg, kv::KvReg,
    mbox::MboxCsr, pv::PvReg, sha256::Sha256Reg, sha512::Sha512Reg, sha512_acc::Sha512AccCsr,
    soc_ifc::SocIfcReg, soc_ifc_trng::SocIfcTrngReg,
};
use dpe::context::{Context, ContextState};
use dpe::tci::TciMeasurement;
use dpe::{
    commands::{CommandExecution, DeriveChildCmd, DeriveChildFlags},
    context::ContextHandle,
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    support::Support,
    DPE_PROFILE,
};

use crypto::{AlgLen, Crypto, CryptoBuf};

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

    pub pcr_bank: PcrBank,

    pub cert_chain: ArrayVec<u8, MAX_CERT_CHAIN_SIZE>,

    pub attestation_disabled: bool,

    #[cfg(feature = "fips_self_test")]
    pub self_test_status: SelfTestStatus,

    pub is_shutdown: bool,
}

impl Drivers {
    /// # Safety
    ///
    /// Callers must ensure that this function is called only once, and that
    /// any concurrent access to these register blocks does not conflict with
    /// these drivers.
    pub unsafe fn new_from_registers() -> CaliptraResult<Self> {
        let mut drivers = Self::get_unsafe_registers()?;

        Self::create_cert_chain(&mut drivers)?;

        let reset_reason = drivers.soc_ifc.reset_reason();
        match reset_reason {
            ResetReason::ColdReset => {
                Self::initialize_dpe(&mut drivers)?;
            }
            ResetReason::UpdateReset => {
                Self::validate_dpe_structure(&mut drivers)?;
                Self::update_dpe_rt_journey(&mut drivers)?;
            }
            ResetReason::WarmReset => {
                Self::validate_dpe_structure(&mut drivers)?;
                Self::check_dpe_rt_journey_unchanged(&mut drivers)?;
            }
            ResetReason::Unknown => {
                return Err(CaliptraError::RUNTIME_UNKNOWN_RESET_FLOW);
            }
        }

        Ok(drivers)
    }

    /// Isolates unsafe behavior in new_from_registers
    unsafe fn get_unsafe_registers() -> CaliptraResult<Self> {
        let mut trng = Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )?;

        Ok(Self {
            mbox: Mailbox::new(MboxCsr::new()),
            sha_acc: Sha512AccCsr::new(),
            data_vault: DataVault::new(DvReg::new()),
            key_vault: KeyVault::new(KvReg::new()),
            soc_ifc: SocIfc::new(SocIfcReg::new()),
            sha256: Sha256::new(Sha256Reg::new()),
            sha384: Sha384::new(Sha512Reg::new()),
            sha384_acc: Sha384Acc::new(Sha512AccCsr::new()),
            hmac384: Hmac384::new(HmacReg::new()),
            ecc384: Ecc384::new(EccReg::new()),
            sha1: Sha1::default(),
            lms: Lms::default(),
            trng,
            persistent_data: PersistentDataAccessor::new(),
            pcr_bank: PcrBank::new(PvReg::new()),
            #[cfg(feature = "fips_self_test")]
            self_test_status: SelfTestStatus::Idle,
            cert_chain: ArrayVec::new(),
            attestation_disabled: false,
            is_shutdown: false,
        })
    }

    // Inlined so the callsite optimizer knows that root_idx < dpe.contexts.len()
    // and won't insert possible call to panic.
    #[inline(always)]
    fn get_dpe_root_context_idx(dpe: &DpeInstance) -> CaliptraResult<usize> {
        // Find root node by finding the non-inactive context with parent equal to ROOT_INDEX
        let root_idx = dpe
            .contexts
            .iter()
            .enumerate()
            .find(|&(idx, context)| {
                context.state != ContextState::Inactive && context.parent_idx == Context::ROOT_INDEX
            })
            .ok_or(CaliptraError::RUNTIME_DPE_VALIDATION_FAILED)?
            .0;
        if root_idx >= dpe.contexts.len() {
            return Err(CaliptraError::RUNTIME_DPE_VALIDATION_FAILED);
        }
        Ok(root_idx)
    }

    fn validate_dpe_structure(mut drivers: &mut Drivers) -> CaliptraResult<()> {
        let dpe = &drivers.persistent_data.get().dpe;
        let root_idx = Self::get_dpe_root_context_idx(dpe)?;
        // Ensure context/TCI tree is well-formed (all nodes reachable from root and no cycles)
        if !dpe.validate_context_tree(root_idx) {
            // If SRAM Dpe Instance validation fails, disable attestation
            let mut result = DisableAttestationCmd::execute(drivers);
            match result {
                Ok(_) => cprintln!("Disabled attestation due to DPE validation failure"),
                Err(e) => {
                    cprintln!("{}", e.0);
                    return Err(CaliptraError::RUNTIME_GLOBAL_EXCEPTION);
                }
            }
        }

        Ok(())
    }

    fn update_dpe_rt_journey(drivers: &mut Drivers) -> CaliptraResult<()> {
        let dpe = &mut drivers.persistent_data.get_mut().dpe;
        let root_idx = Self::get_dpe_root_context_idx(dpe)?;
        let latest_pcr = <[u8; 48]>::from(drivers.pcr_bank.read_pcr(PcrId::PcrId3));
        dpe.contexts[root_idx].tci.tci_current = TciMeasurement(latest_pcr);
        dpe.contexts[root_idx].tci.tci_cumulative = TciMeasurement(latest_pcr);

        Ok(())
    }

    fn check_dpe_rt_journey_unchanged(mut drivers: &mut Drivers) -> CaliptraResult<()> {
        let dpe = &drivers.persistent_data.get().dpe;
        let root_idx = Self::get_dpe_root_context_idx(dpe)?;
        let latest_tci = dpe.contexts[root_idx].tci.tci_current;

        let mut hasher = drivers
            .sha384
            .digest_init()
            .map_err(|_| CaliptraError::RUNTIME_DPE_VALIDATION_FAILED)?;

        hasher
            .update(&[0; AlgLen::Bit384.size()])
            .map_err(|_| CaliptraError::RUNTIME_DPE_VALIDATION_FAILED)?;
        hasher
            .update(&latest_tci.0)
            .map_err(|_| CaliptraError::RUNTIME_DPE_VALIDATION_FAILED)?;

        let mut digest = Array4x12::default();
        hasher
            .finalize(&mut digest)
            .map_err(|_| CaliptraError::RUNTIME_DPE_VALIDATION_FAILED)?;

        let latest_pcr = drivers.pcr_bank.read_pcr(PcrId::PcrId3);
        // Ensure SHA384_HASH(0x00..00, TCI from SRAM) == PCR3 value
        if latest_pcr != digest {
            // If latest pcr validation fails, disable attestation
            let mut result = DisableAttestationCmd::execute(drivers);
            match result {
                Ok(_) => cprintln!("Disabled attestation due to latest TCI of the node containing the runtime journey PCR not matching the runtime PCR"),
                Err(e) => {
                    cprintln!("{}", e.0);
                    return Err(CaliptraError::RUNTIME_GLOBAL_EXCEPTION);
                }
            }
        }

        Ok(())
    }

    // Caliptra Name serialNumber fields are sha256 digests
    pub fn compute_rt_alias_sn(&mut self) -> CaliptraResult<CryptoBuf> {
        let key = self.persistent_data.get().fht.rt_dice_pub_key.to_der();

        let rt_digest = self.sha256.digest(&key)?;
        let token = CryptoBuf::new(&Into::<[u8; 32]>::into(rt_digest))
            .map_err(|_| CaliptraError::RUNTIME_INITIALIZE_DPE_FAILED)?;

        Ok(token)
    }

    fn initialize_dpe(drivers: &mut Drivers) -> CaliptraResult<()> {
        let locality = drivers.persistent_data.get().manifest1.header.pl0_pauser;
        let hashed_rt_pub_key = drivers.compute_rt_alias_sn()?;
        let mut crypto = DpeCrypto::new(
            &mut drivers.sha384,
            &mut drivers.trng,
            &mut drivers.ecc384,
            &mut drivers.hmac384,
            &mut drivers.key_vault,
            drivers.persistent_data.get().fht.rt_dice_pub_key,
        );

        let mut env = DpeEnv::<CptraDpeTypes> {
            crypto,
            platform: DpePlatform::new(locality, hashed_rt_pub_key, &mut drivers.cert_chain),
        };
        let mut dpe = DpeInstance::new(&mut env, DPE_SUPPORT)
            .map_err(|_| CaliptraError::RUNTIME_INITIALIZE_DPE_FAILED)?;

        let data = <[u8; DPE_PROFILE.get_hash_size()]>::from(
            &drivers.pcr_bank.read_pcr(RT_FW_JOURNEY_PCR),
        );
        // Call DeriveChild to create root context.
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

        // Call DeriveChild to create TCIs for each measurement added in ROM
        let num_measurements = drivers.persistent_data.get().fht.meas_log_index as usize;
        let measurement_log = drivers.persistent_data.get().measurement_log;
        for measurement_log_entry in measurement_log.iter().take(num_measurements) {
            let measurement_data = measurement_log_entry.pcr_entry.measured_data();
            let tci_type = u32::from_be_bytes(measurement_log_entry.metadata);
            DeriveChildCmd {
                handle: ContextHandle::default(),
                data: measurement_data
                    .try_into()
                    .map_err(|_| CaliptraError::RUNTIME_ADD_ROM_MEASUREMENTS_TO_DPE_FAILED)?,
                flags: DeriveChildFlags::MAKE_DEFAULT
                    | DeriveChildFlags::CHANGE_LOCALITY
                    | DeriveChildFlags::INPUT_ALLOW_CA
                    | DeriveChildFlags::INPUT_ALLOW_X509,
                tci_type,
                target_locality: locality,
            }
            .execute(&mut dpe, &mut env, locality)
            .map_err(|_| CaliptraError::RUNTIME_ADD_ROM_MEASUREMENTS_TO_DPE_FAILED)?;
        }

        // Write DPE to persistent data.
        drivers.persistent_data.get_mut().dpe = dpe;
        Ok(())
    }

    fn create_cert_chain(drivers: &mut Drivers) -> CaliptraResult<()> {
        let data_vault = &drivers.data_vault;
        let persistent_data = &drivers.persistent_data;
        let mut cert = [0u8; MAX_CERT_CHAIN_SIZE];

        // Write ldev_id cert to cert chain.
        let ldevid_cert_size = dice::copy_ldevid_cert(data_vault, persistent_data.get(), &mut cert)
            .map_err(|_| CaliptraError::RUNTIME_CERT_CHAIN_CREATION_FAILED)?;
        if ldevid_cert_size > cert.len() {
            return Err(CaliptraError::RUNTIME_CERT_CHAIN_CREATION_FAILED);
        }

        // Write fmc alias cert to cert chain.
        let fmcalias_cert_size = dice::copy_fmc_alias_cert(
            data_vault,
            persistent_data.get(),
            &mut cert[ldevid_cert_size..],
        )
        .map_err(|_| CaliptraError::RUNTIME_CERT_CHAIN_CREATION_FAILED)?;
        if ldevid_cert_size + fmcalias_cert_size > cert.len() {
            return Err(CaliptraError::RUNTIME_CERT_CHAIN_CREATION_FAILED);
        }

        // Write rt alias cert to cert chain.
        let rtalias_cert_size = dice::copy_rt_alias_cert(
            persistent_data.get(),
            &mut cert[ldevid_cert_size + fmcalias_cert_size..],
        )
        .map_err(|_| CaliptraError::RUNTIME_CERT_CHAIN_CREATION_FAILED)?;
        let cert_chain_size = ldevid_cert_size + fmcalias_cert_size + rtalias_cert_size;
        if cert_chain_size > cert.len() {
            return Err(CaliptraError::RUNTIME_CERT_CHAIN_CREATION_FAILED);
        }

        // Copy cert chain to ArrayVec.
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

        drivers.cert_chain = cert_chain;
        Ok(())
    }
}
