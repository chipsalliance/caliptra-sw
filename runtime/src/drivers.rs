// Licensed under the Apache-2.0 license

#![cfg_attr(not(feature = "fip-self-test"), allow(unused))]

#[cfg(feature = "fips_self_test")]
pub use crate::fips::{fips_self_test_cmd, fips_self_test_cmd::SelfTestStatus};

use crate::{
    dice, CptraDpeTypes, DpeCrypto, DpePlatform, Mailbox, DPE_SUPPORT, MAX_CERT_CHAIN_SIZE,
};

use arrayvec::ArrayVec;
use caliptra_drivers::{
    CaliptraError, CaliptraResult, DataVault, Ecc384, KeyVault, Lms, PersistentDataAccessor,
    ResetReason, Sha1, SocIfc,
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

use crypto::{AlgLen, Crypto};

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

        let rt_pub_key = persistent_data.get().fht.rt_dice_pub_key;
        let mut data_vault = DataVault::new(DvReg::new());
        let mut cert_chain = Self::create_cert_chain(&mut data_vault, &mut persistent_data)?;
        let mut pcr_bank = PcrBank::new(PvReg::new());
        let mut soc_ifc = SocIfc::new(SocIfcReg::new());
        if soc_ifc.reset_reason() == ResetReason::ColdReset {
            let locality = persistent_data.get().manifest1.header.pl0_pauser;
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
            let env = DpeEnv::<CptraDpeTypes> {
                crypto,
                platform: DpePlatform::new(locality, hashed_rt_pub_key, &mut cert_chain),
            };
            let dpe = Self::initialize_dpe(env, &mut pcr_bank, locality)?;
            persistent_data.get_mut().dpe = dpe;
        }

        Ok(Self {
            mbox: Mailbox::new(MboxCsr::new()),
            sha_acc: Sha512AccCsr::new(),
            data_vault,
            key_vault,
            soc_ifc,
            sha256: Sha256::new(Sha256Reg::new()),
            sha384,
            sha384_acc: Sha384Acc::new(Sha512AccCsr::new()),
            hmac384,
            ecc384,
            sha1: Sha1::default(),
            lms: Lms::default(),
            trng,
            persistent_data,
            pcr_bank,
            #[cfg(feature = "fips_self_test")]
            self_test_status: SelfTestStatus::Idle,
            cert_chain,
            attestation_disabled: false,
            is_shutdown: false,
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
