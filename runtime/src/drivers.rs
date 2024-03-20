/*++

Licensed under the Apache-2.0 license.

File Name:

    drivers.rs

Abstract:

    File contains driver initializations.

--*/

#![cfg_attr(not(feature = "fip-self-test"), allow(unused))]

#[cfg(feature = "fips_self_test")]
pub use crate::fips::{fips_self_test_cmd, fips_self_test_cmd::SelfTestStatus};

use crate::{
    dice, CptraDpeTypes, DisableAttestationCmd, DpeCrypto, DpePlatform, Mailbox, DPE_SUPPORT,
    MAX_CERT_CHAIN_SIZE, PL0_DPE_ACTIVE_CONTEXT_THRESHOLD, PL0_PAUSER_FLAG,
    PL1_DPE_ACTIVE_CONTEXT_THRESHOLD,
};

use arrayvec::ArrayVec;
use caliptra_cfi_derive::{cfi_impl_fn, cfi_mod_fn};
use caliptra_cfi_lib::{cfi_assert, cfi_assert_eq, cfi_assert_eq_12_words, cfi_launder};
use caliptra_drivers::KeyId;
use caliptra_drivers::{
    cprint, cprintln, pcr_log::RT_FW_JOURNEY_PCR, Array4x12, CaliptraError, CaliptraResult,
    DataVault, Ecc384, KeyVault, Lms, PersistentDataAccessor, Pic, ResetReason, Sha1, SocIfc,
};
use caliptra_drivers::{
    hand_off::DataStore, Ecc384PubKey, Hmac384, PcrBank, PcrId, Sha256, Sha256Alg, Sha384,
    Sha384Acc, Trng,
};
use caliptra_image_types::ImageManifest;
use caliptra_registers::el2_pic_ctrl::El2PicCtrl;
use caliptra_registers::mbox::enums::MboxStatusE;
use caliptra_registers::{
    csrng::CsrngReg, dv::DvReg, ecc::EccReg, entropy_src::EntropySrcReg, hmac::HmacReg, kv::KvReg,
    mbox::MboxCsr, pv::PvReg, sha256::Sha256Reg, sha512::Sha512Reg, sha512_acc::Sha512AccCsr,
    soc_ifc::SocIfcReg, soc_ifc_trng::SocIfcTrngReg,
};
use caliptra_x509::{NotAfter, NotBefore};
use dpe::context::{Context, ContextState, ContextType};
use dpe::tci::TciMeasurement;
use dpe::validation::DpeValidator;
use dpe::MAX_HANDLES;
use dpe::{
    commands::{CommandExecution, DeriveContextCmd, DeriveContextFlags},
    context::ContextHandle,
    dpe_instance::{DpeEnv, DpeInstance, DpeTypes},
    support::Support,
    DPE_PROFILE,
};

use core::cmp::Ordering::{Equal, Greater};
use crypto::{AlgLen, Crypto, CryptoBuf, Hasher};
use zerocopy::AsBytes;

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

    pub pic: Pic,

    pub cert_chain: ArrayVec<u8, MAX_CERT_CHAIN_SIZE>,

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
        if drivers.persistent_data.get().attestation_disabled.get() {
            DisableAttestationCmd::execute(&mut drivers)
                .map_err(|_| CaliptraError::RUNTIME_GLOBAL_EXCEPTION)?;
        }

        let reset_reason = drivers.soc_ifc.reset_reason();
        match reset_reason {
            ResetReason::ColdReset => {
                cfi_assert_eq(drivers.soc_ifc.reset_reason(), ResetReason::ColdReset);
                Self::initialize_dpe(&mut drivers)?;
            }
            ResetReason::UpdateReset => {
                cfi_assert_eq(drivers.soc_ifc.reset_reason(), ResetReason::UpdateReset);
                Self::validate_dpe_structure(&mut drivers)?;
                Self::validate_context_tags(&mut drivers)?;
                Self::update_dpe_rt_journey(&mut drivers)?;
            }
            ResetReason::WarmReset => {
                cfi_assert_eq(drivers.soc_ifc.reset_reason(), ResetReason::WarmReset);
                Self::validate_dpe_structure(&mut drivers)?;
                Self::validate_context_tags(&mut drivers)?;
                Self::check_dpe_rt_journey_unchanged(&mut drivers)?;
            }
            ResetReason::Unknown => {
                cfi_assert_eq(drivers.soc_ifc.reset_reason(), ResetReason::Unknown);
                return Err(CaliptraError::RUNTIME_UNKNOWN_RESET_FLOW);
            }
        }

        Ok(drivers)
    }

    /// Isolates unsafe behavior in new_from_registers
    unsafe fn get_unsafe_registers() -> CaliptraResult<Self> {
        let trng = Trng::new(
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
            pic: Pic::new(El2PicCtrl::new()),
            #[cfg(feature = "fips_self_test")]
            self_test_status: SelfTestStatus::Idle,
            cert_chain: ArrayVec::new(),
            is_shutdown: false,
        })
    }

    /// Retrieves the root context index. Inlined so the callsite optimizer
    /// knows that root_idx < dpe.contexts.len() and won't insert possible call to panic.
    ///
    /// # Arguments
    ///
    /// * `dpe` - DpeInstance
    ///
    /// # Returns
    ///
    /// * `usize` - Index containing the root DPE context
    #[inline(always)]
    pub fn get_dpe_root_context_idx(dpe: &DpeInstance) -> CaliptraResult<usize> {
        // Find root node by finding the non-inactive context with parent equal to ROOT_INDEX
        let root_idx = dpe
            .contexts
            .iter()
            .enumerate()
            .find(|&(idx, context)| {
                context.state != ContextState::Inactive
                    && context.parent_idx == Context::ROOT_INDEX
                    && context.context_type == ContextType::Normal
            })
            .ok_or(CaliptraError::RUNTIME_UNABLE_TO_FIND_DPE_ROOT_CONTEXT)?
            .0;
        if root_idx >= dpe.contexts.len() {
            return Err(CaliptraError::RUNTIME_UNABLE_TO_FIND_DPE_ROOT_CONTEXT);
        }
        Ok(root_idx)
    }

    /// Validate DPE and disable attestation if validation fails
    fn validate_dpe_structure(mut drivers: &mut Drivers) -> CaliptraResult<()> {
        let dpe = &mut drivers.persistent_data.get_mut().dpe;
        let dpe_validator = DpeValidator { dpe };
        let validation_result = dpe_validator.validate_dpe();
        if let Err(e) = validation_result {
            // If SRAM Dpe Instance validation fails, disable attestation
            let mut result = DisableAttestationCmd::execute(drivers);
            if cfi_launder(result.is_ok()) {
                cfi_assert!(result.is_ok());
            } else {
                cfi_assert!(result.is_err());
            }
            match result {
                Ok(_) => {
                    cprintln!("Disabled attestation due to DPE validation failure");
                    // store specific validation error in CPTRA_FW_EXTENDED_ERROR_INFO
                    drivers.soc_ifc.set_fw_extended_error(e.get_error_code());
                    caliptra_drivers::report_fw_error_non_fatal(
                        CaliptraError::RUNTIME_DPE_VALIDATION_FAILED.into(),
                    );
                }
                Err(e) => {
                    cprintln!("{}", e.0);
                    return Err(CaliptraError::RUNTIME_GLOBAL_EXCEPTION);
                }
            }
        } else {
            let pl0_pauser = drivers.persistent_data.get().manifest1.header.pl0_pauser;
            let flags = drivers.persistent_data.get().manifest1.header.flags;
            let locality = drivers.mbox.user();
            // check that DPE used context limits are not exceeded
            let dpe_context_threshold_exceeded = Self::is_dpe_context_threshold_exceeded(
                pl0_pauser,
                flags,
                locality,
                &drivers.persistent_data.get().dpe,
                true,
            );
            if cfi_launder(dpe_context_threshold_exceeded.is_ok()) {
                cfi_assert!(dpe_context_threshold_exceeded.is_ok());
            } else {
                cfi_assert!(dpe_context_threshold_exceeded.is_err());
            }
            if let Err(e) = dpe_context_threshold_exceeded {
                let result = DisableAttestationCmd::execute(drivers);
                if cfi_launder(result.is_ok()) {
                    cfi_assert!(result.is_ok());
                } else {
                    cfi_assert!(result.is_err());
                }
                match result {
                    Ok(_) => {
                        cprintln!(
                            "Disabled attestation due to DPE used context limits being breached"
                        );
                        caliptra_drivers::report_fw_error_non_fatal(e.into());
                    }
                    Err(e) => {
                        cprintln!("{}", e.0);
                        return Err(CaliptraError::RUNTIME_GLOBAL_EXCEPTION);
                    }
                }
            }
        }

        Ok(())
    }

    /// Update DPE root context's TCI measurement with RT_FW_JOURNEY_PCR
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn update_dpe_rt_journey(drivers: &mut Drivers) -> CaliptraResult<()> {
        let dpe = &mut drivers.persistent_data.get_mut().dpe;
        let root_idx = Self::get_dpe_root_context_idx(dpe)?;
        let latest_pcr = <[u8; 48]>::from(drivers.pcr_bank.read_pcr(RT_FW_JOURNEY_PCR));
        dpe.contexts[root_idx].tci.tci_current = TciMeasurement(latest_pcr);
        dpe.contexts[root_idx].tci.tci_cumulative = TciMeasurement(latest_pcr);

        Ok(())
    }

    /// Check that RT_FW_JOURNEY_PCR == DPE Root Context's TCI measurement
    fn check_dpe_rt_journey_unchanged(mut drivers: &mut Drivers) -> CaliptraResult<()> {
        let dpe = &drivers.persistent_data.get().dpe;
        let root_idx = Self::get_dpe_root_context_idx(dpe)?;
        let latest_tci = Array4x12::from(&dpe.contexts[root_idx].tci.tci_current.0);
        let latest_pcr = drivers.pcr_bank.read_pcr(RT_FW_JOURNEY_PCR);

        // Ensure TCI from SRAM == RT_FW_JOURNEY_PCR
        if latest_pcr != latest_tci {
            // If latest pcr validation fails, disable attestation
            let result = DisableAttestationCmd::execute(drivers);
            if cfi_launder(result.is_ok()) {
                cfi_assert!(result.is_ok());
            } else {
                cfi_assert!(result.is_err());
            }
            match result {
                Ok(_) => {
                    cprintln!("Disabled attestation due to latest TCI of the node containing the runtime journey PCR not matching the runtime PCR");
                    caliptra_drivers::report_fw_error_non_fatal(
                        CaliptraError::RUNTIME_RT_JOURNEY_PCR_VALIDATION_FAILED.into(),
                    );
                }
                Err(e) => {
                    cprintln!("{}", e.0);
                    return Err(CaliptraError::RUNTIME_GLOBAL_EXCEPTION);
                }
            }
        } else {
            cfi_assert_eq_12_words(
                &<[u32; 12]>::from(latest_tci),
                &<[u32; 12]>::from(latest_pcr),
            )
        }

        Ok(())
    }

    /// Check that inactive DPE contexts do not have context tags set
    fn validate_context_tags(mut drivers: &mut Drivers) -> CaliptraResult<()> {
        let pdata = drivers.persistent_data.get();
        let context_has_tag = &pdata.context_has_tag;
        let context_tags = &pdata.context_tags;
        let dpe = &pdata.dpe;

        for i in (0..MAX_HANDLES) {
            if dpe.contexts[i].state == ContextState::Inactive {
                if context_tags[i] != 0 {
                    return Err(CaliptraError::RUNTIME_CONTEXT_TAGS_VALIDATION_FAILED);
                } else if context_has_tag[i].get() {
                    return Err(CaliptraError::RUNTIME_CONTEXT_HAS_TAG_VALIDATION_FAILED);
                }
            }
        }
        Ok(())
    }

    /// Compute the Caliptra Name SerialNumber by Sha256 hashing the RT Alias public key
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn compute_rt_alias_sn(&mut self) -> CaliptraResult<CryptoBuf> {
        let key = self.persistent_data.get().fht.rt_dice_pub_key.to_der();

        let rt_digest = self.sha256.digest(&key)?;
        let token = CryptoBuf::new(&Into::<[u8; 32]>::into(rt_digest))
            .map_err(|_| CaliptraError::RUNTIME_COMPUTE_RT_ALIAS_SN_FAILED)?;

        Ok(token)
    }

    /// Initialize DPE with measurements and store in Drivers
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn initialize_dpe(drivers: &mut Drivers) -> CaliptraResult<()> {
        let caliptra_locality = 0xFFFFFFFF;
        let pl0_pauser_locality = drivers.persistent_data.get().manifest1.header.pl0_pauser;
        let hashed_rt_pub_key = drivers.compute_rt_alias_sn()?;

        // create a hash of all the mailbox valid pausers
        const PAUSER_COUNT: usize = 5;
        let mbox_valid_pauser: [u32; PAUSER_COUNT] = drivers.soc_ifc.mbox_valid_pauser();
        let mbox_pauser_lock: [bool; PAUSER_COUNT] = drivers.soc_ifc.mbox_pauser_lock();
        let mut digest_op = drivers.sha384.digest_init()?;
        for i in 0..PAUSER_COUNT {
            if mbox_pauser_lock[i] {
                digest_op.update(mbox_valid_pauser[i].as_bytes())?;
            }
        }
        let mut valid_pauser_hash = Array4x12::default();
        digest_op.finalize(&mut valid_pauser_hash)?;

        let key_id_rt_cdi = Drivers::get_key_id_rt_cdi(drivers)?;
        let key_id_rt_priv_key = Drivers::get_key_id_rt_priv_key(drivers)?;
        let pdata = drivers.persistent_data.get_mut();
        let mut crypto = DpeCrypto::new(
            &mut drivers.sha384,
            &mut drivers.trng,
            &mut drivers.ecc384,
            &mut drivers.hmac384,
            &mut drivers.key_vault,
            &mut pdata.fht.rt_dice_pub_key,
            key_id_rt_cdi,
            key_id_rt_priv_key,
        );

        let (nb, nf) = Self::get_cert_validity_info(&pdata.manifest1);
        let mut env = DpeEnv::<CptraDpeTypes> {
            crypto,
            platform: DpePlatform::new(
                caliptra_locality,
                &hashed_rt_pub_key,
                &drivers.cert_chain,
                &nb,
                &nf,
            ),
        };

        // Initialize DPE with the RT journey PCR
        let rt_journey_measurement = <[u8; DPE_PROFILE.get_hash_size()]>::from(
            &drivers.pcr_bank.read_pcr(RT_FW_JOURNEY_PCR),
        );
        let mut dpe = DpeInstance::new_auto_init(
            &mut env,
            DPE_SUPPORT,
            u32::from_be_bytes(*b"RTJM"),
            rt_journey_measurement,
        )
        .map_err(|_| CaliptraError::RUNTIME_INITIALIZE_DPE_FAILED)?;

        // Call DeriveContext to create a measurement for the mailbox valid pausers and change locality to the pl0 pauser locality
        let derive_context_resp = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: valid_pauser_hash
                .as_bytes()
                .try_into()
                .map_err(|_| CaliptraError::RUNTIME_ADD_VALID_PAUSER_MEASUREMENT_TO_DPE_FAILED)?,
            flags: DeriveContextFlags::MAKE_DEFAULT
                | DeriveContextFlags::CHANGE_LOCALITY
                | DeriveContextFlags::INPUT_ALLOW_CA
                | DeriveContextFlags::INPUT_ALLOW_X509,
            tci_type: u32::from_be_bytes(*b"MBVP"),
            target_locality: pl0_pauser_locality,
        }
        .execute(&mut dpe, &mut env, caliptra_locality);
        if let Err(e) = derive_context_resp {
            // If there is extended error info, populate CPTRA_FW_EXTENDED_ERROR_INFO
            if let Some(ext_err) = e.get_error_detail() {
                drivers.soc_ifc.set_fw_extended_error(ext_err);
            }
            Err(CaliptraError::RUNTIME_ADD_VALID_PAUSER_MEASUREMENT_TO_DPE_FAILED)?
        }

        // Call DeriveContext to create TCIs for each measurement added in ROM
        let num_measurements = pdata.fht.meas_log_index as usize;
        let measurement_log = pdata.measurement_log;
        for measurement_log_entry in measurement_log.iter().take(num_measurements) {
            // Check that adding this measurement to DPE doesn't cause
            // the PL0 context threshold to be exceeded.
            let pl0_pauser = pdata.manifest1.header.pl0_pauser;
            let flags = pdata.manifest1.header.flags;
            Self::is_dpe_context_threshold_exceeded(
                pl0_pauser_locality,
                flags,
                pl0_pauser_locality,
                &dpe,
                false,
            )?;

            let measurement_data = measurement_log_entry.pcr_entry.measured_data();
            let tci_type = u32::from_be_bytes(measurement_log_entry.metadata);
            let derive_context_resp = DeriveContextCmd {
                handle: ContextHandle::default(),
                data: measurement_data
                    .try_into()
                    .map_err(|_| CaliptraError::RUNTIME_ADD_ROM_MEASUREMENTS_TO_DPE_FAILED)?,
                flags: DeriveContextFlags::MAKE_DEFAULT
                    | DeriveContextFlags::CHANGE_LOCALITY
                    | DeriveContextFlags::INPUT_ALLOW_CA
                    | DeriveContextFlags::INPUT_ALLOW_X509,
                tci_type,
                target_locality: pl0_pauser_locality,
            }
            .execute(&mut dpe, &mut env, pl0_pauser_locality);
            if let Err(e) = derive_context_resp {
                // If there is extended error info, populate CPTRA_FW_EXTENDED_ERROR_INFO
                if let Some(ext_err) = e.get_error_detail() {
                    drivers.soc_ifc.set_fw_extended_error(ext_err);
                }
                Err(CaliptraError::RUNTIME_ADD_ROM_MEASUREMENTS_TO_DPE_FAILED)?
            }
        }

        // Write DPE to persistent data.
        pdata.dpe = dpe;
        Ok(())
    }

    /// Create certificate chain and store in Drivers
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn create_cert_chain(drivers: &mut Drivers) -> CaliptraResult<()> {
        let data_vault = &drivers.data_vault;
        let persistent_data = &drivers.persistent_data;
        let mut cert = [0u8; MAX_CERT_CHAIN_SIZE];

        // Write ldev_id cert to cert chain.
        let ldevid_cert_size =
            dice::copy_ldevid_cert(data_vault, persistent_data.get(), &mut cert)?;
        if ldevid_cert_size > cert.len() {
            return Err(CaliptraError::RUNTIME_LDEV_ID_CERT_TOO_BIG);
        }

        // Write fmc alias cert to cert chain.
        let fmcalias_cert_size = dice::copy_fmc_alias_cert(
            data_vault,
            persistent_data.get(),
            &mut cert[ldevid_cert_size..],
        )?;
        if ldevid_cert_size + fmcalias_cert_size > cert.len() {
            return Err(CaliptraError::RUNTIME_FMC_ALIAS_CERT_TOO_BIG);
        }

        // Write rt alias cert to cert chain.
        let rtalias_cert_size = dice::copy_rt_alias_cert(
            persistent_data.get(),
            &mut cert[ldevid_cert_size + fmcalias_cert_size..],
        )?;
        let cert_chain_size = ldevid_cert_size + fmcalias_cert_size + rtalias_cert_size;
        if cert_chain_size > cert.len() {
            return Err(CaliptraError::RUNTIME_RT_ALIAS_CERT_TOO_BIG);
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

    /// Counts the number of non-inactive DPE contexts and returns an error
    /// if this number is greater than or equal to the active context threshold
    /// corresponding to the privilege level of the caller.
    ///
    /// # Arguments
    ///
    /// * `pl0_pauser` - Value of PL0 PAuser
    /// * `flags` - Flags from manifest header
    /// * `locality` - Caller's locality
    /// * `dpe` - DpeInstance
    /// * `check_already_exceeded` - If true, checks that the active context threshold is already exceeded.
    pub fn is_dpe_context_threshold_exceeded(
        pl0_pauser: u32,
        flags: u32,
        locality: u32,
        dpe: &DpeInstance,
        check_already_exceeded: bool,
    ) -> CaliptraResult<()> {
        let used_pl0_dpe_context_count = dpe
            .count_contexts(|c: &Context| {
                c.state != ContextState::Inactive && c.locality == pl0_pauser
            })
            .map_err(|_| CaliptraError::RUNTIME_INTERNAL)?;
        // the number of used pl1 dpe contexts is the total number of used contexts
        // minus the number of used pl0 contexts, since a context can only be activated
        // from pl0 or from pl1. Here, used means an active or retired context.
        let used_pl1_dpe_context_count = dpe
            .count_contexts(|c: &Context| c.state != ContextState::Inactive)
            .map_err(|_| CaliptraError::RUNTIME_INTERNAL)?
            - used_pl0_dpe_context_count;

        match (
            Self::is_caller_pl1(pl0_pauser, flags, locality),
            used_pl1_dpe_context_count.cmp(&PL1_DPE_ACTIVE_CONTEXT_THRESHOLD),
            used_pl0_dpe_context_count.cmp(&PL0_DPE_ACTIVE_CONTEXT_THRESHOLD),
        ) {
            (true, Equal, _) => Err(CaliptraError::RUNTIME_PL1_USED_DPE_CONTEXT_THRESHOLD_REACHED),
            (true, Greater, _) => {
                Err(CaliptraError::RUNTIME_PL1_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED)
            }
            (false, _, Equal) => Err(CaliptraError::RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_REACHED),
            (false, _, Greater) => {
                Err(CaliptraError::RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED)
            }
            _ => Ok(()),
        }
    }

    /// Checks if the caller is privilege level 1
    ///
    /// # Arguments
    ///
    /// * `pl0_pauser` - Value of PL0 PAuser
    /// * `flags` - Flags from manifest header
    /// * `locality` - Caller's locality
    pub fn is_caller_pl1(pl0_pauser: u32, flags: u32, locality: u32) -> bool {
        flags & PL0_PAUSER_FLAG == 0 && locality != pl0_pauser
    }

    /// Get the KeyId for the RT Alias CDI
    ///
    /// # Arguments
    ///
    /// * `drivers` - Drivers
    ///
    /// # Returns
    ///
    /// * `KeyId` - RT Alias CDI
    pub fn get_key_id_rt_cdi(drivers: &Drivers) -> CaliptraResult<KeyId> {
        let ds: DataStore = drivers
            .persistent_data
            .get()
            .fht
            .rt_cdi_kv_hdl
            .try_into()
            .map_err(|_| CaliptraError::RUNTIME_CDI_KV_HDL_HANDOFF_FAILED)?;

        match ds {
            DataStore::KeyVaultSlot(key_id) => Ok(key_id),
            _ => Err(CaliptraError::RUNTIME_CDI_KV_HDL_HANDOFF_FAILED),
        }
    }

    /// Get the KeyId for the RT Alias private key
    ///
    /// # Arguments
    ///
    /// * `drivers` - Drivers
    ///
    /// # Returns
    ///
    /// * `KeyId` - RT Alias private key
    pub fn get_key_id_rt_priv_key(drivers: &Drivers) -> CaliptraResult<KeyId> {
        let ds: DataStore = drivers
            .persistent_data
            .get()
            .fht
            .rt_priv_key_kv_hdl
            .try_into()
            .map_err(|_| CaliptraError::RUNTIME_PRIV_KEY_KV_HDL_HANDOFF_FAILED)?;

        match ds {
            DataStore::KeyVaultSlot(key_id) => Ok(key_id),
            _ => Err(CaliptraError::RUNTIME_PRIV_KEY_KV_HDL_HANDOFF_FAILED),
        }
    }

    /// Process the certificate validity info
    ///
    /// # Arguments
    /// * `manifest` - Manifest
    ///
    /// # Returns
    /// * `NotBefore` - Valid Not Before Time
    /// * `NotAfter`  - Valid Not After Time
    ///
    pub fn get_cert_validity_info(manifest: &ImageManifest) -> (NotBefore, NotAfter) {
        // If there is a valid value in the manifest for the not_before and not_after times,
        // use those. Otherwise use the default values.
        let mut nb = NotBefore::default();
        let mut nf = NotAfter::default();
        let null_time = [0u8; 15];

        if manifest.header.vendor_data.vendor_not_after != null_time
            && manifest.header.vendor_data.vendor_not_before != null_time
        {
            nf.value = manifest.header.vendor_data.vendor_not_after;
            nb.value = manifest.header.vendor_data.vendor_not_before;
        }

        // Owner values take preference.
        if manifest.header.owner_data.owner_not_after != null_time
            && manifest.header.owner_data.owner_not_before != null_time
        {
            nf.value = manifest.header.owner_data.owner_not_after;
            nb.value = manifest.header.owner_data.owner_not_before;
        }

        (nb, nf)
    }
}
