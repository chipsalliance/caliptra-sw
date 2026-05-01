/*++

Licensed under the Apache-2.0 license.

File Name:

    drivers.rs

Abstract:

    File contains driver initializations.

--*/

#![cfg_attr(not(feature = "fips_self_test"), allow(unused))]

use crate::cryptographic_mailbox::CmStorage;
use crate::debug_unlock::ProductionDebugUnlock;
use crate::dpe_crypto::DpeCrypto;
#[cfg(feature = "fips_self_test")]
pub use crate::fips::fips_self_test_cmd::SelfTestStatus;
use crate::ocp_lock::OcpLockContext;
use crate::recovery_flow::RecoveryFlow;
use crate::CaliptraDpeEnv;
use crate::{
    dice, CaliptraDpeProfile, DisableAttestationCmd, DpePlatform, Mailbox, CALIPTRA_LOCALITY,
    DPE_SUPPORT, MAX_ECC_CERT_CHAIN_SIZE, MAX_MLDSA_CERT_CHAIN_SIZE,
    PL0_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD, PL0_PAUSER_FLAG,
    PL1_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD,
};

use arrayvec::ArrayVec;
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_cfi_lib::{
    cfi_assert, cfi_assert_bool, cfi_assert_eq, cfi_assert_eq_12_words, cfi_launder,
};
use caliptra_common::cfi_check;
use caliptra_common::crypto::Crypto;
use caliptra_common::dice::{copy_ldevid_ecc384_cert, copy_ldevid_mldsa87_cert};
use caliptra_common::mailbox_api::AddSubjectAltNameReq;
use caliptra_dpe::commands::DeriveContextCmd;
use caliptra_dpe::context::{Context, ContextState, ContextType};
use caliptra_dpe::response::DeriveContextResp;
use caliptra_dpe::tci::TciMeasurement;
use caliptra_dpe::validation::DpeValidator;
use caliptra_dpe::MAX_HANDLES;
use caliptra_dpe::{
    commands::{CommandExecution, DeriveContextFlags},
    context::ContextHandle,
    dpe_instance::DpeInstance,
};
use caliptra_dpe::{DpeFlags, DpeProfile};
use caliptra_dpe_crypto::ecdsa::curve_384::EcdsaPub384;
use caliptra_dpe_crypto::ecdsa::EcdsaPubKey;
use caliptra_dpe_crypto::{Digest, PubKey};
use caliptra_drivers::{
    cprintln,
    hand_off::DataStore,
    pcr_log::{RT_FW_CURRENT_PCR, RT_FW_JOURNEY_PCR},
    sha2_512_384::Sha2DigestOpTrait,
    Abr, Aes, Array4x12, CaliptraError, CaliptraResult, Ecc384, Hmac, KeyId, KeyVault, Lms,
    PcrBank, PersistentDataAccessor, Pic, ResetReason, Sha256, Sha256Alg, Sha2_512_384,
    Sha2_512_384Acc, Sha3, SocIfc, Trng,
};
use caliptra_drivers::{okref, Dma, DmaMmio, Mldsa87PubKey};
use caliptra_image_types::ImageManifest;
use caliptra_registers::aes::AesReg;
use caliptra_registers::aes_clp::AesClpReg;
use caliptra_registers::{
    abr::AbrReg, csrng::CsrngReg, ecc::EccReg, el2_pic_ctrl::El2PicCtrl,
    entropy_src::EntropySrcReg, hmac::HmacReg, kmac::Kmac as KmacReg, kv::KvReg, mbox::MboxCsr,
    pv::PvReg, sha256::Sha256Reg, sha512::Sha512Reg, sha512_acc::Sha512AccCsr, soc_ifc::SocIfcReg,
    soc_ifc_trng::SocIfcTrngReg,
};
use caliptra_ureg::MmioMut;
use caliptra_x509::{NotAfter, NotBefore};

use core::cmp::Ordering::{Equal, Greater};
use zerocopy::IntoBytes;

pub const MCI_TOP_REG_RESET_REASON_OFFSET: u32 = 0x38;

#[derive(PartialEq, Clone, Copy)]
pub enum PauserPrivileges {
    PL0,
    PL1,
}

#[derive(Debug, Copy, Clone)]
pub enum McuResetReason {
    Cold = 0,
    FwHitlessUpd = 0b1 << 0,
    FwBoot = 0b1 << 1,
    Warm = 0b1 << 2,
}

impl From<McuResetReason> for u32 {
    fn from(reason: McuResetReason) -> Self {
        reason as u32
    }
}

#[derive(Debug, Copy, Clone)]
pub enum McuFwStatus {
    NotLoaded,
    Loaded,
    HitlessUpdateStarted,
}

impl From<McuFwStatus> for u32 {
    fn from(status: McuFwStatus) -> Self {
        status as u32
    }
}

pub struct Drivers {
    pub mbox: Mailbox,
    pub sha_acc: Sha512AccCsr,
    pub key_vault: KeyVault,
    pub soc_ifc: SocIfc,
    pub sha256: Sha256,

    // SHA2-512/384 Engine
    pub sha2_512_384: Sha2_512_384,

    // SHA2-512/384 Accelerator
    pub sha2_512_384_acc: Sha2_512_384Acc,

    // SHA3/SHAKE Engine
    pub sha3: Sha3,

    /// Hmac-512/384 Engine
    pub hmac: Hmac,

    /// Cryptographically Secure Random Number Generator
    pub trng: Trng,

    /// Ecc384 Engine
    pub ecc384: Ecc384,

    /// ABR Engine (ML-DSA and ML-KEM)
    pub abr: Abr,

    pub persistent_data: PersistentDataAccessor,

    pub lms: Lms,

    pub pcr_bank: PcrBank,

    pub pic: Pic,

    // [CAP2][TODO] maybe use the Mbox Resp buffer to construct these are runtime rather than storing them here.
    // That should reduce the stack size by 28K
    pub ecc_cert_chain: ArrayVec<u8, MAX_ECC_CERT_CHAIN_SIZE>,

    pub mldsa_cert_chain: ArrayVec<u8, MAX_MLDSA_CERT_CHAIN_SIZE>,

    #[cfg(feature = "fips_self_test")]
    pub self_test_status: SelfTestStatus,

    pub is_shutdown: bool,

    pub dmtf_device_info: Option<ArrayVec<u8, { AddSubjectAltNameReq::MAX_DEVICE_INFO_LEN }>>,
    pub dma: Dma,

    pub cryptographic_mailbox: CmStorage,
    pub aes: Aes,

    pub debug_unlock: ProductionDebugUnlock,
    pub ocp_lock_context: OcpLockContext,

    /// MCU firmware metadata recorded during recovery.
    /// Queried by MCU ROM via GET_MCU_FW_SIZE during encrypted boot.
    pub mcu_fw_info: crate::get_mcu_fw_size::McuFwInfo,
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
            PersistentDataAccessor::new(),
        )?;

        let aes = Aes::new(AesReg::new(), AesClpReg::new())?;
        let soc_ifc = SocIfc::new(SocIfcReg::new());
        let persistent_data = PersistentDataAccessor::new();

        let hek_available = persistent_data.get().rom.ocp_lock_metadata.hek_available;
        let ocp_lock_context = OcpLockContext::new(&soc_ifc, &mut trng, hek_available)?;

        Ok(Self {
            mbox: Mailbox::new(MboxCsr::new()),
            sha_acc: Sha512AccCsr::new(),
            key_vault: KeyVault::new(KvReg::new()),
            soc_ifc,
            sha256: Sha256::new(Sha256Reg::new()),
            sha2_512_384: Sha2_512_384::new(Sha512Reg::new()),
            sha2_512_384_acc: Sha2_512_384Acc::new(Sha512AccCsr::new()),
            sha3: Sha3::new(KmacReg::new()),
            hmac: Hmac::new(HmacReg::new()),
            ecc384: Ecc384::new(EccReg::new()),
            abr: Abr::new(AbrReg::new()),
            lms: Lms::default(),
            trng,
            persistent_data,
            pcr_bank: PcrBank::new(PvReg::new()),
            pic: Pic::new(El2PicCtrl::new()),
            #[cfg(feature = "fips_self_test")]
            self_test_status: SelfTestStatus::Idle,
            ecc_cert_chain: ArrayVec::new(),
            mldsa_cert_chain: ArrayVec::new(),
            is_shutdown: false,
            dmtf_device_info: None,
            dma: Dma::default(),
            cryptographic_mailbox: CmStorage::new(),
            debug_unlock: ProductionDebugUnlock::new(),
            ocp_lock_context,
            aes,
            mcu_fw_info: crate::get_mcu_fw_size::McuFwInfo::default(),
        })
    }

    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    pub fn run_reset_flow(&mut self) -> CaliptraResult<()> {
        Self::create_cert_chain(self)?;
        self.cryptographic_mailbox
            .init(&self.persistent_data, &mut self.trng)?;
        if self.persistent_data.get().fw.dpe.attestation_disabled.get() {
            DisableAttestationCmd::execute(self)
                .map_err(|_| CaliptraError::RUNTIME_GLOBAL_EXCEPTION)?;
        }

        let reset_reason = self.soc_ifc.reset_reason();
        match reset_reason {
            ResetReason::ColdReset => {
                cfi_assert_eq(self.soc_ifc.reset_reason(), ResetReason::ColdReset);
                Self::initialize_dpe(self)?;
                if self.soc_ifc.subsystem_mode() {
                    RecoveryFlow::recovery_flow(self)?;
                }
            }
            ResetReason::UpdateReset => {
                cfi_assert_eq(self.soc_ifc.reset_reason(), ResetReason::UpdateReset);
                Self::validate_dpe_structure(self)?;
                Self::validate_context_tags(self)?;
                Self::update_dpe_rt_tci(self)?;
                Self::update_dpe_cciv(self)?;
            }
            ResetReason::WarmReset => {
                cfi_assert_eq(self.soc_ifc.reset_reason(), ResetReason::WarmReset);
                Self::validate_dpe_structure(self)?;
                Self::validate_context_tags(self)?;
                Self::check_dpe_rt_pcrs_unchanged(self)?;
                Self::update_fw_version(self, true, true);
                if self.soc_ifc.subsystem_mode() {
                    Self::release_mcu_sram(self)?;
                }
            }
            ResetReason::Unknown => {
                cfi_assert_eq(self.soc_ifc.reset_reason(), ResetReason::Unknown);
                return Err(CaliptraError::RUNTIME_UNKNOWN_RESET_FLOW);
            }
        }

        Ok(())
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
    pub fn get_dpe_root_context_idx(dpe: &caliptra_dpe::State) -> CaliptraResult<usize> {
        // Find root node by finding the non-inactive context with parent equal to ROOT_INDEX
        let root_idx = dpe
            .contexts
            .iter()
            .enumerate()
            .find(|&(_idx, context)| {
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

    /// Returns the index of the single CCIV context that is an immediate child of the DPE root.
    /// Errors if none or if multiple are found.
    ///
    /// # Arguments
    ///
    /// * `dpe` - DpeInstance
    ///
    /// # Returns
    ///
    /// * `usize` - Index containing the CCIV DPE context
    #[inline(always)]
    pub fn get_dpe_cciv_context_idx(dpe: &caliptra_dpe::State) -> CaliptraResult<usize> {
        // Find the root context index using your existing helper
        let root_idx = Self::get_dpe_root_context_idx(dpe)? as u8;

        let cciv_type = u32::from_be_bytes(*b"CCIV");
        let mut found_idx: Option<usize> = None;

        // Search only immediate children of root for an active, Normal CCIV context
        for (idx, ctx) in dpe.contexts.iter().enumerate() {
            if ctx.state != ContextState::Inactive
                && ctx.context_type == ContextType::Normal
                && ctx.parent_idx == root_idx
                && ctx.tci.tci_type == cciv_type
            {
                if found_idx.is_some() {
                    // Multiple CCIV children found under root
                    return Err(CaliptraError::RUNTIME_MULTIPLE_CCIV_CONTEXTS_FOUND);
                }
                found_idx = Some(idx);
            }
        }

        match found_idx {
            Some(idx) => {
                // prevent panic
                if idx >= dpe.contexts.len() {
                    return Err(CaliptraError::RUNTIME_CCIV_CONTEXT_NOT_FOUND);
                }
                Ok(idx)
            }
            None => Err(CaliptraError::RUNTIME_CCIV_CONTEXT_NOT_FOUND),
        }
    }

    pub fn set_mcu_reset_reason(drivers: &mut Drivers, reason: McuResetReason) {
        let dma = &drivers.dma;
        let mci_base_addr = drivers.soc_ifc.mci_base_addr().into();
        let mmio = &DmaMmio::new(mci_base_addr, dma);
        unsafe { mmio.write_volatile(MCI_TOP_REG_RESET_REASON_OFFSET as *mut u32, reason.into()) };
    }

    pub fn request_mcu_reset(drivers: &mut Drivers, reason: McuResetReason) {
        Self::set_mcu_reset_reason(drivers, reason);
        drivers.soc_ifc.set_mcu_firmware_ready();
    }

    /// Validate DPE and disable attestation if validation fails
    fn validate_dpe_structure(drivers: &mut Drivers) -> CaliptraResult<()> {
        let dpe = &mut drivers.persistent_data.get_mut().fw.dpe.state;
        let dpe_validator = DpeValidator { dpe };
        let validation_result = dpe_validator.validate_dpe();
        if let Err(e) = validation_result {
            // If SRAM Dpe Instance validation fails, disable attestation
            let result = DisableAttestationCmd::execute(drivers);
            cfi_check!(result);
            match result {
                Ok(_) => {
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
            let _pl0_pauser = drivers
                .persistent_data
                .get()
                .rom
                .manifest1
                .header
                .pl0_pauser;
            // check that DPE used context limits are not exceeded
            let dpe_context_threshold_exceeded =
                drivers.is_dpe_context_threshold_exceeded(drivers.caller_privilege_level());
            cfi_check!(dpe_context_threshold_exceeded);
            if let Err(e) = dpe_context_threshold_exceeded {
                let result = DisableAttestationCmd::execute(drivers);
                cfi_check!(result);
                match result {
                    Ok(_) => {
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
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    fn update_dpe_rt_tci(drivers: &mut Drivers) -> CaliptraResult<()> {
        let dpe = &mut drivers.persistent_data.get_mut().fw.dpe.state;
        let root_idx = Self::get_dpe_root_context_idx(dpe)?;
        let current_pcr = <[u8; 48]>::from(drivers.pcr_bank.read_pcr(RT_FW_CURRENT_PCR));
        let journey_pcr = <[u8; 48]>::from(drivers.pcr_bank.read_pcr(RT_FW_JOURNEY_PCR));
        dpe.contexts[root_idx].tci.tci_current = TciMeasurement(current_pcr);
        dpe.contexts[root_idx].tci.tci_cumulative = TciMeasurement(journey_pcr);

        Ok(())
    }

    /// Update DPE CCIV measurement with new values
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    fn update_dpe_cciv(drivers: &mut Drivers) -> CaliptraResult<()> {
        if drivers
            .persistent_data
            .get()
            .fw
            .dpe
            .attestation_disabled
            .get()
        {
            // If attestation is disabled, do not attempt to update CCIV values
            return Ok(());
        }
        let initialization_values_hash: [u8; 48] =
            <[u8; 48]>::from(Self::compute_initialization_values_hash(drivers)?);
        let dpe = &mut drivers.persistent_data.get_mut().fw.dpe.state;
        let cciv_idx = Self::get_dpe_cciv_context_idx(dpe)?;

        // Only update if changed
        let prev_current: [u8; 48] = dpe.contexts[cciv_idx].tci.tci_current.0;
        if prev_current == initialization_values_hash {
            return Ok(());
        }

        // Compute new journey: SHA-384(prev_journey || initialization_values_hash)
        let prev_journey: [u8; 48] = dpe.contexts[cciv_idx].tci.tci_cumulative.0;
        let mut digest_op = drivers.sha2_512_384.sha384_digest_init()?;
        digest_op.update(&prev_journey)?;
        digest_op.update(&initialization_values_hash)?;
        let mut journey_hash = Array4x12::default();
        digest_op.finalize(&mut journey_hash)?;
        let new_journey: [u8; 48] = journey_hash.into();

        // Update CCIV current and cumulative
        dpe.contexts[cciv_idx].tci.tci_current = TciMeasurement(initialization_values_hash);
        dpe.contexts[cciv_idx].tci.tci_cumulative = TciMeasurement(new_journey);

        Ok(())
    }

    fn update_fw_version(drivers: &mut Drivers, update_fmc_ver: bool, update_rt_ver: bool) {
        // This is a temp workaround since cptra_fw_rev_id registers are not sticky on a warm reset.
        if update_fmc_ver {
            drivers
                .soc_ifc
                .set_fmc_fw_rev_id(drivers.persistent_data.get().rom.manifest1.fmc.version as u16);
        }
        if update_rt_ver {
            drivers
                .soc_ifc
                .set_rt_fw_rev_id(drivers.persistent_data.get().rom.manifest1.runtime.version);
        }
    }

    /// Release MCU SRAM if MCU FW was previously loaded correctly
    fn release_mcu_sram(drivers: &mut Drivers) -> CaliptraResult<()> {
        // Check if MCU previous Cold-Reset was successful.
        let mcu_firmware_loaded = drivers.persistent_data.get().fw.mcu_firmware_loaded;
        if mcu_firmware_loaded == McuFwStatus::NotLoaded.into() {
            cprintln!("[rt-warm-reset] Warning: Prev Cold Reset failed, not releasing MCU SRAM");
        }

        // Check if MCU previous Update-Reset, if any, was successful.
        if mcu_firmware_loaded == McuFwStatus::HitlessUpdateStarted.into() {
            cprintln!(
                "[rt-warm-reset] Warning: Prev Hitless Update Reset failed, not releasing MCU SRAM"
            );
        }

        cfi_assert_eq(mcu_firmware_loaded, McuFwStatus::Loaded.into());
        cprintln!("[rt-warm-reset] MCU FW is loaded in SRAM");
        Self::request_mcu_reset(drivers, McuResetReason::FwBoot);

        Ok(())
    }

    /// Check that RT_FW_JOURNEY_PCR == DPE Root Context's TCI measurement
    fn check_dpe_rt_pcrs_unchanged(drivers: &mut Drivers) -> CaliptraResult<()> {
        let dpe = &drivers.persistent_data.get().fw.dpe.state;
        let root_idx = Self::get_dpe_root_context_idx(dpe)?;
        let latest_tci = Array4x12::from(&dpe.contexts[root_idx].tci.tci_current.0);
        let latest_pcr = drivers.pcr_bank.read_pcr(RT_FW_CURRENT_PCR);
        let journey_tci = Array4x12::from(&dpe.contexts[root_idx].tci.tci_cumulative.0);
        let journey_pcr = drivers.pcr_bank.read_pcr(RT_FW_JOURNEY_PCR);

        // Ensure TCIs from SRAM == PCRs
        if latest_pcr != latest_tci || journey_pcr != journey_tci {
            // If pcr validation fails, disable attestation
            let result = DisableAttestationCmd::execute(drivers);
            cfi_check!(result);
            match result {
                Ok(_) => {
                    let error = if latest_pcr != latest_tci {
                        CaliptraError::RUNTIME_RT_CURRENT_PCR_VALIDATION_FAILED
                    } else {
                        CaliptraError::RUNTIME_RT_JOURNEY_PCR_VALIDATION_FAILED
                    };

                    caliptra_drivers::report_fw_error_non_fatal(error.into());
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
            );
            cfi_assert_eq_12_words(
                &<[u32; 12]>::from(journey_tci),
                &<[u32; 12]>::from(journey_pcr),
            );
        }

        Ok(())
    }

    /// Check that inactive DPE contexts do not have context tags set
    fn validate_context_tags(drivers: &mut Drivers) -> CaliptraResult<()> {
        let pdata = drivers.persistent_data.get();
        let context_has_tag = &pdata.fw.dpe.context_has_tag;
        let context_tags = &pdata.fw.dpe.context_tags;
        let dpe = &pdata.fw.dpe.state;

        for i in 0..MAX_HANDLES {
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
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    pub fn compute_ecc_rt_alias_sn(&mut self) -> CaliptraResult<Digest> {
        let key = self
            .persistent_data
            .get()
            .rom
            .fht
            .rt_dice_ecc_pub_key
            .to_der();

        let rt_digest = self.sha256.digest(&key)?;
        let token = Digest::Sha256(caliptra_dpe_crypto::Sha256(rt_digest.into()));

        Ok(token)
    }

    /// Compute the Caliptra Name SerialNumber by Sha256 hashing the RT Alias public key
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    pub fn compute_mldsa_rt_alias_sn(&mut self) -> CaliptraResult<Digest> {
        let key = Self::get_key_id_rt_mldsa_pub_key(self);
        let key = okref(&key)?;

        let rt_digest = self.sha256.digest(key.as_bytes())?;
        let token = Digest::Sha256(caliptra_dpe_crypto::Sha256(rt_digest.into()));

        Ok(token)
    }

    /// Initialize DPE with measurements and store in Drivers
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    fn initialize_dpe(drivers: &mut Drivers) -> CaliptraResult<()> {
        // NOTE: All initialization in this function is done using the ECC P384 profile because
        // these operations are profile agnostic. Using the ML-DSA-87 profile would have an equal
        // outcome.

        let manifest = drivers.persistent_data.get().rom.manifest1;
        let pl0_pauser_locality = manifest.header.pl0_pauser;
        let hashed_rt_pub_key = drivers.compute_ecc_rt_alias_sn()?;
        let privilege_level = drivers.caller_privilege_level();

        // Set context limits in persistent data as we init DPE
        drivers.persistent_data.get_mut().fw.dpe.pl0_context_limit =
            PL0_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD as u8;
        drivers.persistent_data.get_mut().fw.dpe.pl1_context_limit =
            PL1_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD as u8;
        let pl0_context_limit = drivers.persistent_data.get().fw.dpe.pl0_context_limit;
        let pl1_context_limit = drivers.persistent_data.get().fw.dpe.pl1_context_limit;

        // Create a hash of critical initialization values
        let initialization_values_hash = Self::compute_initialization_values_hash(drivers)?;

        let key_id_rt_cdi = Drivers::get_key_id_rt_cdi(drivers)?;
        let key_id_rt_priv_key = Drivers::get_key_id_rt_ecc_priv_key(drivers)?;
        let pdata = drivers.persistent_data.get_mut();
        let rt_pub_key = &mut pdata.rom.fht.rt_dice_ecc_pub_key;
        let rt_pub_key = PubKey::Ecdsa(EcdsaPubKey::Ecdsa384(EcdsaPub384::from_slice(
            &rt_pub_key.x.into(),
            &rt_pub_key.y.into(),
        )));
        let crypto = DpeCrypto::new_ecc384(
            &mut drivers.sha2_512_384,
            &mut drivers.trng,
            &mut drivers.ecc384,
            &mut drivers.hmac,
            &mut drivers.key_vault,
            rt_pub_key,
            key_id_rt_cdi,
            key_id_rt_priv_key,
            &mut pdata.fw.dpe.exported_cdi_slots,
        )?;

        let (nb, nf) = Self::get_cert_validity_info(&pdata.rom.manifest1);
        let mut state = caliptra_dpe::State::new(DPE_SUPPORT, DpeFlags::empty());
        let mut env = CaliptraDpeEnv {
            crypto,
            platform: DpePlatform::new(
                CaliptraDpeProfile::Ecc384,
                CALIPTRA_LOCALITY,
                hashed_rt_pub_key,
                &drivers.ecc_cert_chain,
                nb,
                nf,
                None,
                None,
            ),
            state: &mut state,
        };

        // Initialize DPE with the RT current PCR
        let current_pcr = TciMeasurement(drivers.pcr_bank.read_pcr(RT_FW_CURRENT_PCR).into());
        let mut dpe = DpeInstance::new_auto_init(
            &mut env,
            DpeProfile::P384Sha384,
            u32::from_be_bytes(*b"RTMR"),
            &current_pcr,
        )
        .map_err(|_| CaliptraError::RUNTIME_INITIALIZE_DPE_FAILED)?;

        // DPE internally extends the current measurement to set the cumulative measurement. Set it
        // to the journey PCR so it follows the hardware.
        let root_idx = Self::get_dpe_root_context_idx(env.state)?;
        env.state.contexts[root_idx].tci.tci_cumulative =
            TciMeasurement(drivers.pcr_bank.read_pcr(RT_FW_JOURNEY_PCR).into());

        // Call DeriveContext to create a measurement for the caliptra configured initialization values and change
        // locality to the pl0 pauser locality
        let mut derive_context_resp_buf = [0u32; size_of::<DeriveContextResp>() / 4];
        let derive_context_resp = derive_context_resp_buf.as_mut_bytes();
        let result = DeriveContextCmd {
            handle: ContextHandle::default(),
            data: TciMeasurement(<[u8; 48]>::from(initialization_values_hash)),
            flags: DeriveContextFlags::MAKE_DEFAULT
                | DeriveContextFlags::CHANGE_LOCALITY
                | DeriveContextFlags::ALLOW_NEW_CONTEXT_TO_EXPORT
                | DeriveContextFlags::INPUT_ALLOW_X509
                | DeriveContextFlags::ALLOW_RECURSIVE,
            tci_type: u32::from_be_bytes(*b"CCIV"),
            target_locality: pl0_pauser_locality,
            svn: 0,
        }
        .execute_serialized(&mut dpe, &mut env, CALIPTRA_LOCALITY, derive_context_resp);
        if let Err(e) = result {
            // If there is extended error info, populate CPTRA_FW_EXTENDED_ERROR_INFO
            if let Some(ext_err) = e.get_error_detail() {
                drivers.soc_ifc.set_fw_extended_error(ext_err);
            }
            Err(CaliptraError::RUNTIME_ADD_CCIV_MEASUREMENT_TO_DPE_FAILED)?
        }

        // Call DeriveContext to create TCIs for each measurement added in ROM
        let num_measurements = pdata.rom.fht.meas_log_index as usize;
        let measurement_log = pdata.rom.measurement_log;
        for measurement_log_entry in measurement_log.iter().take(num_measurements) {
            // Check that adding this measurement to DPE doesn't cause
            // the PL0 context threshold to be exceeded.
            //
            // Use the helper method here because the DPE instance holds a mutable reference to driver
            Self::is_dpe_context_threshold_exceeded_helper(
                pl0_pauser_locality,
                privilege_level,
                env.state,
                pl0_context_limit as usize,
                pl1_context_limit as usize,
            )?;

            let measurement_data = measurement_log_entry.pcr_entry.measured_data();
            let tci_type = u32::from_ne_bytes(measurement_log_entry.metadata);
            let result = DeriveContextCmd {
                handle: ContextHandle::default(),
                data: TciMeasurement(
                    measurement_data
                        .try_into()
                        .map_err(|_| CaliptraError::RUNTIME_ADD_ROM_MEASUREMENTS_TO_DPE_FAILED)?,
                ),
                flags: DeriveContextFlags::MAKE_DEFAULT
                    | DeriveContextFlags::CHANGE_LOCALITY
                    | DeriveContextFlags::ALLOW_NEW_CONTEXT_TO_EXPORT
                    | DeriveContextFlags::INPUT_ALLOW_X509
                    | DeriveContextFlags::ALLOW_RECURSIVE,
                tci_type,
                target_locality: pl0_pauser_locality,
                svn: measurement_log_entry.svn,
            }
            .execute_serialized(
                &mut dpe,
                &mut env,
                pl0_pauser_locality,
                derive_context_resp,
            );
            if let Err(e) = result {
                // If there is extended error info, populate CPTRA_FW_EXTENDED_ERROR_INFO
                if let Some(ext_err) = e.get_error_detail() {
                    drivers.soc_ifc.set_fw_extended_error(ext_err);
                }
                Err(CaliptraError::RUNTIME_ADD_ROM_MEASUREMENTS_TO_DPE_FAILED)?
            }
        }

        // Tell the compiler env is no longer needed so the state can be copied to persistent data.
        // Otherwise the error, "cannot move out of `state` because it is borrowed" is given.
        drop(env);

        // Write DPE to persistent data.
        pdata.fw.dpe.state = state;
        Ok(())
    }

    /// Create certificate chain and store in Drivers
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    fn create_cert_chain(drivers: &mut Drivers) -> CaliptraResult<()> {
        Self::create_ecc_cert_chain(drivers)?;
        Self::create_mldsa_cert_chain(drivers)
    }

    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    fn create_ecc_cert_chain(drivers: &mut Drivers) -> CaliptraResult<()> {
        let persistent_data = &drivers.persistent_data;

        // Clear and resize the cert chain to have space for writing
        drivers.ecc_cert_chain.clear();
        for _ in 0..MAX_ECC_CERT_CHAIN_SIZE {
            drivers
                .ecc_cert_chain
                .try_push(0)
                .map_err(|_| CaliptraError::RUNTIME_CERT_CHAIN_CREATION_FAILED)?;
        }

        // Write ldev_id cert to cert chain.
        let ldevid_cert_size =
            copy_ldevid_ecc384_cert(persistent_data.get(), drivers.ecc_cert_chain.as_mut_slice())?;
        if ldevid_cert_size > drivers.ecc_cert_chain.len() {
            return Err(CaliptraError::RUNTIME_LDEV_ID_CERT_TOO_BIG);
        }

        // Write fmc alias cert to cert chain.
        let fmcalias_cert_size = dice::copy_fmc_alias_ecc384_cert(
            persistent_data.get(),
            &mut drivers.ecc_cert_chain.as_mut_slice()[ldevid_cert_size..],
        )?;
        if ldevid_cert_size + fmcalias_cert_size > drivers.ecc_cert_chain.len() {
            return Err(CaliptraError::RUNTIME_FMC_ALIAS_CERT_TOO_BIG);
        }

        // Write rt alias cert to cert chain.
        let rtalias_cert_size = dice::copy_rt_alias_ecc384_cert(
            persistent_data.get(),
            &mut drivers.ecc_cert_chain.as_mut_slice()[ldevid_cert_size + fmcalias_cert_size..],
        )?;
        let cert_chain_size = ldevid_cert_size + fmcalias_cert_size + rtalias_cert_size;
        if cert_chain_size > drivers.ecc_cert_chain.len() {
            return Err(CaliptraError::RUNTIME_RT_ALIAS_CERT_TOO_BIG);
        }

        // Truncate to actual used size
        drivers.ecc_cert_chain.truncate(cert_chain_size);

        Ok(())
    }

    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    fn create_mldsa_cert_chain(drivers: &mut Drivers) -> CaliptraResult<()> {
        let persistent_data = &drivers.persistent_data;

        // Clear and resize the cert chain to have space for writing
        drivers.mldsa_cert_chain.clear();
        for _ in 0..MAX_MLDSA_CERT_CHAIN_SIZE {
            drivers
                .mldsa_cert_chain
                .try_push(0)
                .map_err(|_| CaliptraError::RUNTIME_CERT_CHAIN_CREATION_FAILED)?;
        }

        // Write ldev_id cert to cert chain.
        let ldevid_cert_size = copy_ldevid_mldsa87_cert(
            persistent_data.get(),
            drivers.mldsa_cert_chain.as_mut_slice(),
        )?;
        if ldevid_cert_size > drivers.mldsa_cert_chain.len() {
            return Err(CaliptraError::RUNTIME_LDEV_ID_CERT_TOO_BIG);
        }

        // Write fmc alias cert to cert chain.
        let fmcalias_cert_size = dice::copy_fmc_alias_mldsa87_cert(
            persistent_data.get(),
            &mut drivers.mldsa_cert_chain.as_mut_slice()[ldevid_cert_size..],
        )?;
        if ldevid_cert_size + fmcalias_cert_size > drivers.mldsa_cert_chain.len() {
            return Err(CaliptraError::RUNTIME_FMC_ALIAS_CERT_TOO_BIG);
        }

        // Write rt alias cert to cert chain.
        let rtalias_cert_size = dice::copy_rt_alias_mldsa87_cert(
            persistent_data.get(),
            &mut drivers.mldsa_cert_chain.as_mut_slice()[ldevid_cert_size + fmcalias_cert_size..],
        )?;
        let cert_chain_size = ldevid_cert_size + fmcalias_cert_size + rtalias_cert_size;
        if cert_chain_size > drivers.mldsa_cert_chain.len() {
            return Err(CaliptraError::RUNTIME_RT_ALIAS_CERT_TOO_BIG);
        }

        // Truncate to actual used size
        drivers.mldsa_cert_chain.truncate(cert_chain_size);

        Ok(())
    }

    /// Counts the number of non-inactive DPE contexts
    pub fn dpe_get_used_context_counts(&self) -> CaliptraResult<(usize, usize)> {
        Self::dpe_get_used_context_counts_helper(
            self.persistent_data.get().rom.manifest1.header.pl0_pauser,
            &self.persistent_data.get().fw.dpe.state,
        )
    }

    fn dpe_get_used_context_counts_helper(
        pl0_pauser: u32,
        dpe: &caliptra_dpe::State,
    ) -> CaliptraResult<(usize, usize)> {
        let used_pl0_dpe_context_count = dpe
            .count_contexts(|c: &Context| {
                c.state != ContextState::Inactive
                    && (c.locality == pl0_pauser || c.locality == CALIPTRA_LOCALITY)
            })
            .map_err(|_| CaliptraError::RUNTIME_INTERNAL)?;
        // the number of used pl1 dpe contexts is the total number of used contexts
        // minus the number of used pl0 contexts, since a context can only be activated
        // from pl0 or from pl1. Here, used means an active or retired context.
        let used_pl1_dpe_context_count = dpe
            .count_contexts(|c: &Context| c.state != ContextState::Inactive)
            .map_err(|_| CaliptraError::RUNTIME_INTERNAL)?
            - used_pl0_dpe_context_count;

        Ok((used_pl0_dpe_context_count, used_pl1_dpe_context_count))
    }

    /// Counts the number of non-inactive DPE contexts and returns an error
    /// if this number is greater than or equal to the active context threshold
    /// corresponding to the privilege level provided.
    pub fn is_dpe_context_threshold_exceeded(
        &self,
        context_privilege_level: PauserPrivileges,
    ) -> CaliptraResult<()> {
        let dpe_data = &self.persistent_data.get().fw.dpe;
        Self::is_dpe_context_threshold_exceeded_helper(
            self.persistent_data.get().rom.manifest1.header.pl0_pauser,
            context_privilege_level,
            &dpe_data.state,
            dpe_data.pl0_context_limit as usize,
            dpe_data.pl1_context_limit as usize,
        )
    }

    fn is_dpe_context_threshold_exceeded_helper(
        pl0_pauser: u32,
        caller_privilege_level: PauserPrivileges,
        dpe: &caliptra_dpe::State,
        pl0_context_limit: usize,
        pl1_context_limit: usize,
    ) -> CaliptraResult<()> {
        let (used_pl0_dpe_context_count, used_pl1_dpe_context_count) =
            Self::dpe_get_used_context_counts_helper(pl0_pauser, dpe)?;

        match (
            caller_privilege_level,
            used_pl1_dpe_context_count.cmp(&pl1_context_limit),
            used_pl0_dpe_context_count.cmp(&pl0_context_limit),
        ) {
            (PauserPrivileges::PL1, Equal, _) => {
                Err(CaliptraError::RUNTIME_PL1_USED_DPE_CONTEXT_THRESHOLD_REACHED)
            }
            (PauserPrivileges::PL1, Greater, _) => {
                Err(CaliptraError::RUNTIME_PL1_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED)
            }
            (PauserPrivileges::PL0, _, Equal) => {
                Err(CaliptraError::RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_REACHED)
            }
            (PauserPrivileges::PL0, _, Greater) => {
                Err(CaliptraError::RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED)
            }
            _ => Ok(()),
        }
    }

    /// Retrieves the caller permission level
    pub fn caller_privilege_level(&self) -> PauserPrivileges {
        let locality = self.mbox.id();
        self.privilege_level_from_locality(locality)
    }

    pub fn privilege_level_from_locality(&self, locality: u32) -> PauserPrivileges {
        let manifest_header = self.persistent_data.get().rom.manifest1.header;
        let flags = manifest_header.flags;
        let pl0_pauser = manifest_header.pl0_pauser;

        // When the PL0_PAUSER_FLAG bit is not set there can be no PL0 PAUSER.
        if flags & PL0_PAUSER_FLAG == 0 {
            return PauserPrivileges::PL1;
        }

        if locality == pl0_pauser {
            PauserPrivileges::PL0
        } else {
            PauserPrivileges::PL1
        }
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
            .rom
            .fht
            .rt_cdi_kv_hdl
            .try_into()
            .map_err(|_| CaliptraError::RUNTIME_CDI_KV_HDL_HANDOFF_FAILED)?;

        match ds {
            DataStore::KeyVaultSlot(key_id) => Ok(key_id),
            _ => Err(CaliptraError::RUNTIME_CDI_KV_HDL_HANDOFF_FAILED),
        }
    }

    /// Get the KeyId for the RT ECC Alias private key
    ///
    /// # Arguments
    ///
    /// * `drivers` - Drivers
    ///
    /// # Returns
    ///
    /// * `KeyId` - RT Alias private key
    pub fn get_key_id_rt_ecc_priv_key(drivers: &Drivers) -> CaliptraResult<KeyId> {
        let ds: DataStore = drivers
            .persistent_data
            .get()
            .rom
            .fht
            .rt_ecc_priv_key_kv_hdl
            .try_into()
            .map_err(|_| CaliptraError::RUNTIME_PRIV_KEY_KV_HDL_HANDOFF_FAILED)?;

        match ds {
            DataStore::KeyVaultSlot(key_id) => Ok(key_id),
            _ => Err(CaliptraError::RUNTIME_PRIV_KEY_KV_HDL_HANDOFF_FAILED),
        }
    }

    /// Get the KeyId for the RT ML-DSA Alias key pair seed
    ///
    /// # Arguments
    ///
    /// * `drivers` - Drivers
    ///
    /// # Returns
    ///
    /// * `KeyId` - RT Alias private key
    pub fn get_key_id_rt_mldsa_keypair_seed(drivers: &Drivers) -> CaliptraResult<KeyId> {
        let ds: DataStore = drivers
            .persistent_data
            .get()
            .rom
            .fht
            .rt_mldsa_keypair_seed_kv_hdl
            .try_into()
            .map_err(|_| CaliptraError::RUNTIME_PRIV_KEY_KV_HDL_HANDOFF_FAILED)?;

        match ds {
            DataStore::KeyVaultSlot(key_id) => Ok(key_id),
            _ => Err(CaliptraError::RUNTIME_PRIV_KEY_KV_HDL_HANDOFF_FAILED),
        }
    }

    /// Get the Public Key for the RT ML-DSA Alias key pair seed
    ///
    /// # Arguments
    ///
    /// * `drivers` - Drivers
    ///
    /// # Returns
    ///
    /// * `Mldsa87PubKey` - RT Alias pub key
    pub fn get_key_id_rt_mldsa_pub_key(drivers: &mut Drivers) -> CaliptraResult<Mldsa87PubKey> {
        let rt_cdi = Self::get_key_id_rt_cdi(drivers)?;
        let rt_mldsa_key = Self::get_key_id_rt_mldsa_keypair_seed(drivers)?;
        let mldsa_key_pair = drivers.abr.with_mldsa87(|mut mldsa87| {
            Crypto::mldsa87_key_gen(
                &mut mldsa87,
                &mut drivers.hmac,
                &mut drivers.trng,
                rt_cdi,
                b"alias_rt_mldsa_key",
                rt_mldsa_key,
            )
        })?;
        Ok(mldsa_key_pair.pub_key)
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

    /// Computes the SHA-384 hash over critical initialization values
    /// This includes mailbox valid pausers (for locked slots) and select fields from the manifest
    ///
    /// # Arguments
    ///
    /// * `drivers` - Drivers
    ///
    /// # Returns
    ///
    /// * `Array4x12` - SHA-384 hash of the initialization values
    fn compute_initialization_values_hash(drivers: &mut Drivers) -> CaliptraResult<Array4x12> {
        let manifest = drivers.persistent_data.get().rom.manifest1;

        // Collect mailbox pausers and lock states
        const PAUSER_COUNT: usize = 5;
        let mbox_valid_pauser: [u32; PAUSER_COUNT] = drivers.soc_ifc.mbox_valid_pauser();
        let mbox_pauser_lock: [bool; PAUSER_COUNT] = drivers.soc_ifc.mbox_pauser_lock();

        // Build digest over locked mailbox pausers and manifest fields
        let mut digest_op = drivers.sha2_512_384.sha384_digest_init()?;
        for i in 0..PAUSER_COUNT {
            if mbox_pauser_lock[i] {
                digest_op.update(mbox_valid_pauser[i].as_bytes())?;
            }
        }
        digest_op.update(manifest.header.pl0_pauser.as_bytes())?;
        digest_op.update(manifest.header.flags.as_bytes())?;
        digest_op.update(manifest.fmc.load_addr.as_bytes())?;
        digest_op.update(manifest.fmc.entry_point.as_bytes())?;
        digest_op.update(manifest.runtime.load_addr.as_bytes())?;
        digest_op.update(manifest.runtime.entry_point.as_bytes())?;

        // Finalize digest into Array4x12 (48 bytes for SHA-384)
        let mut initialization_values_hash = Array4x12::default();
        digest_op.finalize(&mut initialization_values_hash)?;
        Ok(initialization_values_hash)
    }
}
