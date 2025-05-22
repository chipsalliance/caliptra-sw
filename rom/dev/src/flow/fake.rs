/*++

Licensed under the Apache-2.0 license.

File Name:

    fake.rs

Abstract:

    File contains the implementation of the fake ROM reset flows

--*/

#[cfg(not(feature = "fake-rom"))]
compile_error!("This file should NEVER be included except for the fake-rom feature");

use crate::fht;
use crate::flow::cold_reset::fw_processor::FirmwareProcessor;
use crate::flow::update_reset;
use crate::flow::warm_reset;
use crate::print::HexBytes;
use crate::rom_env::RomEnv;
use caliptra_common::keyids::KEY_ID_ROM_FMC_CDI;
use caliptra_common::FirmwareHandoffTable;
use caliptra_common::RomBootStatus::*;
use caliptra_drivers::cprintln;
use caliptra_drivers::Lifecycle;
use caliptra_drivers::LmsResult;
use caliptra_drivers::VendorEccPubKeyRevocation;
use caliptra_drivers::*;
use caliptra_error::CaliptraError;
use caliptra_image_types::*;
use caliptra_image_verify::ImageVerificationEnv;
use caliptra_registers::sha512_acc::Sha512AccCsr;
use core::ops::Range;

include!(concat!(env!("OUT_DIR"), "/fake_consts.rs"));

pub struct FakeRomFlow {}

impl FakeRomFlow {
    /// Execute ROM Flows based on reset reason
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    #[inline(never)]
    pub fn run(env: &mut RomEnv) -> CaliptraResult<()> {
        let reset_reason = env.soc_ifc.reset_reason();
        match reset_reason {
            // Cold Reset Flow
            ResetReason::ColdReset => {
                cprintln!("[fake-rom-cold-reset] ++");
                report_boot_status(ColdResetStarted.into());

                // Zeroize the key vault in the fake ROM flow
                unsafe { KeyVault::zeroize() };

                env.soc_ifc.flow_status_set_ready_for_mb_processing();

                fht::initialize_fht(env);

                // SKIP Execute IDEVID layer
                // LDEVID cert
                copy_canned_ldev_cert(env)?;
                // LDEVID cdi
                initialize_fake_ldevid_cdi(env)?;

                // Unlock the SHA Acc by creating a SHA Acc operation and dropping it.
                // In real ROM, this is done as part of executing the SHA-ACC KAT.
                let sha_op = env
                    .sha2_512_384_acc
                    .try_start_operation(ShaAccLockState::AssumedLocked)
                    .unwrap();
                drop(sha_op);

                // Download and validate firmware.
                _ = FirmwareProcessor::process(env)?;

                // FMC Alias Cert
                copy_canned_fmc_alias_cert(env)?;

                cprintln!("[fake-rom-cold-reset] --");
                report_boot_status(ColdResetComplete.into());

                Ok(())
            }

            // Warm Reset Flow
            ResetReason::WarmReset => warm_reset::WarmResetFlow::run(env),

            // Update Reset Flow
            ResetReason::UpdateReset => update_reset::UpdateResetFlow::run(env),

            // Unknown/Spurious Reset Flow
            ResetReason::Unknown => Err(CaliptraError::ROM_UNKNOWN_RESET_FLOW),
        }
    }
}

// Used to derive the firmware's key ladder.
fn initialize_fake_ldevid_cdi(env: &mut RomEnv) -> CaliptraResult<()> {
    let fake_key = Array4x16::from([0x1234_5678u32; 16]);
    env.hmac.hmac(
        HmacKey::Array4x16(&fake_key),
        HmacData::Slice(b""),
        &mut env.trng,
        KeyWriteArgs::new(KEY_ID_ROM_FMC_CDI, KeyUsage::default().set_hmac_key_en()).into(),
        HmacMode::Hmac512,
    )
}

pub fn copy_canned_ldev_cert(env: &mut RomEnv) -> CaliptraResult<()> {
    let data_vault = &mut env.persistent_data.get_mut().data_vault;

    // Store signature
    data_vault.set_ldev_dice_ecc_signature(&FAKE_LDEV_ECC_SIG);
    data_vault.set_ldev_dice_mldsa_signature(&LEArray4x1157::from(&FAKE_LDEV_MLDSA_SIG));

    // Store pub key
    data_vault.set_ldev_dice_ecc_pub_key(&FAKE_LDEV_ECC_PUB_KEY);
    data_vault.set_ldev_dice_mldsa_pub_key(&LEArray4x648::from(&FAKE_LDEV_MLDSA_PUB_KEY));

    // Copy TBS to DCCM
    let tbs = &FAKE_LDEV_ECC_TBS;
    env.persistent_data.get_mut().fht.ecc_ldevid_tbs_size = u16::try_from(tbs.len()).unwrap();
    let Some(dst) = env
        .persistent_data
        .get_mut()
        .ecc_ldevid_tbs
        .get_mut(..tbs.len())
    else {
        return Err(CaliptraError::ROM_GLOBAL_UNSUPPORTED_LDEVID_TBS_SIZE);
    };
    dst.copy_from_slice(tbs);

    let tbs = &FAKE_LDEV_MLDSA_TBS;
    env.persistent_data.get_mut().fht.mldsa_ldevid_tbs_size = u16::try_from(tbs.len()).unwrap();
    let Some(dst) = env
        .persistent_data
        .get_mut()
        .mldsa_ldevid_tbs
        .get_mut(..tbs.len())
    else {
        return Err(CaliptraError::ROM_GLOBAL_UNSUPPORTED_LDEVID_TBS_SIZE);
    };
    dst.copy_from_slice(tbs);

    Ok(())
}

pub fn copy_canned_fmc_alias_cert(env: &mut RomEnv) -> CaliptraResult<()> {
    let data_vault = &mut env.persistent_data.get_mut().data_vault;

    // Store signature
    data_vault.set_fmc_dice_ecc_signature(&FAKE_FMC_ALIAS_ECC_SIG);
    data_vault.set_fmc_dice_mldsa_signature(&LEArray4x1157::from(&FAKE_FMC_ALIAS_MLDSA_SIG));

    // Store pub key
    data_vault.set_fmc_ecc_pub_key(&FAKE_FMC_ALIAS_ECC_PUB_KEY);
    data_vault.set_fmc_mldsa_pub_key(&LEArray4x648::from(&FAKE_FMC_ALIAS_MLDSA_PUB_KEY));

    // Copy TBS to DCCM
    let tbs = &FAKE_FMC_ALIAS_ECC_TBS;
    env.persistent_data.get_mut().fht.ecc_fmcalias_tbs_size = u16::try_from(tbs.len()).unwrap();
    let Some(dst) = env
        .persistent_data
        .get_mut()
        .ecc_fmcalias_tbs
        .get_mut(..tbs.len())
    else {
        return Err(CaliptraError::ROM_GLOBAL_UNSUPPORTED_FMCALIAS_TBS_SIZE);
    };
    dst.copy_from_slice(tbs);

    let tbs = &FAKE_FMC_ALIAS_MLDSA_TBS;
    env.persistent_data.get_mut().fht.mldsa_fmcalias_tbs_size = u16::try_from(tbs.len()).unwrap();
    let Some(dst) = env
        .persistent_data
        .get_mut()
        .mldsa_fmcalias_tbs
        .get_mut(..tbs.len())
    else {
        return Err(CaliptraError::ROM_GLOBAL_UNSUPPORTED_FMCALIAS_TBS_SIZE);
    };
    dst.copy_from_slice(tbs);
    Ok(())
}

// ROM Verification Environment
pub(crate) struct FakeRomImageVerificationEnv<'a, 'b> {
    pub(crate) sha256: &'a mut Sha256,
    pub(crate) sha2_512_384: &'a mut Sha2_512_384,
    pub(crate) sha2_512_384_acc: &'a mut Sha2_512_384Acc,
    pub(crate) soc_ifc: &'a mut SocIfc,
    pub(crate) data_vault: &'a DataVault,
    pub(crate) ecc384: &'a mut Ecc384,
    pub(crate) mldsa87: &'a mut Mldsa87,
    pub image: &'b [u8],
    pub(crate) dma: &'a Dma,
}

impl ImageVerificationEnv for &mut FakeRomImageVerificationEnv<'_, '_> {
    /// Calculate 384 digest using SHA2 Engine
    fn sha384_digest(&mut self, offset: u32, len: u32) -> CaliptraResult<ImageDigest384> {
        let err = CaliptraError::IMAGE_VERIFIER_ERR_DIGEST_OUT_OF_BOUNDS;
        let data = self
            .image
            .get(offset as usize..)
            .ok_or(err)?
            .get(..len as usize)
            .ok_or(err)?;
        Ok(self.sha2_512_384.sha384_digest(data)?.0)
    }

    /// Calculate 512 digest using SHA2 Engine
    fn sha512_digest(&mut self, offset: u32, len: u32) -> CaliptraResult<ImageDigest512> {
        let err = CaliptraError::IMAGE_VERIFIER_ERR_DIGEST_OUT_OF_BOUNDS;
        let data = self
            .image
            .get(offset as usize..)
            .ok_or(err)?
            .get(..len as usize)
            .ok_or(err)?;
        Ok(self.sha2_512_384.sha512_digest(data)?.0)
    }

    fn sha384_acc_digest(
        &mut self,
        offset: u32,
        len: u32,
        digest_failure: CaliptraError,
    ) -> CaliptraResult<ImageDigest384> {
        let mut digest = Array4x12::default();

        if let Some(mut sha_acc_op) = self
            .sha2_512_384_acc
            .try_start_operation(ShaAccLockState::NotAcquired)?
        {
            sha_acc_op
                .digest_384(len, offset, false, &mut digest)
                .map_err(|_| digest_failure)?;
        } else {
            Err(CaliptraError::KAT_SHA2_512_384_ACC_DIGEST_START_OP_FAILURE)?;
        };

        Ok(digest.0)
    }

    fn sha512_acc_digest(
        &mut self,
        offset: u32,
        len: u32,
        digest_failure: CaliptraError,
    ) -> CaliptraResult<ImageDigest512> {
        let mut digest = Array4x16::default();

        if let Some(mut sha_acc_op) = self
            .sha2_512_384_acc
            .try_start_operation(ShaAccLockState::NotAcquired)?
        {
            sha_acc_op
                .digest_512(len, offset, false, &mut digest)
                .map_err(|_| digest_failure)?;
        } else {
            Err(CaliptraError::KAT_SHA2_512_384_ACC_DIGEST_START_OP_FAILURE)?;
        };

        Ok(digest.0)
    }

    /// ECC-384 Verification routine
    fn ecc384_verify(
        &mut self,
        digest: &ImageDigest384,
        pub_key: &ImageEccPubKey,
        sig: &ImageEccSignature,
    ) -> CaliptraResult<Array4xN<12, 48>> {
        if self.soc_ifc.verify_in_fake_mode() {
            let pub_key = Ecc384PubKey {
                x: pub_key.x.into(),
                y: pub_key.y.into(),
            };

            let digest: Array4x12 = digest.into();

            let sig = Ecc384Signature {
                r: sig.r.into(),
                s: sig.s.into(),
            };

            self.ecc384.verify_r(&pub_key, &digest, &sig)
        } else {
            // Mock verify, just always return success
            Ok(Array4x12::from(sig.r))
        }
    }

    fn lms_verify(
        &mut self,
        digest: &ImageDigest384,
        pub_key: &ImageLmsPublicKey,
        sig: &ImageLmsSignature,
    ) -> CaliptraResult<HashValue<SHA192_DIGEST_WORD_SIZE>> {
        if self.soc_ifc.verify_in_fake_mode() {
            let mut message = [0u8; SHA384_DIGEST_BYTE_SIZE];
            for i in 0..digest.len() {
                message[i * 4..][..4].copy_from_slice(&digest[i].to_be_bytes());
            }
            Lms::default().verify_lms_signature_cfi(self.sha256, &message, pub_key, sig)
        } else {
            // Mock verify, just always return success
            Ok(HashValue::from(pub_key.digest))
        }
    }

    fn mldsa87_verify(
        &mut self,
        msg: &[u8],
        pub_key: &ImageMldsaPubKey,
        sig: &ImageMldsaSignature,
    ) -> CaliptraResult<Mldsa87Result> {
        if self.soc_ifc.verify_in_fake_mode() {
            let pub_key = Mldsa87PubKey::from(pub_key.0);
            let sig = Mldsa87Signature::from(sig.0);

            self.mldsa87.verify_var(&pub_key, &msg, &sig)
        } else {
            // Mock verify, just always return success
            Ok(Mldsa87Result::Success)
        }
    }

    /// Retrieve Vendor Public Key Digest
    fn vendor_pub_key_info_digest_fuses(&self) -> ImageDigest384 {
        self.soc_ifc.fuse_bank().vendor_pub_key_info_hash().into()
    }

    /// Retrieve Vendor ECC Public Key Revocation Bitmask
    fn vendor_ecc_pub_key_revocation(&self) -> VendorEccPubKeyRevocation {
        self.soc_ifc.fuse_bank().vendor_ecc_pub_key_revocation()
    }

    /// Retrieve Vendor LMS Public Key Revocation Bitmask
    fn vendor_lms_pub_key_revocation(&self) -> u32 {
        self.soc_ifc.fuse_bank().vendor_lms_pub_key_revocation()
    }

    /// Retrieve Vendor MLDSA Public Key Revocation Bitmask
    fn vendor_mldsa_pub_key_revocation(&self) -> u32 {
        self.soc_ifc.fuse_bank().vendor_mldsa_pub_key_revocation()
    }

    /// Retrieve Owner Public Key Digest from fuses
    fn owner_pub_key_digest_fuses(&self) -> ImageDigest384 {
        self.soc_ifc.fuse_bank().owner_pub_key_hash().into()
    }

    /// Retrieve Anti-Rollback disable fuse value
    fn anti_rollback_disable(&self) -> bool {
        self.soc_ifc.fuse_bank().anti_rollback_disable()
    }

    /// Retrieve Device Lifecycle state
    fn dev_lifecycle(&self) -> Lifecycle {
        self.soc_ifc.lifecycle()
    }

    /// Get the vendor ECC key index saved in data vault on cold boot
    fn vendor_ecc_pub_key_idx_dv(&self) -> u32 {
        self.data_vault.vendor_ecc_pk_index()
    }

    /// Get the vendor LMS key index saved in data vault on cold boot
    fn vendor_pqc_pub_key_idx_dv(&self) -> u32 {
        self.data_vault.vendor_pqc_pk_index()
    }

    /// Get the owner public key digest saved in the dv on cold boot
    fn owner_pub_key_digest_dv(&self) -> ImageDigest384 {
        self.data_vault.owner_pk_hash().into()
    }

    // Get the fmc digest from the data vault on cold boot
    fn get_fmc_digest_dv(&self) -> ImageDigest384 {
        self.data_vault.fmc_tci().into()
    }

    // Get Fuse FW Manifest SVN
    fn fw_fuse_svn(&self) -> u32 {
        self.soc_ifc.fuse_bank().fw_fuse_svn()
    }

    fn iccm_range(&self) -> Range<u32> {
        caliptra_common::memory_layout::ICCM_RANGE
    }

    fn set_fw_extended_error(&mut self, err: u32) {
        self.soc_ifc.set_fw_extended_error(err);
    }

    fn pqc_key_type_fuse(&self) -> CaliptraResult<FwVerificationPqcKeyType> {
        let pqc_key_type =
            FwVerificationPqcKeyType::from_u8(self.soc_ifc.fuse_bank().pqc_key_type() as u8)
                .ok_or(CaliptraError::IMAGE_VERIFIER_ERR_INVALID_PQC_KEY_TYPE_IN_FUSE)?;
        Ok(pqc_key_type)
    }
}
