/*++

Licensed under the Apache-2.0 license.

File Name:

    rt_alias.rs

Abstract:

    Alias RT DICE Layer & PCR extension

--*/
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_cfi_lib::cfi_assert_eq;
use caliptra_cfi_lib::{cfi_assert, cfi_launder};

use crate::flow::crypto::Crypto;
use crate::flow::dice::{DiceInput, DiceOutput};
use crate::flow::pcr::extend_pcr_common;
use crate::flow::tci::Tci;
use crate::flow::x509::X509;
use crate::fmc_env::FmcEnv;
use crate::FmcBootStatus;
use crate::HandOff;
use caliptra_common::cprintln;
use caliptra_common::crypto::Ecc384KeyPair;
use caliptra_common::keyids::{KEY_ID_RT_CDI, KEY_ID_RT_PRIV_KEY, KEY_ID_TMP};
use caliptra_common::HexBytes;
use caliptra_drivers::{
    okref, report_boot_status, CaliptraError, CaliptraResult, Ecc384Result, KeyId, PersistentData,
    ResetReason,
};
use caliptra_x509::{NotAfter, NotBefore, RtAliasCertTbs, RtAliasCertTbsParams};

const SHA384_HASH_SIZE: usize = 48;

#[derive(Default)]
pub struct RtAliasLayer {}

impl RtAliasLayer {
    /// Perform derivations for the DICE layer
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive(env: &mut FmcEnv, input: &DiceInput) -> CaliptraResult<DiceOutput> {
        if Self::kv_slot_collides(input.cdi) {
            return Err(CaliptraError::FMC_CDI_KV_COLLISION);
        }

        if Self::kv_slot_collides(input.auth_key_pair.priv_key) {
            return Err(CaliptraError::FMC_ALIAS_KV_COLLISION);
        }

        cprintln!("[alias rt] Derive CDI");
        cprintln!("[alias rt] Store in in slot 0x{:x}", KEY_ID_RT_CDI as u8);

        // Derive CDI
        Self::derive_cdi(env, input.cdi, KEY_ID_RT_CDI)?;
        report_boot_status(FmcBootStatus::RtAliasDeriveCdiComplete as u32);
        cprintln!("[alias rt] Derive Key Pair");
        cprintln!(
            "[alias rt] Store priv key in slot 0x{:x}",
            KEY_ID_RT_PRIV_KEY as u8
        );

        // Derive DICE Key Pair from CDI
        let key_pair = Self::derive_key_pair(env, KEY_ID_RT_CDI, KEY_ID_RT_PRIV_KEY)?;
        cprintln!("[alias rt] Derive Key Pair - Done");
        report_boot_status(FmcBootStatus::RtAliasKeyPairDerivationComplete as u32);

        // Generate the Subject Serial Number and Subject Key Identifier.
        //
        // This information will be used by next DICE Layer while generating
        // certificates
        let subj_sn = X509::subj_sn(env, &key_pair.pub_key)?;
        report_boot_status(FmcBootStatus::RtAliasSubjIdSnGenerationComplete.into());

        let subj_key_id = X509::subj_key_id(env, &key_pair.pub_key)?;
        report_boot_status(FmcBootStatus::RtAliasSubjKeyIdGenerationComplete.into());

        // Generate the output for next layer
        let output = DiceOutput {
            cdi: KEY_ID_RT_CDI,
            subj_key_pair: key_pair,
            subj_sn,
            subj_key_id,
        };

        let manifest = &env.persistent_data.get().manifest1;

        let (nb, nf) = Self::get_cert_validity_info(manifest);

        // Generate Rt Alias Certificate
        Self::generate_cert_sig(env, input, &output, &nb.value, &nf.value)?;
        Ok(output)
    }

    fn kv_slot_collides(slot: KeyId) -> bool {
        slot == KEY_ID_RT_CDI || slot == KEY_ID_RT_PRIV_KEY || slot == KEY_ID_TMP
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub fn run(env: &mut FmcEnv) -> CaliptraResult<()> {
        cprintln!("[alias rt] Extend RT PCRs");
        Self::extend_pcrs(env)?;
        cprintln!("[alias rt] Extend RT PCRs Done");

        cprintln!("[alias rt] Lock RT PCRs");
        env.pcr_bank
            .set_pcr_lock(caliptra_common::RT_FW_CURRENT_PCR);
        env.pcr_bank
            .set_pcr_lock(caliptra_common::RT_FW_JOURNEY_PCR);
        cprintln!("[alias rt] Lock RT PCRs Done");

        cprintln!("[alias rt] Populate DV");
        Self::populate_dv(env)?;
        cprintln!("[alias rt] Populate DV Done");
        report_boot_status(crate::FmcBootStatus::RtMeasurementComplete as u32);

        // Retrieve Dice Input Layer from Hand Off and Derive Key
        match Self::dice_input_from_hand_off(env) {
            Ok(input) => {
                let out = Self::derive(env, &input)?;
                report_boot_status(crate::FmcBootStatus::RtAliasDerivationComplete as u32);
                HandOff::update(env, out)
            }
            _ => Err(CaliptraError::FMC_RT_ALIAS_DERIVE_FAILURE),
        }
    }

    /// Retrieve DICE Input from HandsOff
    ///
    /// # Arguments
    ///
    /// * `hand_off` - HandOff
    ///
    /// # Returns
    ///
    /// * `DiceInput` - DICE Layer Input
    fn dice_input_from_hand_off(env: &mut FmcEnv) -> CaliptraResult<DiceInput> {
        let auth_pub = HandOff::fmc_pub_key(env);
        let auth_serial_number = X509::subj_sn(env, &auth_pub)?;
        let auth_key_id = X509::subj_key_id(env, &auth_pub)?;
        // Create initial output
        let input = DiceInput {
            cdi: HandOff::fmc_cdi(env),
            auth_key_pair: Ecc384KeyPair {
                priv_key: HandOff::fmc_priv_key(env),
                pub_key: auth_pub,
            },
            auth_sn: auth_serial_number,
            auth_key_id,
        };

        Ok(input)
    }

    /// Extend current and journey PCRs
    ///
    /// # Arguments
    ///
    /// * `env` - FMC Environment
    /// * `hand_off` - HandOff
    pub fn extend_pcrs(env: &mut FmcEnv) -> CaliptraResult<()> {
        let reset_reason = env.soc_ifc.reset_reason();
        match reset_reason {
            ResetReason::ColdReset => {
                cfi_assert_eq(reset_reason, ResetReason::ColdReset);
                extend_pcr_common(env)
            }
            ResetReason::UpdateReset => {
                cfi_assert_eq(reset_reason, ResetReason::UpdateReset);
                extend_pcr_common(env)
            }
            ResetReason::WarmReset => {
                cfi_assert_eq(reset_reason, ResetReason::WarmReset);
                cprintln!("[alias rt : skip pcr extension");
                Ok(())
            }
            ResetReason::Unknown => {
                cfi_assert_eq(reset_reason, ResetReason::Unknown);
                Err(CaliptraError::FMC_UNKNOWN_RESET)
            }
        }
    }

    /// Populate Data Vault
    ///
    /// # Arguments
    ///
    /// * `env` - FMC Environment
    /// * `hand_off` - HandOff
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn populate_dv(env: &mut FmcEnv) -> CaliptraResult<()> {
        let rt_svn = HandOff::rt_svn(env);
        let reset_reason = env.soc_ifc.reset_reason();

        let rt_min_svn = if reset_reason == ResetReason::ColdReset {
            cfi_assert_eq(reset_reason, ResetReason::ColdReset);
            rt_svn
        } else {
            core::cmp::min(rt_svn, HandOff::rt_min_svn(env))
        };

        HandOff::set_and_lock_rt_min_svn(env, rt_min_svn)
    }

    fn get_cert_validity_info(
        manifest: &caliptra_image_types::ImageManifest,
    ) -> (NotBefore, NotAfter) {
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

    /// Permute Composite Device Identity (CDI) using Rt TCI and Image Manifest Digest
    /// The RT Alias CDI will overwrite the FMC Alias CDI in the KeyVault Slot
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `fmc_cdi` - Key Slot that holds the current CDI
    /// * `rt_cdi` - Key Slot to store the generated CDI
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_cdi(env: &mut FmcEnv, fmc_cdi: KeyId, rt_cdi: KeyId) -> CaliptraResult<()> {
        // Compose FMC TCI (1. RT TCI, 2. Image Manifest Digest)
        let mut tci = [0u8; 2 * SHA384_HASH_SIZE];
        let rt_tci: [u8; 48] = HandOff::rt_tci(env).into();
        tci[0..SHA384_HASH_SIZE].copy_from_slice(&rt_tci);

        let image_manifest_digest: Result<_, CaliptraError> = Tci::image_manifest_digest(env);
        let image_manifest_digest: [u8; 48] = okref(&image_manifest_digest)?.into();
        tci[SHA384_HASH_SIZE..2 * SHA384_HASH_SIZE].copy_from_slice(&image_manifest_digest);

        // Permute CDI from FMC TCI
        Crypto::hmac384_kdf(env, fmc_cdi, b"rt_alias_cdi", Some(&tci), rt_cdi)?;
        report_boot_status(FmcBootStatus::RtAliasDeriveCdiComplete as u32);
        Ok(())
    }

    /// Derive Dice Layer Key Pair
    ///
    /// # Arguments
    ///
    /// * `env`      - Fmc Environment
    /// * `cdi`      - Composite Device Identity
    /// * `priv_key` - Key slot to store the private key into
    ///
    /// # Returns
    ///
    /// * `Ecc384KeyPair` - Derive DICE Layer Key Pair
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_key_pair(
        env: &mut FmcEnv,
        cdi: KeyId,
        priv_key: KeyId,
    ) -> CaliptraResult<Ecc384KeyPair> {
        let result = Crypto::ecc384_key_gen(env, cdi, b"rt_alias_keygen", priv_key);
        if cfi_launder(result.is_ok()) {
            cfi_assert!(result.is_ok());
        } else {
            cfi_assert!(result.is_err());
        }

        result
    }

    /// Generate Local Device ID Certificate Signature
    ///
    /// # Arguments
    ///
    /// * `env`    - FMC Environment
    /// * `input`  - DICE Input
    /// * `output` - DICE Output
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn generate_cert_sig(
        env: &mut FmcEnv,
        input: &DiceInput,
        output: &DiceOutput,
        not_before: &[u8; RtAliasCertTbsParams::NOT_BEFORE_LEN],
        not_after: &[u8; RtAliasCertTbsParams::NOT_AFTER_LEN],
    ) -> CaliptraResult<()> {
        let auth_priv_key = input.auth_key_pair.priv_key;
        let auth_pub_key = &input.auth_key_pair.pub_key;
        let pub_key = &output.subj_key_pair.pub_key;

        let serial_number = &X509::cert_sn(env, pub_key)?;

        let rt_tci: [u8; 48] = HandOff::rt_tci(env).into();
        let rt_svn = HandOff::rt_svn(env) as u8;

        // Certificate `To Be Signed` Parameters
        let params = RtAliasCertTbsParams {
            // Do we need the UEID here?
            ueid: &X509::ueid(env)?,
            subject_sn: &output.subj_sn,
            subject_key_id: &output.subj_key_id,
            issuer_sn: &input.auth_sn,
            authority_key_id: &input.auth_key_id,
            serial_number,
            public_key: &pub_key.to_der(),
            not_before,
            not_after,
            tcb_info_rt_svn: &rt_svn.to_be_bytes(),
            tcb_info_rt_tci: &rt_tci,
            // Are there any fields missing?
        };

        // Generate the `To Be Signed` portion of the CSR
        let tbs = RtAliasCertTbs::new(&params);

        // Sign the `To Be Signed` portion
        cprintln!(
            "[alias rt] Signing Cert with AUTHO
            RITY.KEYID = {}",
            auth_priv_key as u8
        );

        // Sign the AliasRt To Be Signed DER Blob with AliasFMC Private Key in Key Vault Slot 7
        // AliasRtTbsDigest = sha384_digest(AliasRtTbs) AliaRtTbsCertSig = ecc384_sign(KvSlot5, AliasFmcTbsDigest)

        let sig = Crypto::ecdsa384_sign(env, auth_priv_key, auth_pub_key, tbs.tbs());
        let sig = okref(&sig)?;
        // Clear the authority private key
        cprintln!(
            "[alias rt] Erasing AUTHORITY.KEYID = {}",
            auth_priv_key as u8
        );
        // FMC ensures that CDIFMC and PrivateKeyFMC are locked to block further usage until the next boot.
        env.key_vault.set_key_use_lock(auth_priv_key);
        env.key_vault.set_key_use_lock(input.cdi);

        let _pub_x: [u8; 48] = (&pub_key.x).into();
        let _pub_y: [u8; 48] = (&pub_key.y).into();
        cprintln!("[alias rt] PUB.X = {}", HexBytes(&_pub_x));
        cprintln!("[alias rt] PUB.Y = {}", HexBytes(&_pub_y));

        let _sig_r: [u8; 48] = (&sig.r).into();
        let _sig_s: [u8; 48] = (&sig.s).into();
        cprintln!("[alias rt] SIG.R = {}", HexBytes(&_sig_r));
        cprintln!("[alias rt] SIG.S = {}", HexBytes(&_sig_s));

        // Verify the signature of the `To Be Signed` portion
        if Crypto::ecdsa384_verify(env, auth_pub_key, tbs.tbs(), sig)? != Ecc384Result::Success {
            return Err(CaliptraError::FMC_RT_ALIAS_CERT_VERIFY);
        }

        HandOff::set_rt_dice_signature(env, sig);

        //  Copy TBS to DCCM and set size in FHT.
        Self::copy_tbs(tbs.tbs(), env.persistent_data.get_mut())?;
        HandOff::set_rtalias_tbs_size(env, tbs.tbs().len());

        report_boot_status(FmcBootStatus::RtAliasCertSigGenerationComplete as u32);

        Ok(())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn copy_tbs(tbs: &[u8], persistent_data: &mut PersistentData) -> CaliptraResult<()> {
        let Some(dest) = persistent_data.rtalias_tbs.get_mut(..tbs.len()) else {
            return Err(CaliptraError::FMC_RT_ALIAS_TBS_SIZE_EXCEEDED);
        };
        dest.copy_from_slice(tbs);
        Ok(())
    }
}
