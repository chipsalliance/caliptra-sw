/*++

Licensed under the Apache-2.0 license.

File Name:

    init_dev_id.rs

Abstract:

    File contains the implementation of DICE Initial Device Identity (IDEVID)
    layer.

--*/

use super::dice::*;
use crate::cprintln;
use crate::crypto::Ecdsa384SignatureAdapter;
use crate::flow::cold_reset;
use crate::print::HexBytes;
use crate::rom_env::RomEnv;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_cfi_lib::{cfi_assert, cfi_assert_bool, cfi_launder};
use caliptra_common::{
    crypto::{Crypto, Ecc384KeyPair, MlDsaKeyPair, PubKey},
    keyids::{
        ocp_lock::{KEY_ID_HEK, KEY_ID_MDK},
        KEY_ID_FE, KEY_ID_IDEVID_ECDSA_PRIV_KEY, KEY_ID_IDEVID_MLDSA_KEYPAIR_SEED,
        KEY_ID_ROM_FMC_CDI, KEY_ID_UDS,
    },
    x509,
    RomBootStatus::*,
};
use caliptra_drivers::*;
use caliptra_x509::*;
use core::mem::offset_of;
use zerocopy::IntoBytes;
use zeroize::Zeroize;

/// Initialization Vector used by Deobfuscation Engine during UDS / field entropy decryption.
const DOE_IV: Array4x4 = Array4xN::<4, 16>([0xfb10365b, 0xa1179741, 0xfba193a1, 0x0f406d7e]);

/// Dice Initial Device Identity (IDEVID) Layer
pub enum InitDevIdLayer {}

impl InitDevIdLayer {
    /// Perform derivations for the DICE layer
    ///
    /// # Arguments
    ///
    /// * `env`   - ROM Environment
    ///
    /// # Returns
    ///
    /// * `DiceOutput` - DICE layer output
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn derive(env: &mut RomEnv) -> CaliptraResult<DiceOutput> {
        cprintln!("[idev] ++");
        cprintln!("[idev] CDI.KEYID = {}", KEY_ID_ROM_FMC_CDI as u8);
        cprintln!(
            "[idev] ECC SUBJECT.KEYID = {}, MLDSA SUBJECT.KEYID = {}",
            KEY_ID_IDEVID_ECDSA_PRIV_KEY as u8,
            KEY_ID_IDEVID_MLDSA_KEYPAIR_SEED as u8
        );
        cprintln!("[idev] UDS.KEYID = {}", KEY_ID_UDS as u8);

        // If CSR is not requested, indicate to the SOC that it can start
        // uploading the firmware image to the mailbox.
        if !env.soc_ifc.mfg_flag_gen_idev_id_csr() {
            env.soc_ifc.flow_status_set_ready_for_mb_processing();
        }

        // Decrypt the UDS
        Self::decrypt_uds(env, KEY_ID_UDS)?;

        // Decrypt the Field Entropy
        Self::decrypt_field_entropy(env, KEY_ID_FE)?;

        // Clear Deobfuscation Engine Secrets
        Self::clear_doe_secrets(env)?;

        // Derive the DICE CDI from decrypted UDS
        Self::derive_cdi(env, KEY_ID_UDS, KEY_ID_ROM_FMC_CDI)?;

        // Run the OCP LOCK Flow while the DICE CDI is available.
        Self::ocp_lock_cold_reset_flow(env)?;

        // Derive DICE ECC and MLDSA Key Pairs from CDI
        let (ecc_key_pair, mldsa_key_pair) = Self::derive_key_pair(
            env,
            KEY_ID_ROM_FMC_CDI,
            KEY_ID_IDEVID_ECDSA_PRIV_KEY,
            KEY_ID_IDEVID_MLDSA_KEYPAIR_SEED,
        )?;

        // Generate the Subject Serial Number and Subject Key Identifier for ECC.
        // This information will be used by next DICE Layer while generating
        // certificates
        let ecc_subj_sn = x509::subj_sn(&mut env.sha256, &PubKey::Ecc(&ecc_key_pair.pub_key))?;
        let mldsa_subj_sn =
            x509::subj_sn(&mut env.sha256, &PubKey::Mldsa(&mldsa_key_pair.pub_key))?;
        report_boot_status(IDevIdSubjIdSnGenerationComplete.into());

        let ecc_subj_key_id =
            cold_reset::x509::idev_subj_key_id(env, &PubKey::Ecc(&ecc_key_pair.pub_key))?;
        let mldsa_subj_key_id =
            cold_reset::x509::idev_subj_key_id(env, &PubKey::Mldsa(&mldsa_key_pair.pub_key))?;
        report_boot_status(IDevIdSubjKeyIdGenerationComplete.into());

        // Generate the output for next layer
        let output = DiceOutput {
            ecc_subj_key_pair: ecc_key_pair,
            ecc_subj_sn,
            ecc_subj_key_id,
            mldsa_subj_key_id,
            mldsa_subj_key_pair: mldsa_key_pair,
            mldsa_subj_sn,
        };

        // Generate the Initial DevID Certificate Signing Request (CSR)
        Self::generate_csrs(env, &output)?;

        // Indicate (if not already done) to SOC that it can start uploading the firmware image to the mailbox.
        if !env.soc_ifc.flow_status_ready_for_mb_processing() {
            env.soc_ifc.flow_status_set_ready_for_mb_processing();
        }

        // Write IDevID public key to FHT
        env.persistent_data.get_mut().fht.idev_dice_ecdsa_pub_key =
            output.ecc_subj_key_pair.pub_key;

        // Copy the MLDSA public key to Persistent Data.
        env.persistent_data.get_mut().idevid_mldsa_pub_key = output.mldsa_subj_key_pair.pub_key;

        cprintln!("[idev] --");
        report_boot_status(IDevIdDerivationComplete.into());

        // Return the DICE Layer Output
        Ok(output)
    }

    /// Decrypt Unique Device Secret (UDS)
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `uds` - Key Vault slot to store the decrypted UDS in
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn decrypt_uds(env: &mut RomEnv, uds: KeyId) -> CaliptraResult<()> {
        // Engage the Deobfuscation Engine to decrypt the UDS
        env.doe.decrypt_uds(&DOE_IV, uds)?;
        report_boot_status(IDevIdDecryptUdsComplete.into());
        Ok(())
    }

    /// Decrypt Field Entropy (FW)
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `slot` - Key Vault slot to store the decrypted UDS in
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn decrypt_field_entropy(env: &mut RomEnv, fe: KeyId) -> CaliptraResult<()> {
        // Engage the Deobfuscation Engine to decrypt the UDS
        env.doe.decrypt_field_entropy(&DOE_IV, fe)?;
        report_boot_status(IDevIdDecryptFeComplete.into());
        Ok(())
    }

    /// Clear Deobfuscation Engine secrets
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn clear_doe_secrets(env: &mut RomEnv) -> CaliptraResult<()> {
        let result = env.doe.clear_secrets();
        if result.is_ok() {
            report_boot_status(IDevIdClearDoeSecretsComplete.into());
        }
        result
    }

    /// Derive Composite Device Identity (CDI) from Unique Device Secret (UDS)
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `uds` - Key slot holding the UDS
    /// * `cdi` - Key Slot to store the generated CDI
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_cdi(env: &mut RomEnv, uds: KeyId, cdi: KeyId) -> CaliptraResult<()> {
        Crypto::hmac_kdf(
            &mut env.hmac,
            &mut env.trng,
            uds,
            b"idevid_cdi",
            None,
            cdi,
            HmacMode::Hmac512,
            KeyUsage::default()
                .set_ecc_key_gen_seed_en()
                .set_mldsa_key_gen_seed_en()
                .set_hmac_key_en(),
        )?;

        cprintln!("[idev] Erasing UDS.KEYID = {}", uds as u8);
        env.key_vault.erase_key(uds)?;
        report_boot_status(IDevIdCdiDerivationComplete.into());
        Ok(())
    }

    /// Run the OCP LOCK Cold Reset flow
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn ocp_lock_cold_reset_flow(env: &mut RomEnv) -> CaliptraResult<()> {
        if !env.soc_ifc.ocp_lock_enabled() {
            return Ok(());
        }
        Self::derive_hek(env)?;
        Self::derive_mdk(env)?;
        Ok(())
    }

    /// Derive OCP LOCK HEK
    ///
    /// NOTE: The HEK _may_ be disabled once MCU has reported the HEK seed state.
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_hek(env: &mut RomEnv) -> CaliptraResult<()> {
        let hek_seed = env.soc_ifc.fuse_bank().ocp_hek_seed();
        // HEK will be WR locked after the mailbox command handler.
        Crypto::hmac_kdf(
            &mut env.hmac,
            &mut env.trng,
            KEY_ID_ROM_FMC_CDI,
            b"ocp_lock_hek",
            Some(hek_seed.as_bytes()),
            KEY_ID_HEK,
            HmacMode::Hmac512,
            KeyUsage::default().set_hmac_key_en(),
        )?;
        Ok(())
    }

    /// Derive OCP LOCK MDK
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_mdk(env: &mut RomEnv) -> CaliptraResult<()> {
        Crypto::hmac_kdf(
            &mut env.hmac,
            &mut env.trng,
            KEY_ID_ROM_FMC_CDI,
            b"ocp_lock_mdk",
            None,
            KEY_ID_MDK,
            HmacMode::Hmac512,
            KeyUsage::default().set_hmac_key_en(),
        )?;
        // LOCK MDK to prevent later stages from overwriting.
        env.key_vault.set_key_write_lock(KEY_ID_MDK);
        Ok(())
    }

    /// Derive Dice Layer ECC and MLDSA Key Pairs
    ///
    /// # Arguments
    ///
    /// * `env`      - ROM Environment
    /// * `cdi`      - Composite Device Identity
    /// * `ecc_priv_key` - Key slot to store the ECC private key into
    /// * `mldsa_keypair_seed` - Key slot to store the MLDSA key pair seed
    ///
    /// # Returns
    ///
    /// * `(Ecc384KeyPair, MlDsaKeyPair)` - DICE Layer ECC and MLDSA Key Pairs
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_key_pair(
        env: &mut RomEnv,
        cdi: KeyId,
        ecc_priv_key: KeyId,
        mldsa_keypair_seed: KeyId,
    ) -> CaliptraResult<(Ecc384KeyPair, MlDsaKeyPair)> {
        let result = Crypto::ecc384_key_gen(
            &mut env.ecc384,
            &mut env.hmac,
            &mut env.trng,
            &mut env.key_vault,
            cdi,
            b"idevid_ecc_key",
            ecc_priv_key,
        );
        if cfi_launder(result.is_ok()) {
            cfi_assert!(result.is_ok());
        } else {
            cfi_assert!(result.is_err());
        }
        let ecc_keypair = result?;

        // Derive the MLDSA Key Pair.
        let result = Crypto::mldsa87_key_gen(
            &mut env.mldsa87,
            &mut env.hmac,
            &mut env.trng,
            cdi,
            b"idevid_mldsa_key",
            mldsa_keypair_seed,
        );
        if cfi_launder(result.is_ok()) {
            cfi_assert!(result.is_ok());
        } else {
            cfi_assert!(result.is_err());
        }
        let mldsa_keypair = result?;

        report_boot_status(IDevIdKeyPairDerivationComplete.into());
        Ok((ecc_keypair, mldsa_keypair))
    }

    /// Generate Local Device ID CSRs
    ///
    /// # Arguments
    ///
    /// * `env`    - ROM Environment
    /// * `output` - DICE Output
    // Inlined to reduce ROM size
    #[inline(always)]
    fn generate_csrs(env: &mut RomEnv, output: &DiceOutput) -> CaliptraResult<()> {
        //
        // Generate the CSR if requested via Manufacturing Service Register
        //
        // A flag is asserted via JTAG interface to enable the generation of CSR
        if !env.soc_ifc.mfg_flag_gen_idev_id_csr() {
            Self::reset_persistent_storage_csrs(env)?;
            return Ok(());
        }

        cprintln!("[idev] CSR Envelope upload begun");

        // Generate the CSR
        Self::make_csr_envelop(env, output)
    }

    /// Create Initial Device ID CSR Envelope
    ///
    /// # Arguments
    ///
    /// * `env`    - ROM Environment
    /// * `output` - DICE Output
    fn make_csr_envelop(env: &mut RomEnv, output: &DiceOutput) -> CaliptraResult<()> {
        // Generate ECC CSR.
        Self::make_ecc_csr(env, output)?;

        // Generate MLDSA CSR.
        Self::make_mldsa_csr(env, output)?;

        // Create a HMAC tag for the CSR Envelop.
        let csr_envelop = &mut env.persistent_data.get_mut().idevid_csr_envelop;

        // Data to be HMACed is everything before the CSR MAC.
        let offset = offset_of!(InitDevIdCsrEnvelope, csr_mac);
        let envlope_slice = csr_envelop
            .as_bytes()
            .get(..offset)
            .ok_or(CaliptraError::ROM_IDEVID_INVALID_CSR)?;

        // Generate the CSR MAC.
        let mut tag = Array4x16::default();
        env.hmac.hmac(
            HmacKey::CsrMode(),
            HmacData::Slice(envlope_slice),
            &mut env.trng,
            (&mut tag).into(),
            HmacMode::Hmac512,
        )?;

        // Copy the tag to the CSR envelop.
        csr_envelop.csr_mac = tag.into();

        // Execute Send CSR Flow
        Self::send_csr_envelop(env)?;

        report_boot_status(IDevIdMakeCsrEnvelopeComplete.into());
        Ok(())
    }

    fn make_ecc_csr(env: &mut RomEnv, output: &DiceOutput) -> CaliptraResult<()> {
        let key_pair = &output.ecc_subj_key_pair;

        // CSR `To Be Signed` Parameters
        let params = InitDevIdCsrTbsEcc384Params {
            // Unique Endpoint Identifier
            ueid: &x509::ueid(&env.soc_ifc)?,

            // Subject Name
            subject_sn: &output.ecc_subj_sn,

            // Public Key
            public_key: &key_pair.pub_key.to_der(),
        };

        // Generate the `To Be Signed` portion of the CSR
        let tbs = InitDevIdCsrTbsEcc384::new(&params);

        cprintln!(
            "[idev] ECC Sign CSR w/ SUBJECT.KEYID = {}",
            key_pair.priv_key as u8
        );

        // Sign the `To Be Signed` portion
        let mut sig = Crypto::ecdsa384_sign_and_verify(
            &mut env.sha2_512_384,
            &mut env.ecc384,
            &mut env.trng,
            key_pair.priv_key,
            &key_pair.pub_key,
            tbs.tbs(),
        );
        let sig = okmutref(&mut sig)?;

        let _pub_x: [u8; 48] = key_pair.pub_key.x.into();
        let _pub_y: [u8; 48] = key_pair.pub_key.y.into();
        cprintln!("[idev] ECC PUB.X = {}", HexBytes(&_pub_x));
        cprintln!("[idev] ECC PUB.Y = {}", HexBytes(&_pub_y));

        let _sig_r: [u8; 48] = (&sig.r).into();
        let _sig_s: [u8; 48] = (&sig.s).into();
        cprintln!("[idev] ECC SIG.R = {}", HexBytes(&_sig_r));
        cprintln!("[idev] ECC SIG.S = {}", HexBytes(&_sig_s));

        // Build the CSR with `To Be Signed` & `Signature`
        let csr_envelop = &mut env.persistent_data.get_mut().idevid_csr_envelop;
        let ecdsa384_sig = sig.to_ecdsa();
        let result = Ecdsa384CsrBuilder::new(tbs.tbs(), &ecdsa384_sig)
            .ok_or(CaliptraError::ROM_IDEVID_CSR_BUILDER_INIT_FAILURE);
        sig.zeroize();

        let csr_bldr = result?;
        let csr_len = csr_bldr
            .build(&mut csr_envelop.ecc_csr.csr)
            .ok_or(CaliptraError::ROM_IDEVID_CSR_BUILDER_BUILD_FAILURE)?;

        if csr_len > csr_envelop.ecc_csr.csr.len() {
            return Err(CaliptraError::ROM_IDEVID_CSR_OVERFLOW);
        }
        csr_envelop.ecc_csr.csr_len = csr_len as u32;

        cprintln!(
            "[idev] ECC CSR = {}",
            HexBytes(&csr_envelop.ecc_csr.csr[..csr_len])
        );

        Ok(())
    }

    fn make_mldsa_csr(env: &mut RomEnv, output: &DiceOutput) -> CaliptraResult<()> {
        let key_pair = &output.mldsa_subj_key_pair;

        let params = InitDevIdCsrTbsMlDsa87Params {
            // Unique Endpoint Identifier
            ueid: &x509::ueid(&env.soc_ifc)?,

            // Subject Name
            subject_sn: &output.mldsa_subj_sn,

            // Public Key
            public_key: &key_pair.pub_key.into(),
        };

        // Generate the `To Be Signed` portion of the CSR
        let tbs = InitDevIdCsrTbsMlDsa87::new(&params);

        cprintln!(
            "[idev] MLDSA Sign CSR w/ SUBJECT.KEYID = {}",
            key_pair.key_pair_seed as u8
        );

        // Sign the `To Be Signed` portion
        let mut sig = Crypto::mldsa87_sign_and_verify(
            &mut env.mldsa87,
            &mut env.trng,
            key_pair.key_pair_seed,
            &key_pair.pub_key,
            tbs.tbs(),
        )?;

        // Build the CSR with `To Be Signed` & `Signature`
        let mldsa87_signature = caliptra_x509::MlDsa87Signature {
            sig: sig.as_bytes()[..4627].try_into().unwrap(),
        };
        let csr_envelop = &mut env.persistent_data.get_mut().idevid_csr_envelop;
        let result = MlDsa87CsrBuilder::new(tbs.tbs(), &mldsa87_signature)
            .ok_or(CaliptraError::ROM_IDEVID_CSR_BUILDER_INIT_FAILURE);
        sig.zeroize();

        let csr_bldr = result?;
        let csr_len = csr_bldr
            .build(&mut csr_envelop.mldsa_csr.csr)
            .ok_or(CaliptraError::ROM_IDEVID_CSR_BUILDER_BUILD_FAILURE)?;

        if csr_len > csr_envelop.mldsa_csr.csr.len() {
            return Err(CaliptraError::ROM_IDEVID_CSR_OVERFLOW);
        }
        csr_envelop.mldsa_csr.csr_len = csr_len as u32;

        Ok(())
    }

    fn reset_persistent_storage_csrs(env: &mut RomEnv) -> CaliptraResult<()> {
        let csr_envelop_persistent_mem = &mut env.persistent_data.get_mut().idevid_csr_envelop;
        *csr_envelop_persistent_mem = InitDevIdCsrEnvelope::default();

        Ok(())
    }

    /// Send Initial Device ID CSR to SOC
    ///
    /// # Argument
    ///
    /// * `env` - ROM Environment
    fn send_csr_envelop(env: &mut RomEnv) -> CaliptraResult<()> {
        let csr_envelop = &env.persistent_data.get().idevid_csr_envelop;
        loop {
            // Create Mailbox send transaction to send the CSR envelop
            if let Some(mut txn) = env.mbox.try_start_send_txn() {
                // Copy the CSR to mailbox
                txn.send_request(0, csr_envelop.as_bytes())?;

                // Signal the JTAG/SOC that Initial Device ID CSR envelop is ready
                env.soc_ifc.flow_status_set_idevid_csr_ready();

                // Wait for JTAG/SOC to consume the mailbox
                while env.soc_ifc.mfg_flag_gen_idev_id_csr() {}

                // Release access to the mailbox
                txn.complete()?;

                cprintln!("[idev] CSR Envelope uploaded");
                report_boot_status(IDevIdSendCsrEnvelopeComplete.into());

                // exit the loop
                break Ok(());
            }
        }
    }
}
