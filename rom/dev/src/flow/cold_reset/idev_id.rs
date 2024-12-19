/*++

Licensed under the Apache-2.0 license.

File Name:

    init_dev_id.rs

Abstract:

    File contains the implementation of DICE Initial Device Identity (IDEVID)
    layer.

--*/

use super::dice::*;
use super::x509::*;
use crate::cprintln;
use crate::crypto::{Crypto, Ecdsa384SignatureAdapter};
use crate::print::HexBytes;
use crate::rom_env::RomEnv;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_cfi_lib::{cfi_assert, cfi_assert_bool, cfi_launder};
use caliptra_common::{
    crypto::{Ecc384KeyPair, MlDsaKeyPair, PubKey},
    keyids::{
        KEY_ID_FE, KEY_ID_IDEVID_ECDSA_PRIV_KEY, KEY_ID_IDEVID_MLDSA_KEYPAIR_SEED,
        KEY_ID_ROM_FMC_CDI, KEY_ID_UDS,
    },
    x509,
    RomBootStatus::*,
};
use caliptra_drivers::*;
use caliptra_x509::*;
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
        let ecc_subj_sn =
            x509::X509::subj_sn(&mut env.sha256, &PubKey::Ecc(&ecc_key_pair.pub_key))?;
        let mldsa_subj_sn =
            x509::X509::subj_sn(&mut env.sha256, &PubKey::Mldsa(&mldsa_key_pair.pub_key))?;
        report_boot_status(IDevIdSubjIdSnGenerationComplete.into());

        let ecc_subj_key_id = X509::idev_subj_key_id(env, &PubKey::Ecc(&ecc_key_pair.pub_key))?;
        let mldsa_subj_key_id =
            X509::idev_subj_key_id(env, &PubKey::Mldsa(&mldsa_key_pair.pub_key))?;
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
        Self::generate_csr(env, &output)?;

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
        Crypto::env_hmac_kdf(env, uds, b"idevid_cdi", None, cdi, HmacMode::Hmac512)?;

        cprintln!("[idev] Erasing UDS.KEYID = {}", uds as u8);
        env.key_vault.erase_key(uds)?;
        report_boot_status(IDevIdCdiDerivationComplete.into());
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
        let result = Crypto::ecc384_key_gen(env, cdi, b"idevid_ecc_key", ecc_priv_key);
        if cfi_launder(result.is_ok()) {
            cfi_assert!(result.is_ok());
        } else {
            cfi_assert!(result.is_err());
        }
        let ecc_keypair = result?;

        // Derive the MLDSA Key Pair.
        let result = Crypto::mldsa_key_gen(env, cdi, b"idevid_mldsa_key", mldsa_keypair_seed);
        if cfi_launder(result.is_ok()) {
            cfi_assert!(result.is_ok());
        } else {
            cfi_assert!(result.is_err());
        }
        let mldsa_keypair = result?;

        report_boot_status(IDevIdKeyPairDerivationComplete.into());
        Ok((ecc_keypair, mldsa_keypair))
    }

    /// Generate Local Device ID CSR
    ///
    /// # Arguments
    ///
    /// * `env`    - ROM Environment
    /// * `output` - DICE Output
    // Inlined to reduce ROM size
    #[inline(always)]
    fn generate_csr(env: &mut RomEnv, output: &DiceOutput) -> CaliptraResult<()> {
        //
        // Generate the CSR if requested via Manufacturing Service Register
        //
        // A flag is asserted via JTAG interface to enable the generation of CSR
        if !env.soc_ifc.mfg_flag_gen_idev_id_csr() {
            let dev_id_csr = IdevIdCsr::default();
            Self::write_csr_to_peristent_storage(env, &dev_id_csr)?;
            return Ok(());
        }

        cprintln!("[idev] CSR upload begun");

        // Generate the CSR
        Self::make_csr(env, output)
    }

    /// Create Initial Device ID CSR
    ///
    /// # Arguments
    ///
    /// * `env`    - ROM Environment
    /// * `output` - DICE Output
    fn make_csr(env: &mut RomEnv, output: &DiceOutput) -> CaliptraResult<()> {
        let key_pair = &output.ecc_subj_key_pair;

        // CSR `To Be Signed` Parameters
        let params = InitDevIdCsrTbsParams {
            // Unique Endpoint Identifier
            ueid: &x509::X509::ueid(&env.soc_ifc)?,

            // Subject Name
            subject_sn: &output.ecc_subj_sn,

            // Public Key
            public_key: &key_pair.pub_key.to_der(),
        };

        // Generate the `To Be Signed` portion of the CSR
        let tbs = InitDevIdCsrTbs::new(&params);

        cprintln!(
            "[idev] Sign CSR w/ SUBJECT.KEYID = {}",
            key_pair.priv_key as u8
        );

        // Sign the `To Be Signed` portion
        let mut sig =
            Crypto::ecdsa384_sign_and_verify(env, key_pair.priv_key, &key_pair.pub_key, tbs.tbs());
        let sig = okmutref(&mut sig)?;

        let _pub_x: [u8; 48] = key_pair.pub_key.x.into();
        let _pub_y: [u8; 48] = key_pair.pub_key.y.into();
        cprintln!("[idev] PUB.X = {}", HexBytes(&_pub_x));
        cprintln!("[idev] PUB.Y = {}", HexBytes(&_pub_y));

        let _sig_r: [u8; 48] = (&sig.r).into();
        let _sig_s: [u8; 48] = (&sig.s).into();
        cprintln!("[idev] SIG.R = {}", HexBytes(&_sig_r));
        cprintln!("[idev] SIG.S = {}", HexBytes(&_sig_s));

        // Build the CSR with `To Be Signed` & `Signature`
        let mut csr_buf = [0; MAX_CSR_SIZE];
        let ecdsa384_sig = sig.to_ecdsa();
        let result = Ecdsa384CsrBuilder::new(tbs.tbs(), &ecdsa384_sig)
            .ok_or(CaliptraError::ROM_IDEVID_CSR_BUILDER_INIT_FAILURE);
        sig.zeroize();

        let csr_bldr = result?;
        let csr_len = csr_bldr
            .build(&mut csr_buf)
            .ok_or(CaliptraError::ROM_IDEVID_CSR_BUILDER_BUILD_FAILURE)?;

        if csr_len > csr_buf.len() {
            return Err(CaliptraError::ROM_IDEVID_CSR_OVERFLOW);
        }

        // [TODO] Generate MLDSA CSR.

        cprintln!("[idev] CSR = {}", HexBytes(&csr_buf[..csr_len]));
        report_boot_status(IDevIdMakeCsrComplete.into());

        let dev_id_csr = IdevIdCsr::new(&csr_buf, csr_len)?;

        // Execute Send CSR Flow
        let mut result = Self::send_csr(env, &dev_id_csr);
        if result.is_ok() {
            result = Self::write_csr_to_peristent_storage(env, &dev_id_csr);
        }
        csr_buf.zeroize();

        result
    }

    fn write_csr_to_peristent_storage(env: &mut RomEnv, csr: &IdevIdCsr) -> CaliptraResult<()> {
        let csr_persistent_mem = &mut env.persistent_data.get_mut().idevid_csr;
        *csr_persistent_mem = csr.clone();

        Ok(())
    }

    /// Send Initial Device ID CSR to SOC
    ///
    /// # Argument
    ///
    /// * `env` - ROM Environment
    /// * `csr` - Certificate Signing Request to send to SOC
    fn send_csr(env: &mut RomEnv, csr: &IdevIdCsr) -> CaliptraResult<()> {
        loop {
            // Create Mailbox send transaction to send the CSR
            if let Some(mut txn) = env.mbox.try_start_send_txn() {
                // Copy the CSR to mailbox
                txn.send_request(0, csr.get().ok_or(CaliptraError::ROM_IDEVID_INVALID_CSR)?)?;

                // Signal the JTAG/SOC that Initial Device ID CSR is ready
                env.soc_ifc.flow_status_set_idevid_csr_ready();

                // Wait for JTAG/SOC to consume the mailbox
                while env.soc_ifc.mfg_flag_gen_idev_id_csr() {}

                // Release access to the mailbox
                txn.complete()?;

                cprintln!("[idev] CSR uploaded");
                report_boot_status(IDevIdSendCsrComplete.into());

                // exit the loop
                break Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliptra_drivers::memory_layout::IDEVID_CSR_SIZE;

    #[test]
    fn verify_csr_fits_in_dccm() {
        assert!(MAX_CSR_SIZE <= IDEVID_CSR_SIZE as usize);
    }
}
