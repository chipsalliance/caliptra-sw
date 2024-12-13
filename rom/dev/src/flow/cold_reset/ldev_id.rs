/*++

Licensed under the Apache-2.0 license.

File Name:

    ldev_id.rs

Abstract:

    File contains the implementation of DICE Local Device Identity (LDEVID)
    layer.

--*/

use super::dice::*;
use crate::cprintln;
use crate::crypto::Crypto;
use crate::flow::cold_reset::{copy_tbs, TbsType};
use crate::print::HexBytes;
use crate::rom_env::RomEnv;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_cfi_lib::{cfi_assert, cfi_assert_bool, cfi_launder};
use caliptra_common::{
    crypto::{Ecc384KeyPair, MlDsaKeyPair, PubKey},
    keyids::{
        KEY_ID_FE, KEY_ID_LDEVID_ECDSA_PRIV_KEY, KEY_ID_LDEVID_MLDSA_KEYPAIR_SEED,
        KEY_ID_ROM_FMC_CDI,
    },
    x509,
    RomBootStatus::*,
};
use caliptra_drivers::*;
use caliptra_x509::*;
use zerocopy::AsBytes;
use zeroize::Zeroize;

/// Dice Local Device Identity (IDEVID) Layer
#[derive(Default)]
pub struct LocalDevIdLayer {}

impl LocalDevIdLayer {
    /// Perform derivations for the DICE layer
    ///
    /// # Arguments
    ///
    /// * `env`   - ROM Environment
    /// * `input` - Dice input
    ///
    /// # Returns
    ///
    /// * `DiceOutput` - key pair, subject identifier serial number, subject key identifier
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn derive(env: &mut RomEnv, input: &DiceInput) -> CaliptraResult<DiceOutput> {
        cprintln!("[ldev] ++");
        cprintln!("[ldev] CDI.KEYID = {}", KEY_ID_ROM_FMC_CDI as u8);
        cprintln!(
            "[ldev] ECC SUBJECT.KEYID = {}, MLDSA SUBJECT.KEYID = {}",
            KEY_ID_LDEVID_ECDSA_PRIV_KEY as u8,
            KEY_ID_LDEVID_MLDSA_KEYPAIR_SEED as u8,
        );
        cprintln!(
            "[ldev] ECC AUTHORITY.KEYID = {}, MLDSA AUTHORITY.KEYID = {}",
            input.ecc_auth_key_pair.priv_key as u8,
            input.mldsa_auth_key_pair.key_pair_seed as u8,
        );
        cprintln!("[ldev] FE.KEYID = {}", KEY_ID_FE as u8);

        // The measurement for this layer is generated by previous layer
        // (Initial Device ID DICE Layer).
        //
        // This is the decrypted Field Entropy
        Self::derive_cdi(env, KEY_ID_FE, KEY_ID_ROM_FMC_CDI)?;

        // Derive DICE ECC and MLDSA Key Pairs from CDI
        let (ecc_key_pair, mldsa_key_pair) = Self::derive_key_pair(
            env,
            KEY_ID_ROM_FMC_CDI,
            KEY_ID_LDEVID_ECDSA_PRIV_KEY,
            KEY_ID_LDEVID_MLDSA_KEYPAIR_SEED,
        )?;

        // Generate the Subject Serial Number and Subject Key Identifier.
        //
        // This information will be used by the next DICE Layer while generating
        // certificates
        let ecc_subj_sn =
            x509::X509::subj_sn(&mut env.sha256, &PubKey::Ecc(&ecc_key_pair.pub_key))?;
        let mldsa_subj_sn =
            x509::X509::subj_sn(&mut env.sha256, &PubKey::Mldsa(&mldsa_key_pair.pub_key))?;
        report_boot_status(LDevIdSubjIdSnGenerationComplete.into());

        let ecc_subj_key_id =
            x509::X509::subj_key_id(&mut env.sha256, &PubKey::Ecc(&ecc_key_pair.pub_key))?;
        let mldsa_subj_key_id =
            x509::X509::subj_key_id(&mut env.sha256, &PubKey::Mldsa(&mldsa_key_pair.pub_key))?;
        report_boot_status(LDevIdSubjKeyIdGenerationComplete.into());

        // Generate the output for next layer
        let output = DiceOutput {
            ecc_subj_key_pair: ecc_key_pair,
            ecc_subj_sn,
            ecc_subj_key_id,
            mldsa_subj_key_pair: mldsa_key_pair,
            mldsa_subj_sn,
            mldsa_subj_key_id,
        };

        // Generate Local Device ID Certificate
        Self::generate_cert_sig_ecc(env, input, &output)?;
        Self::generate_cert_sig_mldsa(env, input, &output)?;

        cprintln!("[ldev] --");
        report_boot_status(LDevIdDerivationComplete.into());

        Ok(output)
    }

    /// Derive Composite Device Identity (CDI) from field entropy
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `fe`  - Key slot holding the field entropy
    /// * `cdi` - Key Slot to store the generated CDI
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_cdi(env: &mut RomEnv, fe: KeyId, cdi: KeyId) -> CaliptraResult<()> {
        Crypto::hmac_mac(env, cdi, &b"ldevid_cdi".into(), cdi, HmacMode::Hmac512)?;
        Crypto::hmac_mac(
            env,
            cdi,
            &KeyReadArgs::new(fe).into(),
            cdi,
            HmacMode::Hmac512,
        )?;

        cprintln!("[ldev] Erasing FE.KEYID = {}", fe as u8);
        env.key_vault.erase_key(fe)?;
        report_boot_status(LDevIdCdiDerivationComplete.into());
        Ok(())
    }

    /// Derive Dice Layer Key Pair
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
        let result = Crypto::ecc384_key_gen(env, cdi, b"ldevid_ecc_key", ecc_priv_key);
        if cfi_launder(result.is_ok()) {
            cfi_assert!(result.is_ok());
        } else {
            cfi_assert!(result.is_err());
        }
        let ecc_keypair = result?;

        // Derive the MLDSA Key Pair.
        let result = Crypto::mldsa_key_gen(env, cdi, b"ldevid_mldsa_key", mldsa_keypair_seed);
        if cfi_launder(result.is_ok()) {
            cfi_assert!(result.is_ok());
        } else {
            cfi_assert!(result.is_err());
        }
        let mldsa_keypair = result?;

        report_boot_status(LDevIdKeyPairDerivationComplete.into());
        Ok((ecc_keypair, mldsa_keypair))
    }

    /// Generate ECC Local Device ID Certificate Signature
    ///
    /// # Arguments
    ///
    /// * `env`    - ROM Environment
    /// * `input`  - DICE Input
    /// * `output` - DICE Output
    fn generate_cert_sig_ecc(
        env: &mut RomEnv,
        input: &DiceInput,
        output: &DiceOutput,
    ) -> CaliptraResult<()> {
        let ecc_auth_priv_key = input.ecc_auth_key_pair.priv_key;
        let ecc_auth_pub_key = &input.ecc_auth_key_pair.pub_key;
        let ecc_pub_key = &output.ecc_subj_key_pair.pub_key;

        let ecc_serial_number = x509::X509::ecc_cert_sn(&mut env.sha256, ecc_pub_key);
        let ecc_serial_number = okref(&ecc_serial_number)?;

        // CSR `To Be Signed` Parameters
        let ecc_tbs_params = LocalDevIdCertTbsEcc384Params {
            ueid: &x509::X509::ueid(&env.soc_ifc)?,
            subject_sn: &output.ecc_subj_sn,
            subject_key_id: &output.ecc_subj_key_id,
            issuer_sn: input.ecc_auth_sn,
            authority_key_id: input.ecc_auth_key_id,
            serial_number: ecc_serial_number,
            public_key: &ecc_pub_key.to_der(),
            not_before: &NotBefore::default().value,
            not_after: &NotAfter::default().value,
        };

        // Generate the ECC `To Be Signed` portion of the CSR
        let ecc_tbs = LocalDevIdCertTbsEcc384::new(&ecc_tbs_params);

        // Sign the `To Be Signed` portion
        cprintln!(
            "[ldev] Signing Cert with ECC AUTHORITY.KEYID = {}",
            ecc_auth_priv_key as u8
        );
        let mut sig = Crypto::ecdsa384_sign_and_verify(
            env,
            ecc_auth_priv_key,
            ecc_auth_pub_key,
            ecc_tbs.tbs(),
        );
        let sig = okmutref(&mut sig)?;

        // Clear the authority private key
        env.key_vault.erase_key(ecc_auth_priv_key).map_err(|err| {
            sig.zeroize();
            err
        })?;

        let _pub_x: [u8; 48] = (&ecc_pub_key.x).into();
        let _pub_y: [u8; 48] = (&ecc_pub_key.y).into();
        cprintln!("[ldev] PUB.X = {}", HexBytes(&_pub_x));
        cprintln!("[ldev] PUB.Y = {}", HexBytes(&_pub_y));

        let _sig_r: [u8; 48] = (&sig.r).into();
        let _sig_s: [u8; 48] = (&sig.s).into();
        cprintln!("[ldev] SIG.R = {}", HexBytes(&_sig_r));
        cprintln!("[ldev] SIG.S = {}", HexBytes(&_sig_s));

        let data_vault = &mut env.persistent_data.get_mut().data_vault;

        // Save the Local Device ID cert signature in data vault.
        data_vault.set_ldev_dice_ecc_signature(sig);
        sig.zeroize();

        // Save the Local Device ID public key in data vault.
        data_vault.set_ldev_dice_ecc_pub_key(ecc_pub_key);

        //  Copy TBS to DCCM.
        copy_tbs(ecc_tbs.tbs(), TbsType::EccLdevid, env)?;
        Ok(())
    }

    /// Generate MLDSA Local Device ID Certificate Signature
    ///
    /// # Arguments
    ///
    /// * `env`    - ROM Environment
    /// * `input`  - DICE Input
    /// * `output` - DICE Output
    fn generate_cert_sig_mldsa(
        env: &mut RomEnv,
        input: &DiceInput,
        output: &DiceOutput,
    ) -> CaliptraResult<()> {
        let mldsa_auth_priv_key = input.mldsa_auth_key_pair.key_pair_seed;
        let mldsa_auth_pub_key = &input.mldsa_auth_key_pair.pub_key;
        let mldsa_pub_key = &output.mldsa_subj_key_pair.pub_key;

        let mldsa_serial_number = x509::X509::mldsa_cert_sn(&mut env.sha256, mldsa_pub_key);
        let mldsa_serial_number = okref(&mldsa_serial_number)?;

        // CSR `To Be Signed` Parameters
        let mldsa_tbs_params = LocalDevIdCertTbsMlDsa87Params {
            ueid: &x509::X509::ueid(&env.soc_ifc)?,
            subject_sn: &output.mldsa_subj_sn,
            subject_key_id: &output.mldsa_subj_key_id,
            issuer_sn: input.mldsa_auth_sn,
            authority_key_id: input.mldsa_auth_key_id,
            serial_number: mldsa_serial_number,
            public_key: mldsa_pub_key.as_bytes().try_into().unwrap(),
            not_before: &NotBefore::default().value,
            not_after: &NotAfter::default().value,
        };

        // Generate the ECC `To Be Signed` portion of the CSR
        let mldsa_tbs = LocalDevIdCertTbsMlDsa87::new(&mldsa_tbs_params);

        // Sign the `To Be Signed` portion
        cprintln!(
            "[ldev] Signing Cert with MLDSA AUTHORITY.KEYID = {}",
            mldsa_auth_priv_key as u8
        );
        let mut sig = Crypto::mldsa87_sign_and_verify(
            env,
            mldsa_auth_priv_key,
            mldsa_auth_pub_key,
            mldsa_tbs.tbs(),
        );
        let sig = okmutref(&mut sig)?;

        // Clear the authority private key
        env.key_vault
            .erase_key(mldsa_auth_priv_key)
            .map_err(|err| {
                sig.zeroize();
                err
            })?;

        let data_vault = &mut env.persistent_data.get_mut().data_vault;

        // Save the Local Device ID cert signature in data vault.
        data_vault.set_ldev_dice_mldsa_signature(sig);
        sig.zeroize();

        // Save the Local Device ID public key in data vault.
        data_vault.set_ldev_dice_mldsa_pub_key(mldsa_pub_key);

        //  Copy TBS to DCCM.
        copy_tbs(mldsa_tbs.tbs(), TbsType::MldsaLdevid, env)?;

        report_boot_status(LDevIdCertSigGenerationComplete.into());
        Ok(())
    }
}
