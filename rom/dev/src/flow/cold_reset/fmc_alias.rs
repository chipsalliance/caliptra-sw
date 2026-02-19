/*++

Licensed under the Apache-2.0 license.

File Name:

    fmc_alias.rs

Abstract:

    File contains the implementation of DICE First Mutable Code (FMC)
    layer.

--*/

use super::dice::{DiceInput, DiceOutput};
use super::fw_processor::FwProcInfo;
use crate::cprintln;
use crate::flow::cold_reset::{copy_tbs, TbsType};
use crate::rom_env::RomEnv;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_cfi_lib::{cfi_assert, cfi_assert_bool, cfi_launder};
use caliptra_common::cfi_check;
use caliptra_common::crypto::{Crypto, Ecc384KeyPair, MlDsaKeyPair, PubKey};
use caliptra_common::keyids::{
    KEY_ID_FMC_ECDSA_PRIV_KEY, KEY_ID_FMC_MLDSA_KEYPAIR_SEED, KEY_ID_ROM_FMC_CDI,
};
use caliptra_common::pcr::PCR_ID_FMC_CURRENT;
use caliptra_common::RomBootStatus::*;
use caliptra_common::{dice, x509};
use caliptra_drivers::{
    okmutref, report_boot_status, Array4x12, CaliptraResult, HmacMode, KeyId, KeyUsage,
};
use caliptra_x509::{
    FmcAliasCertTbsEcc384, FmcAliasCertTbsEcc384Params, FmcAliasCertTbsMlDsa87,
    FmcAliasCertTbsMlDsa87Params,
};
use zeroize::Zeroize;

#[derive(Default)]
pub struct FmcAliasLayer {}

impl FmcAliasLayer {
    /// Perform derivations for the DICE layer
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn derive(
        env: &mut RomEnv,
        input: &DiceInput,
        fw_proc_info: &FwProcInfo,
    ) -> CaliptraResult<()> {
        cprintln!("[afmc] ++");

        // We use the value of PCR0 as the measurement for deriving the CDI.
        let mut measurement = env.pcr_bank.read_pcr(PCR_ID_FMC_CURRENT);

        // Derive the DICE CDI from the measurement
        let result = Self::derive_cdi(env, &measurement, KEY_ID_ROM_FMC_CDI);
        measurement.0.zeroize();
        result?;

        // Derive DICE ECC and MLDSA Key Pairs from CDI
        let (ecc_key_pair, mldsa_key_pair) = Self::derive_key_pair(
            env,
            KEY_ID_ROM_FMC_CDI,
            KEY_ID_FMC_ECDSA_PRIV_KEY,
            KEY_ID_FMC_MLDSA_KEYPAIR_SEED,
        )?;

        // Generate the Subject Serial Number and Subject Key Identifier.
        //
        // This information will be used by next DICE Layer while generating
        // certificates
        let ecc_subj_sn = x509::subj_sn(&mut env.sha256, &PubKey::Ecc(&ecc_key_pair.pub_key))?;
        let mldsa_subj_sn =
            x509::subj_sn(&mut env.sha256, &PubKey::Mldsa(&mldsa_key_pair.pub_key))?;
        report_boot_status(FmcAliasSubjIdSnGenerationComplete.into());

        let ecc_subj_key_id =
            x509::subj_key_id(&mut env.sha256, &PubKey::Ecc(&ecc_key_pair.pub_key))?;
        let mldsa_subj_key_id =
            x509::subj_key_id(&mut env.sha256, &PubKey::Mldsa(&mldsa_key_pair.pub_key))?;
        report_boot_status(FmcAliasSubjKeyIdGenerationComplete.into());

        // Generate the output for next layer
        let mut output = DiceOutput {
            ecc_subj_key_pair: ecc_key_pair,
            ecc_subj_sn,
            ecc_subj_key_id,
            mldsa_subj_key_pair: mldsa_key_pair,
            mldsa_subj_sn,
            mldsa_subj_key_id,
        };

        // Generate FMC Alias Certificate
        let result: CaliptraResult<()> = (|| {
            Self::generate_cert_sig_ecc(env, input, &output, fw_proc_info)?;
            Self::generate_cert_sig_mldsa(env, input, &output, fw_proc_info)?;
            Ok(())
        })();
        output.zeroize();
        result?;

        report_boot_status(FmcAliasDerivationComplete.into());
        cprintln!("[afmc] --");

        Ok(())
    }

    /// Derive Composite Device Identity (CDI) from FMC measurements
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `measurements` - Array containing the FMC measurements
    /// * `cdi` - Key Slot to store the generated CDI
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn derive_cdi(env: &mut RomEnv, measurements: &Array4x12, cdi: KeyId) -> CaliptraResult<()> {
        let mut measurements: [u8; 48] = measurements.into();

        let result = Crypto::hmac_kdf(
            &mut env.hmac,
            &mut env.trng,
            cdi,
            b"alias_fmc_cdi",
            Some(&measurements),
            KEY_ID_ROM_FMC_CDI,
            HmacMode::Hmac512,
            KeyUsage::default()
                .set_ecc_key_gen_seed_en()
                .set_mldsa_key_gen_seed_en()
                .set_hmac_key_en(),
        );
        measurements.zeroize();
        result?;
        report_boot_status(FmcAliasDeriveCdiComplete.into());
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
    /// * `Ecc384KeyPair` - Derive DICE Layer Key Pair
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
            b"alias_fmc_ecc_key",
            ecc_priv_key,
        );
        cfi_check!(result);
        let ecc_keypair = result?;

        // Derive the MLDSA Key Pair.
        let result = env.abr.with_mldsa87(|mut mldsa87| {
            Crypto::mldsa87_key_gen(
                &mut mldsa87,
                &mut env.hmac,
                &mut env.trng,
                cdi,
                b"alias_fmc_mldsa_key",
                mldsa_keypair_seed,
            )
        });
        cfi_check!(result);
        let mldsa_keypair = result?;

        report_boot_status(FmcAliasKeyPairDerivationComplete.into());
        Ok((ecc_keypair, mldsa_keypair))
    }

    /// Generate Local Device ID Certificate Signature
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
        fw_proc_info: &FwProcInfo,
    ) -> CaliptraResult<()> {
        let auth_priv_key = input.ecc_auth_key_pair.priv_key;
        let auth_pub_key = &input.ecc_auth_key_pair.pub_key;
        let pub_key = &output.ecc_subj_key_pair.pub_key;
        let data_vault = &env.persistent_data.get().rom.data_vault;
        let soc_ifc: &caliptra_drivers::SocIfc = &env.soc_ifc;
        let sha2_512_384 = &mut env.sha2_512_384;

        let svn = data_vault.cold_boot_fw_svn() as u8;
        let owner_device_info_hash =
            dice::gen_fmc_alias_owner_device_info_hash(soc_ifc, data_vault, sha2_512_384)?;
        let vendor_device_info_hash =
            dice::gen_fmc_alias_vendor_device_info_hash(soc_ifc, data_vault, sha2_512_384)?;

        // Certificate `To Be Signed` Parameters
        let params = FmcAliasCertTbsEcc384Params {
            ueid: &x509::ueid(soc_ifc)?,
            subject_sn: &output.ecc_subj_sn,
            subject_key_id: &output.ecc_subj_key_id,
            issuer_sn: input.ecc_auth_sn,
            authority_key_id: input.ecc_auth_key_id,
            serial_number: &x509::ecc_cert_sn(&mut env.sha256, pub_key)?,
            public_key: &pub_key.to_der(),
            tcb_info_fmc_tci: &(&data_vault.fmc_tci()).into(),
            tcb_info_owner_device_info_hash: &owner_device_info_hash,
            tcb_info_vendor_device_info_hash: &vendor_device_info_hash,
            tcb_info_fw_svn: &svn.to_be_bytes(),
            not_before: &fw_proc_info.fmc_cert_valid_not_before.value,
            not_after: &fw_proc_info.fmc_cert_valid_not_after.value,
        };

        // Generate the `To Be Signed` portion of the CSR
        let tbs = FmcAliasCertTbsEcc384::new(&params);

        // Sign the `To Be Signed` portion
        cprintln!(
            "[afmc] ECC Signing Cert w/ AUTHORITY.KEYID = {}",
            auth_priv_key as u8
        );
        let mut sig = Crypto::ecdsa384_sign_and_verify(
            &mut env.sha2_512_384,
            &mut env.ecc384,
            &mut env.trng,
            auth_priv_key,
            auth_pub_key,
            tbs.tbs(),
        );
        let sig = okmutref(&mut sig)?;

        // Clear the authority private key
        env.key_vault.erase_key(auth_priv_key).inspect_err(|_err| {
            sig.zeroize();
        })?;

        // Set the FMC Certificate Signature in data vault.
        let data_vault = &mut env.persistent_data.get_mut().rom.data_vault;
        data_vault.set_fmc_dice_ecc_signature(sig);
        sig.zeroize();

        // Set the FMC Public key in the data vault.
        data_vault.set_fmc_ecc_pub_key(pub_key);

        //  Copy TBS to DCCM.
        copy_tbs(tbs.tbs(), TbsType::EccFmcalias, env)?;

        Ok(())
    }

    /// Generate Local Device ID Certificate Signature
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
        fw_proc_info: &FwProcInfo,
    ) -> CaliptraResult<()> {
        let auth_priv_key = input.mldsa_auth_key_pair.key_pair_seed;
        let auth_pub_key = &input.mldsa_auth_key_pair.pub_key;
        let pub_key = output.mldsa_subj_key_pair.pub_key;
        let data_vault = &env.persistent_data.get().rom.data_vault;
        let soc_ifc = &env.soc_ifc;
        let sha2_512_384 = &mut env.sha2_512_384;

        let svn = data_vault.cold_boot_fw_svn() as u8;
        let owner_device_info_hash =
            dice::gen_fmc_alias_owner_device_info_hash(soc_ifc, data_vault, sha2_512_384)?;
        let vendor_device_info_hash =
            dice::gen_fmc_alias_vendor_device_info_hash(soc_ifc, data_vault, sha2_512_384)?;

        // Certificate `To Be Signed` Parameters
        let params = FmcAliasCertTbsMlDsa87Params {
            ueid: &x509::ueid(soc_ifc)?,
            subject_sn: &output.mldsa_subj_sn,
            subject_key_id: &output.mldsa_subj_key_id,
            issuer_sn: input.mldsa_auth_sn,
            authority_key_id: input.mldsa_auth_key_id,
            serial_number: &x509::mldsa_cert_sn(&mut env.sha256, &pub_key)?,
            public_key: &pub_key.into(),
            tcb_info_fmc_tci: &(&data_vault.fmc_tci()).into(),
            tcb_info_owner_device_info_hash: &owner_device_info_hash,
            tcb_info_vendor_device_info_hash: &vendor_device_info_hash,
            tcb_info_fw_svn: &svn.to_be_bytes(),
            not_before: &fw_proc_info.fmc_cert_valid_not_before.value,
            not_after: &fw_proc_info.fmc_cert_valid_not_after.value,
        };

        // Generate the `To Be Signed` portion of the CSR
        let tbs = FmcAliasCertTbsMlDsa87::new(&params);

        // Sign the `To Be Signed` portion
        cprintln!(
            "[afmc] MLDSA Signing Cert w/ AUTHORITY.KEYID = {}",
            auth_priv_key as u8
        );
        let mut sig = env.abr.with_mldsa87(|mut mldsa87| {
            Crypto::mldsa87_sign_and_verify(
                &mut mldsa87,
                &mut env.trng,
                auth_priv_key,
                auth_pub_key,
                tbs.tbs(),
            )
        });
        let sig = okmutref(&mut sig)?;

        // Clear the authority private key
        cprintln!(
            "[afmc] MLDSA Erase AUTHORITY.KEYID = {}",
            auth_priv_key as u8
        );
        env.key_vault.erase_key(auth_priv_key).inspect_err(|_err| {
            sig.zeroize();
        })?;

        // Set the FMC Certificate Signature in data vault.
        let data_vault = &mut env.persistent_data.get_mut().rom.data_vault;
        data_vault.set_fmc_dice_mldsa_signature(sig);
        sig.zeroize();

        // Set the FMC Public key in the data vault.
        data_vault.set_fmc_mldsa_pub_key(&pub_key);

        //  Copy TBS to DCCM.
        copy_tbs(tbs.tbs(), TbsType::MldsaFmcalias, env)?;

        report_boot_status(FmcAliasCertSigGenerationComplete.into());
        Ok(())
    }
}
