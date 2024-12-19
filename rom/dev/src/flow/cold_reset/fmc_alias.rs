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
use super::x509::X509;
use crate::cprintln;
use crate::crypto::{Crypto, Ecc384KeyPair, MlDsaKeyPair, PubKey};
use crate::flow::cold_reset::{copy_tbs, TbsType};
use crate::print::HexBytes;
use crate::rom_env::RomEnv;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_cfi_lib::{cfi_assert, cfi_assert_bool, cfi_launder};
use caliptra_common::dice;
use caliptra_common::keyids::{
    KEY_ID_FMC_ECDSA_PRIV_KEY, KEY_ID_FMC_MLDSA_KEYPAIR_SEED, KEY_ID_ROM_FMC_CDI,
};
use caliptra_common::pcr::PCR_ID_FMC_CURRENT;
use caliptra_common::RomBootStatus::*;
use caliptra_drivers::{
    okmutref, report_boot_status, sha2_512_384::Sha2DigestOpTrait, Array4x12, CaliptraResult,
    HmacMode, KeyId, Lifecycle,
};
use caliptra_x509::{FmcAliasCertTbs, FmcAliasCertTbsParams};
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
        cprintln!("[afmc] CDI.KEYID = {}", KEY_ID_ROM_FMC_CDI as u8);
        cprintln!(
            "[afmc] ECC SUBJECT.KEYID = {}, MLDSA SUBJECT.KEYID = {}",
            KEY_ID_FMC_ECDSA_PRIV_KEY as u8,
            KEY_ID_FMC_MLDSA_KEYPAIR_SEED as u8
        );
        cprintln!(
            "[afmc] ECC SUBJECT.KEYID = {}, MLDSA SUBJECT.KEYID = {}",
            KEY_ID_FMC_ECDSA_PRIV_KEY as u8,
            KEY_ID_FMC_MLDSA_KEYPAIR_SEED as u8
        );
        cprintln!(
            "[afmc] ECC AUTHORITY.KEYID = {}, MLDSA AUTHORITY.KEYID = {}",
            input.ecc_auth_key_pair.priv_key as u8,
            input.mldsa_auth_key_pair.key_pair_seed as u8
        );

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
        let ecc_subj_sn = X509::subj_sn(env, &PubKey::Ecc(&ecc_key_pair.pub_key))?;
        let mldsa_subj_sn = X509::subj_sn(env, &PubKey::Mldsa(&mldsa_key_pair.pub_key))?;
        report_boot_status(FmcAliasSubjIdSnGenerationComplete.into());

        let ecc_subj_key_id = X509::subj_key_id(env, &PubKey::Ecc(&ecc_key_pair.pub_key))?;
        let mldsa_subj_key_id = X509::subj_key_id(env, &PubKey::Mldsa(&mldsa_key_pair.pub_key))?;
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
        let result = Self::generate_cert_sig(env, input, &output, fw_proc_info);
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

        let result = Crypto::env_hmac_kdf(
            env,
            cdi,
            b"alias_fmc_cdi",
            Some(&measurements),
            KEY_ID_ROM_FMC_CDI,
            HmacMode::Hmac512,
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
        let result = Crypto::ecc384_key_gen(env, cdi, b"alias_fmc_ecc_key", ecc_priv_key);
        if cfi_launder(result.is_ok()) {
            cfi_assert!(result.is_ok());
        } else {
            cfi_assert!(result.is_err());
        }
        let ecc_keypair = result?;

        // Derive the MLDSA Key Pair.
        let result = Crypto::mldsa_key_gen(env, cdi, b"alias_fmc_mldsa_key", mldsa_keypair_seed);
        if cfi_launder(result.is_ok()) {
            cfi_assert!(result.is_ok());
        } else {
            cfi_assert!(result.is_err());
        }
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
    fn generate_cert_sig(
        env: &mut RomEnv,
        input: &DiceInput,
        output: &DiceOutput,
        fw_proc_info: &FwProcInfo,
    ) -> CaliptraResult<()> {
        let auth_priv_key = input.ecc_auth_key_pair.priv_key;
        let auth_pub_key = &input.ecc_auth_key_pair.pub_key;
        let pub_key = &output.ecc_subj_key_pair.pub_key;
        let data_vault = &env.persistent_data.get().data_vault;
        let soc_ifc = &env.soc_ifc;

        let flags = Self::make_flags(env.soc_ifc.lifecycle(), env.soc_ifc.debug_locked());

        let svn = data_vault.fmc_svn() as u8;
        let fuse_svn = fw_proc_info.effective_fuse_svn as u8;

        let mut fuse_info_digest = Array4x12::default();
        let mut hasher = env.sha2_512_384.sha384_digest_init()?;
        hasher.update(&[
            soc_ifc.lifecycle() as u8,
            soc_ifc.debug_locked() as u8,
            soc_ifc.fuse_bank().anti_rollback_disable() as u8,
            data_vault.vendor_ecc_pk_index() as u8,
            data_vault.vendor_pqc_pk_index() as u8,
            fw_proc_info.pqc_verify_config,
            fw_proc_info.owner_pub_keys_digest_in_fuses as u8,
        ])?;
        hasher.update(&<[u8; 48]>::from(
            soc_ifc.fuse_bank().vendor_pub_key_info_hash(),
        ))?;
        hasher.update(&<[u8; 48]>::from(data_vault.owner_pk_hash()))?;
        hasher.finalize(&mut fuse_info_digest)?;

        // Certificate `To Be Signed` Parameters
        let params = FmcAliasCertTbsParams {
            ueid: &X509::ueid(soc_ifc)?,
            subject_sn: &output.ecc_subj_sn,
            subject_key_id: &output.ecc_subj_key_id,
            issuer_sn: input.ecc_auth_sn,
            authority_key_id: input.ecc_auth_key_id,
            serial_number: &X509::ecc_cert_sn(&mut env.sha256, pub_key)?,
            public_key: &pub_key.to_der(),
            tcb_info_fmc_tci: &(&data_vault.fmc_tci()).into(),
            tcb_info_device_info_hash: &fuse_info_digest.into(),
            tcb_info_flags: &flags,
            tcb_info_fmc_svn: &svn.to_be_bytes(),
            tcb_info_fmc_svn_fuses: &fuse_svn.to_be_bytes(),
            not_before: &fw_proc_info.fmc_cert_valid_not_before.value,
            not_after: &fw_proc_info.fmc_cert_valid_not_after.value,
        };

        // Generate the `To Be Signed` portion of the CSR
        let tbs = FmcAliasCertTbs::new(&params);

        // Sign the `To Be Signed` portion
        cprintln!(
            "[afmc] Signing Cert w/ AUTHORITY.KEYID = {}",
            auth_priv_key as u8
        );
        let mut sig = Crypto::ecdsa384_sign_and_verify(env, auth_priv_key, auth_pub_key, tbs.tbs());
        let sig = okmutref(&mut sig)?;

        // Clear the authority private key
        cprintln!("[afmc] Erase AUTHORITY.KEYID = {}", auth_priv_key as u8);
        env.key_vault.erase_key(auth_priv_key).map_err(|err| {
            sig.zeroize();
            err
        })?;

        let _pub_x: [u8; 48] = (&pub_key.x).into();
        let _pub_y: [u8; 48] = (&pub_key.y).into();
        cprintln!("[afmc] PUB.X = {}", HexBytes(&_pub_x));
        cprintln!("[afmc] PUB.Y = {}", HexBytes(&_pub_y));

        let _sig_r: [u8; 48] = (&sig.r).into();
        let _sig_s: [u8; 48] = (&sig.s).into();
        cprintln!("[afmc] SIG.R = {}", HexBytes(&_sig_r));
        cprintln!("[afmc] SIG.S = {}", HexBytes(&_sig_s));

        // Set the FMC Certificate Signature in data vault.
        let data_vault = &mut env.persistent_data.get_mut().data_vault;
        data_vault.set_fmc_dice_ecc_signature(sig);
        sig.zeroize();

        // Set the FMC Public key in the data vault.
        data_vault.set_fmc_ecc_pub_key(pub_key);

        //  Copy TBS to DCCM.
        copy_tbs(tbs.tbs(), TbsType::FmcaliasTbs, env)?;

        // [CAP2][TODO] Generate MLDSA certificate signature, TBS.

        report_boot_status(FmcAliasCertSigGenerationComplete.into());
        Ok(())
    }

    /// Generate flags for DICE evidence
    ///
    /// # Arguments
    ///
    /// * `device_lifecycle` - Device lifecycle
    /// * `debug_locked`     - Debug locked
    fn make_flags(device_lifecycle: Lifecycle, debug_locked: bool) -> [u8; 4] {
        let mut flags: u32 = dice::FLAG_BIT_FIXED_WIDTH;

        flags |= match device_lifecycle {
            Lifecycle::Unprovisioned => dice::FLAG_BIT_NOT_CONFIGURED,
            Lifecycle::Manufacturing => dice::FLAG_BIT_NOT_SECURE,
            _ => 0,
        };

        if !debug_locked {
            flags |= dice::FLAG_BIT_DEBUG;
        }

        flags.reverse_bits().to_be_bytes()
    }
}
