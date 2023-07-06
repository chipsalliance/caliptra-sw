/*++

Licensed under the Apache-2.0 license.

File Name:

    fmc_alias.rs

Abstract:

    File contains the implementation of DICE First Mutable Code (FMC)
    layer.

--*/

use super::crypto::{Crypto, Ecc384KeyPair};
use super::dice::{DiceInput, DiceOutput};
use super::fw_processor::FwProcInfo;
use super::x509::X509;
use crate::cprintln;
use crate::flow::cold_reset::{copy_tbs, TbsType};
use crate::flow::cold_reset::{KEY_ID_CDI, KEY_ID_FMC_PRIV_KEY};
use crate::print::HexBytes;
use crate::rom_env::RomEnv;
use caliptra_common::dice;
use caliptra_common::RomBootStatus::*;
use caliptra_drivers::{
    okref, report_boot_status, Array4x12, CaliptraResult, Hmac384Data, Hmac384Key, KeyId,
    KeyReadArgs, Lifecycle,
};
use caliptra_error::CaliptraError;
use caliptra_x509::{FmcAliasCertTbs, FmcAliasCertTbsParams};

#[derive(Default)]
pub struct FmcAliasLayer {}

impl FmcAliasLayer {
    /// Perform derivations for the DICE layer
    pub fn derive(
        env: &mut RomEnv,
        input: &DiceInput,
        fw_proc_info: &FwProcInfo,
    ) -> CaliptraResult<()> {
        cprintln!("[afmc] ++");
        cprintln!("[afmc] CDI.KEYID = {}", KEY_ID_CDI as u8);
        cprintln!("[afmc] SUBJECT.KEYID = {}", KEY_ID_FMC_PRIV_KEY as u8);
        cprintln!(
            "[afmc] AUTHORITY.KEYID = {}",
            input.auth_key_pair.priv_key as u8
        );

        // We use the value of PCR0 as the measurement for deriving the CDI.
        let mut measurement = env.pcr_bank.read_pcr(caliptra_drivers::PcrId::PcrId0);

        // Derive the DICE CDI from decrypted UDS
        let result = Self::derive_cdi(env, &measurement, KEY_ID_CDI);
        measurement.0.fill(0);
        result?;

        // Derive DICE Key Pair from CDI
        let key_pair = Self::derive_key_pair(env, KEY_ID_CDI, KEY_ID_FMC_PRIV_KEY)?;
        report_boot_status(FmcAliasKeyPairDerivationComplete.into());

        // Generate the Subject Serial Number and Subject Key Identifier.
        //
        // This information will be used by next DICE Layer while generating
        // certificates
        let subj_sn = X509::subj_sn(env, &key_pair.pub_key)?;
        report_boot_status(FmcAliasSubjIdSnGenerationComplete.into());

        let subj_key_id = X509::subj_key_id(env, &key_pair.pub_key)?;
        report_boot_status(FmcAliasSubjKeyIdGenerationComplete.into());

        // Generate the output for next layer
        let mut output = DiceOutput {
            subj_key_pair: key_pair,
            subj_sn,
            subj_key_id,
        };

        // Generate Local Device ID Certificate
        Self::generate_cert_sig(env, input, &output, fw_proc_info)?;
        output.zeroize();

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
    fn derive_cdi(env: &mut RomEnv, measurements: &Array4x12, cdi: KeyId) -> CaliptraResult<()> {
        // CDI Key
        let key = Hmac384Key::Key(KeyReadArgs::new(cdi));
        let mut measurements: [u8; 48] = measurements.into();
        let data = Hmac384Data::Slice(&measurements);
        let result = Crypto::hmac384_mac(env, &key, &data, cdi);
        measurements.fill(0);
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
    /// * `priv_key` - Key slot to store the private key into
    ///
    /// # Returns
    ///
    /// * `Ecc384KeyPair` - Derive DICE Layer Key Pair
    fn derive_key_pair(
        env: &mut RomEnv,
        cdi: KeyId,
        priv_key: KeyId,
    ) -> CaliptraResult<Ecc384KeyPair> {
        Crypto::ecc384_key_gen(env, cdi, priv_key)
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
        let auth_priv_key = input.auth_key_pair.priv_key;
        let auth_pub_key = &input.auth_key_pair.pub_key;
        let pub_key = &output.subj_key_pair.pub_key;

        let flags = Self::make_flags(env.soc_ifc.lifecycle(), env.soc_ifc.debug_locked());

        let svn = env.data_vault.fmc_svn() as u8;
        let fuse_svn = fw_proc_info.fmc_effective_fuse_svn as u8;

        // Certificate `To Be Signed` Parameters
        let params = FmcAliasCertTbsParams {
            ueid: &X509::ueid(env)?,
            subject_sn: &output.subj_sn,
            subject_key_id: &output.subj_key_id,
            issuer_sn: input.auth_sn,
            authority_key_id: input.auth_key_id,
            serial_number: &X509::cert_sn(env, pub_key)?,
            public_key: &pub_key.to_der(),
            tcb_info_fmc_tci: &(&env.data_vault.fmc_tci()).into(),
            tcb_info_owner_pk_hash: &(&env.data_vault.owner_pk_hash()).into(),
            tcb_info_flags: &flags,
            tcb_info_fmc_svn: &svn.to_be_bytes(),
            tcb_info_fmc_svn_fuses: &fuse_svn.to_be_bytes(),
            not_before: &fw_proc_info.fmc_cert_valid_not_before.value,
            not_after: &fw_proc_info.fmc_cert_valid_not_after.value,
        };

        // Generate the `To Be Signed` portion of the CSR
        let tbs = FmcAliasCertTbs::new(&params);

        // Sign the the `To Be Signed` portion
        cprintln!(
            "[afmc] Signing Cert with AUTHORITY.KEYID = {}",
            auth_priv_key as u8
        );
        let sig = Crypto::ecdsa384_sign(env, auth_priv_key, tbs.tbs());
        let sig = okref(&sig)?;

        // Clear the authority private key
        cprintln!("[afmc] Erasing AUTHORITY.KEYID = {}", auth_priv_key as u8);
        env.key_vault.erase_key(auth_priv_key)?;

        // Verify the signature of the `To Be Signed` portion
        if !Crypto::ecdsa384_verify(env, auth_pub_key, tbs.tbs(), sig)? {
            return Err(CaliptraError::FMC_ALIAS_CERT_VERIFY);
        }

        let _pub_x: [u8; 48] = (&pub_key.x).into();
        let _pub_y: [u8; 48] = (&pub_key.y).into();
        cprintln!("[afmc] PUB.X = {}", HexBytes(&_pub_x));
        cprintln!("[afmc] PUB.Y = {}", HexBytes(&_pub_y));

        let _sig_r: [u8; 48] = (&sig.r).into();
        let _sig_s: [u8; 48] = (&sig.s).into();
        cprintln!("[afmc] SIG.R = {}", HexBytes(&_sig_r));
        cprintln!("[afmc] SIG.S = {}", HexBytes(&_sig_s));

        // Lock the FMC Certificate Signature in data vault until next boot
        env.data_vault.set_fmc_dice_signature(sig);

        // Lock the FMC Public key in the data vault until next boot
        env.data_vault.set_fmc_pub_key(pub_key);

        //  Copy TBS to DCCM.
        copy_tbs(tbs.tbs(), TbsType::FmcaliasTbs, env)?;

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

        flags.to_be_bytes()
    }
}
