/*++

Licensed under the Apache-2.0 license.

File Name:

    ldev_id.rs

Abstract:

    File contains the implementation of DICE Local Device Identity (LDEVID)
    layer.

--*/

use super::crypto::*;
use super::dice::*;
use super::x509::*;
use crate::cprintln;
use crate::flow::cold_reset::{copy_tbs, TbsType};
use crate::flow::cold_reset::{KEY_ID_CDI, KEY_ID_FE, KEY_ID_LDEVID_PRIV_KEY};
use crate::print::HexBytes;
use crate::rom_env::RomEnv;
use caliptra_common::RomBootStatus::*;
use caliptra_drivers::*;
use caliptra_x509::*;

/// Dice Local Device Identity (IDEVID) Layer
#[derive(Default)]
pub struct LocalDevIdLayer {}

impl DiceLayer for LocalDevIdLayer {
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
    fn derive(env: &mut RomEnv, input: &DiceInput) -> CaliptraResult<DiceOutput> {
        cprintln!("[ldev] ++");
        cprintln!("[ldev] CDI.KEYID = {}", KEY_ID_CDI as u8);
        cprintln!("[ldev] SUBJECT.KEYID = {}", KEY_ID_LDEVID_PRIV_KEY as u8);
        cprintln!(
            "[ldev] AUTHORITY.KEYID = {}",
            input.auth_key_pair.priv_key as u8
        );
        cprintln!("[ldev] FE.KEYID = {}", KEY_ID_FE as u8);

        // The measurement for this layer is generated by previous layer
        // (Initial Device ID DICE Layer).
        //
        // This is the decrypted Field Entropy
        Self::derive_cdi(env, KEY_ID_FE, KEY_ID_CDI)?;

        // Derive DICE Key Pair from CDI
        let key_pair = Self::derive_key_pair(env, KEY_ID_CDI, KEY_ID_LDEVID_PRIV_KEY)?;

        // Generate the Subject Serial Number and Subject Key Identifier.
        //
        // This information will be used by the next DICE Layer while generating
        // certificates
        let subj_sn = X509::subj_sn(env, &key_pair.pub_key)?;
        report_boot_status(LDevIdSubjIdSnGenerationComplete.into());

        let subj_key_id = X509::subj_key_id(env, &key_pair.pub_key)?;
        report_boot_status(LDevIdSubjKeyIdGenerationComplete.into());

        // Generate the output for next layer
        let output = DiceOutput {
            subj_key_pair: key_pair,
            subj_sn,
            subj_key_id,
        };

        // Generate Local Device ID Certificate
        Self::generate_cert_sig(env, input, &output)?;

        cprintln!("[ldev] --");
        report_boot_status(LDevIdDerivationComplete.into());

        Ok(output)
    }
}

impl LocalDevIdLayer {
    /// Derive Composite Device Identity (CDI) from field entropy
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `fe`  - Key slot holding the field entropy
    /// * `cdi` - Key Slot to store the generated CDI
    fn derive_cdi(env: &mut RomEnv, fe: KeyId, cdi: KeyId) -> CaliptraResult<()> {
        // CDI Key
        let key = Hmac384Key::Key(KeyReadArgs::new(cdi));
        let data = Hmac384Data::Key(KeyReadArgs::new(fe));
        Crypto::hmac384_mac(env, key, data, cdi)?;

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
        let result = Crypto::ecc384_key_gen(env, cdi, priv_key);
        if result.is_ok() {
            report_boot_status(LDevIdKeyPairDerivationComplete.into());
        }
        result
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
    ) -> CaliptraResult<()> {
        let auth_priv_key = input.auth_key_pair.priv_key;
        let auth_pub_key = &input.auth_key_pair.pub_key;
        let pub_key = &output.subj_key_pair.pub_key;

        let serial_number = X509::cert_sn(env, pub_key);
        let serial_number = okref(&serial_number)?;

        // CSR `To Be Signed` Parameters
        let params = LocalDevIdCertTbsParams {
            ueid: &X509::ueid(env)?,
            subject_sn: &output.subj_sn,
            subject_key_id: &output.subj_key_id,
            issuer_sn: input.auth_sn,
            authority_key_id: input.auth_key_id,
            serial_number,
            public_key: &pub_key.to_der(),
            not_before: &NotBefore::default().not_before,
            not_after: &NotAfter::default().not_after,
        };

        // Generate the `To Be Signed` portion of the CSR
        let tbs = LocalDevIdCertTbs::new(&params);

        // Sign the the `To Be Signed` portion
        cprintln!(
            "[ldev] Signing Cert with AUTHORITY.KEYID = {}",
            auth_priv_key as u8
        );
        let sig = Crypto::ecdsa384_sign(env, auth_priv_key, tbs.tbs());
        let sig = okref(&sig)?;

        // Clear the authority private key
        //To-Do : Disabling The Print Temporarily
        //cprintln!("[ldev] Erasing AUTHORITY.KEYID = {}", auth_priv_key as u8);
        env.key_vault.erase_key(auth_priv_key)?;

        // Verify the signature of the `To Be Signed` portion
        if !Crypto::ecdsa384_verify(env, auth_pub_key, tbs.tbs(), sig)? {
            return Err(CaliptraError::ROM_LDEVID_CSR_VERIFICATION_FAILURE);
        }

        let _pub_x: [u8; 48] = (&pub_key.x).into();
        let _pub_y: [u8; 48] = (&pub_key.y).into();
        cprintln!("[ldev] PUB.X = {}", HexBytes(&_pub_x));
        cprintln!("[ldev] PUB.Y = {}", HexBytes(&_pub_y));

        let _sig_r: [u8; 48] = (&sig.r).into();
        let _sig_s: [u8; 48] = (&sig.s).into();
        cprintln!("[ldev] SIG.R = {}", HexBytes(&_sig_r));
        cprintln!("[ldev] SIG.S = {}", HexBytes(&_sig_s));

        // Lock the Local Device ID cert signature in data vault until
        // cold reset
        env.data_vault.set_ldev_dice_signature(sig);

        // Lock the Local Device ID public keys in data vault until
        // cold reset
        env.data_vault.set_ldev_dice_pub_key(pub_key);

        //  Copy TBS to DCCM.
        copy_tbs(tbs.tbs(), TbsType::LdevidTbs)?;

        report_boot_status(LDevIdCertSigGenerationComplete.into());
        Ok(())
    }
}
