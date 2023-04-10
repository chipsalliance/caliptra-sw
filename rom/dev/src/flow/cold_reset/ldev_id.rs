/*++

Licensed under the Apache-2.0 license.

File Name:

    ldev_id.rs

Abstract:

    File contains the implementation of DICE Local Device Identity (IDEVID)
    layer.

--*/

use super::crypto::*;
use super::dice::*;
use super::x509::*;
use crate::cprint_slice;
use crate::cprintln;
use crate::rom_env::RomEnv;
use crate::rom_err_def;
use caliptra_drivers::*;
use caliptra_x509::*;

use crate::flow::cold_reset::{KEY_ID_CDI, KEY_ID_FE, KEY_ID_LDEVID_PRIV_KEY};

rom_err_def! {
    LocalDevId,
    LocalevIdErr
    {
        CertVerify = 0x1,
    }
}

/// Dice Local Device Identity (IDEVID) Layer
#[derive(Default)]
pub struct LocalDevIdLayer {}

impl LocalDevIdLayer {
    /// Perform derivations for the DICE layer
    ///
    /// # Arguments
    ///
    /// * `env`   - ROM Environment
    /// * `idevid_output` - Dice output
    ///
    /// # Returns
    ///
    /// * `DiceOutput` - key pair, subject identifier serial number, subject key identifier
    pub fn derive(env: &RomEnv, idevid_output: &DiceOutput) -> CaliptraResult<DiceOutput> {
        cprintln!("[ldev] ++");
        cprintln!("[ldev] CDI.KEYID = {}", KEY_ID_CDI as u8);
        cprintln!("[ldev] SUBJECT.KEYID = {}", KEY_ID_LDEVID_PRIV_KEY as u8);
        cprintln!(
            "[ldev] AUTHORITY.KEYID = {}",
            idevid_output.subj_key_pair.priv_key as u8
        );
        cprintln!("[ldev] FE.KEYID = {}", KEY_ID_FE as u8);

        // Derive the DICE CDI from decrypted field entropy
        Self::derive_cdi(env, KEY_ID_FE, KEY_ID_CDI)?;

        // Derive DICE Key Pair from CDI
        let ldevid_key_pair = Self::derive_key_pair(env, KEY_ID_CDI, KEY_ID_LDEVID_PRIV_KEY)?;

        // Generate the Subject Serial Number and Subject Key Identifier.
        //
        // This information will be used by the next DICE Layer while generating
        // certificates
        let subj_sn = X509::subj_sn(env, &ldevid_key_pair.pub_key)?;
        let subj_key_id = X509::subj_key_id(env, &ldevid_key_pair.pub_key)?;

        // Generate the output for next layer
        let ldevid_output = DiceOutput {
            subj_key_pair: ldevid_key_pair,
            subj_sn,
            subj_key_id,
        };

        // Generate Local Device ID Certificate
        Self::generate_cert_sig(env, idevid_output, &ldevid_output)?;

        cprintln!("[ldev] --");

        Ok(ldevid_output)
    }

    /// Derive Composite Device Identity (CDI) from Field Entropy
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `fe` - Key slot holding the field entropy
    /// * `cdi` - Key Slot to store the generated CDI
    fn derive_cdi(env: &RomEnv, fe: KeyId, cdi: KeyId) -> CaliptraResult<()> {
        // CDI Key
        let key = Hmac384Key::Key(KeyReadArgs::new(cdi));
        let data = Hmac384Data::Key(KeyReadArgs::new(fe));
        Crypto::hmac384_mac(env, key, data, cdi)?;

        cprintln!("[ldev] Erasing FE.KEYID = {}", fe as u8);
        env.key_vault().map(|k| k.erase_key(fe))?;

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
    fn derive_key_pair(env: &RomEnv, cdi: KeyId, priv_key: KeyId) -> CaliptraResult<Ecc384KeyPair> {
        Crypto::ecc384_key_gen(env, cdi, priv_key)
    }

    /// Generate Local Device ID Certificate Signature
    ///
    /// # Arguments
    ///
    /// * `env`           - ROM Environment
    /// * `idevid_output` - DICE Output for IDevID layer
    /// * `ldevid_output` - DICE Output for LDevID layer
    fn generate_cert_sig(
        env: &RomEnv,
        idevid_output: &DiceOutput,
        ldevid_output: &DiceOutput,
    ) -> CaliptraResult<()> {
        let auth_priv_key = idevid_output.subj_key_pair.priv_key;
        let auth_pub_key = &idevid_output.subj_key_pair.pub_key;
        let pub_key = &ldevid_output.subj_key_pair.pub_key;

        // CSR `To Be Signed` Parameters
        let params = LocalDevIdCertTbsParams {
            ueid: &X509::ueid(env)?,
            subject_sn: &ldevid_output.subj_sn,
            subject_key_id: &ldevid_output.subj_key_id,
            issuer_sn: &idevid_output.subj_sn,
            authority_key_id: &idevid_output.subj_key_id,
            serial_number: &X509::cert_sn(env, pub_key)?,
            public_key: &pub_key.to_der(),
        };

        // Generate the `To Be Signed` portion of the CSR
        let tbs = LocalDevIdCertTbs::new(&params);

        // Sign the the `To Be Signed` portion
        cprintln!(
            "[ldev] Signing Cert with AUTHORITY.KEYID = {}",
            auth_priv_key as u8
        );
        let sig = Crypto::ecdsa384_sign(env, auth_priv_key, tbs.tbs())?;

        // Clear the authority private key
        cprintln!("[ldev] Erasing AUTHORITY.KEYID = {}", auth_priv_key as u8);
        env.key_vault().map(|k| k.erase_key(auth_priv_key))?;

        // Verify the signature of the `To Be Signed` portion
        if !Crypto::ecdsa384_verify(env, auth_pub_key, tbs.tbs(), &sig)? {
            raise_err!(CertVerify);
        }

        let _pub_x: [u8; 48] = pub_key.x.into();
        let _pub_y: [u8; 48] = pub_key.y.into();
        cprint_slice!("[ldev] PUB.X", _pub_x);
        cprint_slice!("[ldev] PUB.Y", _pub_y);

        let _sig_r: [u8; 48] = sig.r.into();
        let _sig_s: [u8; 48] = sig.s.into();
        cprint_slice!("[ldev] SIG.R", _sig_r);
        cprint_slice!("[ldev] SIG.S", _sig_s);

        // Lock the Local Device ID cert signature in data vault until
        // cold reset
        env.data_vault().map(|d| d.set_ldev_dice_signature(&sig));

        // Lock the Local Device ID public keys in data vault until
        // cold reset
        env.data_vault().map(|d| d.set_ldev_dice_pub_key(pub_key));

        Ok(())
    }
}
