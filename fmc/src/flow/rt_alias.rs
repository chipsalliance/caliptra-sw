/*++

Licensed under the Apache-2.0 license.

File Name:

    rt_alias.rs

Abstract:

    Alias RT DICE Layer & PCR extension

--*/
use crate::flow::crypto::Crypto;
use crate::flow::dice::{DiceInput, DiceLayer, DiceOutput};
use crate::flow::pcr::{extend_current_pcr, extend_journey_pcr};
use crate::flow::tci::Tci;
use crate::flow::x509::X509;
use crate::flow::KEY_ID_FMC_PRIV_KEY;
use crate::fmc_env::FmcEnv;
use crate::HandOff;
use caliptra_common::cprintln;
use caliptra_common::crypto::Ecc384KeyPair;
use caliptra_common::HexBytes;
use caliptra_drivers::{
    okref, CaliptraError, CaliptraResult, Ecc384PubKey, Hmac384Data, Hmac384Key, KeyId, KeyReadArgs,
};
use caliptra_x509::{NotAfter, NotBefore, RtAliasCertTbs, RtAliasCertTbsParams};

const SHA384_HASH_SIZE: usize = 48;

const RT_ALIAS_TBS_SIZE: usize = 0x1000;
extern "C" {
    static mut RTALIAS_TBS_ORG: [u8; RT_ALIAS_TBS_SIZE];
}

#[derive(Default)]
pub struct RtAliasLayer {}

impl DiceLayer for RtAliasLayer {
    /// Perform derivations for the DICE layer
    fn derive(
        env: &mut FmcEnv,
        hand_off: &HandOff,
        input: &DiceInput,
    ) -> CaliptraResult<DiceOutput> {
        cprintln!("[fmc] Derive CDI");
        // Derive CDI
        let cdi = *okref(&Self::derive_cdi(env, hand_off, input.cdi))?;
        cprintln!("[fmc] Derive Key Pair");

        // Derive DICE Key Pair from CDI
        let key_pair = Self::derive_key_pair(env, cdi, input.subj_priv_key)?;
        cprintln!("[fmc] Derive Key Pair - Done");

        // Generate the Subject Serial Number and Subject Key Identifier.
        //
        // This information will be used by next DICE Layer while generating
        // certificates
        let subj_sn = X509::subj_sn(env, &key_pair.pub_key)?;
        let subj_key_id = X509::subj_key_id(env, &key_pair.pub_key)?;

        let output = input.to_output(key_pair, subj_sn, subj_key_id);

        let nb = NotBefore::default();
        let nf = NotAfter::default();

        // Generate Rt Alias Certificate
        Self::generate_cert_sig(env, hand_off, input, &output, &nb.not_before, &nf.not_after)?;
        Ok(output)
    }
}

impl RtAliasLayer {
    #[inline(never)]
    pub fn run(env: &mut FmcEnv, hand_off: &HandOff) -> CaliptraResult<()> {
        cprintln!("[fmc] Extend RT PCRs");
        Self::extend_pcrs(env, hand_off)?;
        cprintln!("[fmc] Extend RT PCRs Done");

        // Retrieve Dice Input Layer from Hand Off and Derive Key
        match Self::dice_input_from_hand_off(hand_off) {
            Ok(input) => {
                let out = Self::derive(env, hand_off, &input)?;
                hand_off.update(out)
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
    fn dice_input_from_hand_off(hand_off: &HandOff) -> CaliptraResult<DiceInput> {
        // Create initial output
        let input = DiceInput {
            cdi: hand_off.fmc_cdi(),
            subj_priv_key: hand_off.fmc_priv_key(),
            auth_key_pair: Ecc384KeyPair {
                priv_key: KEY_ID_FMC_PRIV_KEY,
                pub_key: Ecc384PubKey::default(),
            },
            auth_sn: [0u8; 64],
            auth_key_id: [0u8; 20],
            uds_key: hand_off.fmc_cdi(),
        };

        Ok(input)
    }

    /// Extend current and journey PCRs
    ///
    /// # Arguments
    ///
    /// * `env` - FMC Environment
    /// * `hand_off` - HandOff
    pub fn extend_pcrs(env: &mut FmcEnv, hand_off: &HandOff) -> CaliptraResult<()> {
        extend_current_pcr(env, hand_off)?;
        extend_journey_pcr(env, hand_off)?;
        Ok(())
    }

    /// Permute Composite Device Identity (CDI) using Rt TCI and Image Manifest Digest
    /// The RT Alias CDI will overwrite the FMC Alias CDI in the KeyVault Slot
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `hand_off` - HandOff
    /// * `cdi` - Key Slot to store the generated CDI
    ///
    /// # Returns
    ///
    /// * `KeyId` - KeySlot containing the DICE CDI
    fn derive_cdi(env: &mut FmcEnv, hand_off: &HandOff, cdi: KeyId) -> CaliptraResult<KeyId> {
        // Get the HMAC Key from CDI
        let key = Hmac384Key::Key(KeyReadArgs::new(cdi));

        // Compose FMC TCI (1. RT TCI, 2. Image Manifest Digest)
        let mut tci = [0u8; 2 * SHA384_HASH_SIZE];
        let rt_tci = Tci::rt_tci(env, hand_off);
        let rt_tci: [u8; 48] = okref(&rt_tci)?.into();
        tci[0..SHA384_HASH_SIZE].copy_from_slice(&rt_tci);

        let image_manifest_digest: Result<_, CaliptraError> =
            Tci::image_manifest_digest(env, hand_off);
        let image_manifest_digest: [u8; 48] = okref(&image_manifest_digest)?.into();
        tci[SHA384_HASH_SIZE..2 * SHA384_HASH_SIZE].copy_from_slice(&image_manifest_digest);

        // Permute CDI from FMC TCI
        let data = Hmac384Data::Slice(&tci);
        let cdi = Crypto::hmac384_mac(env, key, data, cdi)?;
        Ok(cdi)
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
    fn derive_key_pair(
        env: &mut FmcEnv,
        cdi: KeyId,
        priv_key: KeyId,
    ) -> CaliptraResult<Ecc384KeyPair> {
        Crypto::ecc384_key_gen(env, cdi, priv_key)
    }

    /// Generate Local Device ID Certificate Signature
    ///
    /// # Arguments
    ///
    /// * `env`    - FMC Environment
    /// * `input`  - DICE Input
    /// * `output` - DICE Output
    fn generate_cert_sig(
        env: &mut FmcEnv,
        hand_off: &HandOff,
        input: &DiceInput,
        output: &DiceOutput,
        not_before: &[u8; RtAliasCertTbsParams::NOT_BEFORE_LEN],
        not_after: &[u8; RtAliasCertTbsParams::NOT_AFTER_LEN],
    ) -> CaliptraResult<()> {
        let auth_priv_key = input.auth_key_pair.priv_key;
        let auth_pub_key = &input.auth_key_pair.pub_key;
        let pub_key = &output.subj_key_pair.pub_key;

        let serial_number = &X509::cert_sn(env, pub_key)?;

        let rt_tci = Tci::rt_tci(env, hand_off);
        let rt_tci: [u8; 48] = okref(&rt_tci)?.into();

        let rt_svn = hand_off.rt_svn(env) as u8;

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

        // Sign the the `To Be Signed` portion
        cprintln!(
            "[art] Signing Cert with AUTHO
            RITY.KEYID = {}",
            auth_priv_key as u8
        );

        let sig = Crypto::ecdsa384_sign(env, auth_priv_key, tbs.tbs());
        let sig = okref(&sig)?;

        let _pub_x: [u8; 48] = (&pub_key.x).into();
        let _pub_y: [u8; 48] = (&pub_key.y).into();
        cprintln!("[art] PUB.X = {}", HexBytes(&_pub_x));
        cprintln!("[art] PUB.Y = {}", HexBytes(&_pub_y));

        let _sig_r: [u8; 48] = (&sig.r).into();
        let _sig_s: [u8; 48] = (&sig.s).into();
        cprintln!("[art] SIG.R = {}", HexBytes(&_sig_r));
        cprintln!("[art] SIG.S = {}", HexBytes(&_sig_s));

        // Verify the signature of the `To Be Signed` portion
        if !Crypto::ecdsa384_verify(env, auth_pub_key, tbs.tbs(), sig)? {
            return Err(CaliptraError::FMC_RT_ALIAS_CERT_VERIFY);
        }

        hand_off.set_rt_dice_signature(sig);

        //  Copy TBS to DCCM.
        Self::copy_tbs(tbs.tbs())?;

        Ok(())
    }

    fn copy_tbs(tbs: &[u8]) -> CaliptraResult<()> {
        let dst = unsafe {
            let ptr = &mut RTALIAS_TBS_ORG as *mut u8;
            core::slice::from_raw_parts_mut(ptr, tbs.len())
        };

        if tbs.len() <= RT_ALIAS_TBS_SIZE {
            dst[..tbs.len()].copy_from_slice(tbs);
        } else {
            return Err(CaliptraError::FMC_RT_ALIAS_TBS_SIZE_EXCEEDED);
        }

        Ok(())
    }
}
