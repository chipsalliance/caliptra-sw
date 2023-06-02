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
use caliptra_drivers::{
    okref, CaliptraError, CaliptraResult, Ecc384PubKey, Hmac384Data, Hmac384Key, KeyId, KeyReadArgs,
};
const SHA384_HASH_SIZE: usize = 48;

#[derive(Default)]
pub struct RtAliasLayer {}

impl DiceLayer for RtAliasLayer {
    /// Perform derivations for the DICE layer
    fn derive(
        env: &mut FmcEnv,
        hand_off: &HandOff,
        input: &DiceInput,
    ) -> CaliptraResult<DiceOutput> {
        // Derive CDI
        let cdi = *okref(&Self::derive_cdi(env, hand_off, input.cdi))?;

        // Derive DICE Key Pair from CDI
        let key_pair = Self::derive_key_pair(env, cdi, input.subj_priv_key)?;

        // Generate the Subject Serial Number and Subject Key Identifier.
        //
        // This information will be used by next DICE Layer while generating
        // certificates
        let subj_sn = X509::subj_sn(env, &key_pair.pub_key)?;
        let subj_key_id = X509::subj_key_id(env, &key_pair.pub_key)?;

        let output = input.to_output(key_pair, subj_sn, subj_key_id);

        // Generate Local Device ID Certificate
        Self::generate_cert_sig(env, input, &output)?;
        Ok(output)
    }
}

impl RtAliasLayer {
    #[inline(never)]
    pub fn run(env: &mut FmcEnv, hand_off: &HandOff) -> CaliptraResult<()> {
        cprintln!("[fmc] Extend RT PCRs");
        Self::extend_pcrs(env, hand_off)?;

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
        _env: &FmcEnv,
        _input: &DiceInput,
        _output: &DiceOutput,
    ) -> CaliptraResult<()> {
        // TODO: This will be implemented in a different PR. Issue #84
        Ok(())
    }
}
