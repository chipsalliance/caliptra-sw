/*++

Licensed under the Apache-2.0 license.

File Name:

    hmac.rs

Abstract:

    File contains cryptography helper functions related to HMAC.

--*/

use caliptra_cfi_derive::{cfi_impl_fn, cfi_mod_fn};
use caliptra_cfi_lib::{cfi_assert, cfi_assert_eq, cfi_launder};
use caliptra_common::{crypto::Ecc384KeyPair, keyids::KEY_ID_TMP};
use caliptra_drivers::{
    hmac384_kdf, Array4x12, Ecc384PrivKeyOut, Ecc384PubKey, Hmac384Data, Hmac384Key, Hmac384Tag,
    KeyId, KeyReadArgs, KeyUsage, KeyWriteArgs,
};
use caliptra_error::CaliptraResult;
use zerocopy::AsBytes;
use zeroize::Zeroize;

use crate::Drivers;

/// Generate an ECC key pair
///
/// # Arguments
///
/// * `drivers` - Drivers
/// * `input` - KeyId containing the input data
/// * `label` - Label for KDF
/// * `priv_key` - KeyId which the private key should be written to
///
/// # Returns
///
/// * `Ecc384KeyPair` - Generated key pair
#[cfg_attr(not(feature = "no-cfi"), cfi_mod_fn)]
fn ecc384_key_gen(
    drivers: &mut Drivers,
    input: KeyId,
    label: &[u8],
    priv_key: KeyId,
) -> CaliptraResult<Ecc384KeyPair> {
    hmac384_kdf(
        &mut drivers.hmac384,
        KeyReadArgs::new(input).into(),
        label,
        None,
        &mut drivers.trng,
        KeyWriteArgs::new(
            KEY_ID_TMP,
            KeyUsage::default()
                .set_hmac_key_en()
                .set_ecc_key_gen_seed_en(),
        )
        .into(),
    )?;

    let pub_key = drivers.ecc384.key_pair(
        &KeyReadArgs::new(KEY_ID_TMP).into(),
        &Array4x12::default(),
        &mut drivers.trng,
        KeyWriteArgs::new(priv_key, KeyUsage::default().set_ecc_private_key_en()).into(),
    );

    if KEY_ID_TMP != priv_key {
        drivers.key_vault.erase_key(KEY_ID_TMP)?;
    } else {
        cfi_assert_eq(KEY_ID_TMP, priv_key);
    }

    Ok(Ecc384KeyPair {
        priv_key,
        pub_key: pub_key?,
    })
}

pub enum Hmac {}

impl Hmac {
    /// "Hash" the data in the provided KV slot by HMACing it with an empty slice.
    /// This mechanism is necessary because the hardware does not directly support
    /// hashing data in KV slots.
    ///
    /// # Arguments
    ///
    /// * `drivers` - Drivers
    /// * `input` - KeyId containing the input data
    /// * `output` - KeyId which the output hash should be written to
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn hmac384_hash(drivers: &mut Drivers, input: KeyId, output: KeyId) -> CaliptraResult<()> {
        drivers.hmac384.hmac(
            &KeyReadArgs::new(input).into(),
            &Hmac384Data::Slice(&[]),
            &mut drivers.trng,
            KeyWriteArgs::new(
                output,
                KeyUsage::default()
                    .set_hmac_key_en()
                    .set_ecc_key_gen_seed_en(),
            )
            .into(),
        )
    }

    /// Perform an "HMAC" with a key from KV by first using it to derive an
    /// ECC keypair, then hashing the public key coordinates into an HMAC key.
    /// This roundabout mechanism is necessary because the hardware does not
    /// directly support exposing an HMAC computed with key material from KV.
    /// Note that the derived public key is considered secret.
    ///
    /// # Arguments
    ///
    /// * `drivers` - Drivers
    /// * `input` - KeyId containing the input data
    /// * `label` - Used to diversify the key material before it is used to compute an ECC keypair
    /// * `data` - Data provided to HMAC
    ///
    /// # Returns
    ///
    /// * `Array4x12` - Computed HMAC result
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn ecc384_hmac(
        drivers: &mut Drivers,
        input: KeyId,
        label: &[u8],
        data: &[u8],
    ) -> CaliptraResult<Array4x12> {
        let keypair_result = ecc384_key_gen(drivers, input, label, KEY_ID_TMP);
        if cfi_launder(keypair_result.is_ok()) {
            cfi_assert!(keypair_result.is_ok());
        } else {
            cfi_assert!(keypair_result.is_err());
        }
        let mut keypair = keypair_result?;

        let mut pubkey_digest = Array4x12::default();

        // Done in a closure to ensure state is always cleaned up.
        let hmac_result = || -> CaliptraResult<Array4x12> {
            let mut hasher = drivers.sha384.digest_init()?;

            hasher.update(keypair.pub_key.x.as_bytes())?;
            hasher.update(keypair.pub_key.y.as_bytes())?;
            hasher.finalize(&mut pubkey_digest)?;

            let mut hmac_output = Array4x12::default();
            drivers.hmac384.hmac(
                &Hmac384Key::Array4x12(&pubkey_digest),
                &Hmac384Data::Slice(data),
                &mut drivers.trng,
                Hmac384Tag::Array4x12(&mut hmac_output),
            )?;

            Ok(hmac_output)
        }();

        // Clean up state.
        unsafe { caliptra_drivers::Sha384::zeroize() }
        pubkey_digest.zeroize();
        keypair.pub_key.zeroize();
        drivers.key_vault.erase_key(keypair.priv_key)?;

        hmac_result
    }
}
