/*++

Licensed under the Apache-2.0 license.

File Name:

    hmac.rs

Abstract:

    File contains cryptography helper functions related to HMAC.

--*/

use caliptra_cfi_derive_git::{cfi_impl_fn, cfi_mod_fn};
use caliptra_cfi_lib_git::{cfi_assert, cfi_assert_eq, cfi_launder};
use caliptra_common::{
    crypto::{Crypto, Ecc384KeyPair},
    keyids::KEY_ID_TMP,
};
use caliptra_drivers::{
    hmac384_kdf, Array4x12, Ecc384PrivKeyOut, Ecc384PubKey, Hmac384Data, Hmac384Key, Hmac384Tag,
    KeyId, KeyReadArgs, KeyUsage, KeyWriteArgs,
};
use caliptra_error::CaliptraResult;
use zerocopy::AsBytes;
use zeroize::Zeroize;

use crate::Drivers;

pub enum Hmac {}

impl Hmac {
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
        let keypair_result = Crypto::ecc384_key_gen(
            &mut drivers.hmac384,
            &mut drivers.ecc384,
            &mut drivers.trng,
            &mut drivers.key_vault,
            input,
            label,
            KEY_ID_TMP,
        );
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
