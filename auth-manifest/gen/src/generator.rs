/*++

Licensed under the Apache-2.0 license.

File Name:

   generator.rs

Abstract:

    Caliptra Authorization Manifest generator

--*/

use caliptra_image_gen::ImageGeneratorCrypto;
use zerocopy::AsBytes;

use crate::*;
use core::mem::size_of;

/// Authorization Manifest generator
pub struct AuthManifestGenerator<Crypto: ImageGeneratorCrypto> {
    crypto: Crypto,
}

impl<Crypto: ImageGeneratorCrypto> AuthManifestGenerator<Crypto> {
    /// Create an instance `AuthManifestGenerator`
    pub fn new(crypto: Crypto) -> Self {
        Self { crypto }
    }

    pub fn generate(
        &self,
        config: &AuthManifestGeneratorConfig,
    ) -> anyhow::Result<AuthorizationManifest> {
        let mut auth_manifest = AuthorizationManifest::default();

        if config.image_metadata_list.len() > AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT {
            eprintln!(
                "Encountered an error converting image_metadata_list, only 8 entries supported."
            );
            return Err(anyhow::anyhow!("Error converting image_metadata_list"));
        }

        // Generate the Image Metadata List.
        let slice = config.image_metadata_list.as_slice();
        auth_manifest.image_metadata_col.image_metadata_array[..slice.len()].copy_from_slice(slice);

        auth_manifest.image_metadata_col.header.entry_count =
            config.image_metadata_list.len() as u32;
        auth_manifest.image_metadata_col.header.revision = 0;

        // Generate the preamble.
        auth_manifest.preamble.marker = AUTH_MANIFEST_MARKER;
        auth_manifest.preamble.size = size_of::<AuthManifestPreamble>() as u32;

        // Sign the vendor manifest keys.
        auth_manifest.preamble.vendor_pub_keys = config.vendor_man_key_info.pub_keys;

        let digest = self
            .crypto
            .sha384_digest(&auth_manifest.preamble.vendor_pub_keys.as_bytes())?;

        if let Some(priv_keys) = config.vendor_fw_key_info.priv_keys {
            let sig = self.crypto.ecdsa384_sign(
                &digest,
                &priv_keys.ecc_priv_key,
                &config.vendor_fw_key_info.pub_keys.ecc_pub_key,
            )?;
            auth_manifest.preamble.vendor_pub_keys_signatures.ecc_sig = sig;

            let lms_sig = self.crypto.lms_sign(&digest, &priv_keys.lms_priv_key)?;
            auth_manifest.preamble.vendor_pub_keys_signatures.lms_sig = lms_sig;
        }

        // Sign the owner manifest keys.
        if let Some(owner_fw_config) = &config.owner_fw_key_info {
            if let Some(owner_man_config) = &config.owner_man_key_info {
                auth_manifest.preamble.owner_pub_keys = owner_man_config.pub_keys;

                let digest = self
                    .crypto
                    .sha384_digest(auth_manifest.preamble.owner_pub_keys.as_bytes())?;

                if let Some(owner_fw_priv_keys) = owner_fw_config.priv_keys {
                    let sig = self.crypto.ecdsa384_sign(
                        &digest,
                        &owner_fw_priv_keys.ecc_priv_key,
                        &owner_fw_config.pub_keys.ecc_pub_key,
                    )?;
                    auth_manifest.preamble.owner_pub_keys_signatures.ecc_sig = sig;
                    let lms_sig = self
                        .crypto
                        .lms_sign(&digest, &owner_fw_priv_keys.lms_priv_key)?;
                    auth_manifest.preamble.owner_pub_keys_signatures.lms_sig = lms_sig;
                }
            }
        }

        // Sign the Image Metadata List.
        let digest = self
            .crypto
            .sha384_digest(auth_manifest.image_metadata_col.as_bytes())?;

        // Sign with the vendor manifest public keys.
        if let Some(vendor_man_priv_keys) = config.vendor_man_key_info.priv_keys {
            let sig = self.crypto.ecdsa384_sign(
                &digest,
                &vendor_man_priv_keys.ecc_priv_key,
                &config.vendor_man_key_info.pub_keys.ecc_pub_key,
            )?;
            auth_manifest
                .preamble
                .vendor_image_metdata_signatures
                .ecc_sig = sig;

            let lms_sig = self
                .crypto
                .lms_sign(&digest, &vendor_man_priv_keys.lms_priv_key)?;
            auth_manifest
                .preamble
                .vendor_image_metdata_signatures
                .lms_sig = lms_sig;
        }

        // Sign with the owner manifest public keys.
        if let Some(owner_man_config) = &config.owner_man_key_info {
            if let Some(owner_man_priv_keys) = &owner_man_config.priv_keys {
                let sig = self.crypto.ecdsa384_sign(
                    &digest,
                    &owner_man_priv_keys.ecc_priv_key,
                    &owner_man_config.pub_keys.ecc_pub_key,
                )?;
                auth_manifest
                    .preamble
                    .owner_image_metdata_signatures
                    .ecc_sig = sig;

                let lms_sig = self
                    .crypto
                    .lms_sign(&digest, &owner_man_priv_keys.lms_priv_key)?;
                auth_manifest
                    .preamble
                    .owner_image_metdata_signatures
                    .lms_sig = lms_sig;
            }
        }

        Ok(auth_manifest)
    }
}
