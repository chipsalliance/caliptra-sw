/*++

Licensed under the Apache-2.0 license.

File Name:

   imc_generator.rs

Abstract:

    Caliptra Image Metadata Entry generator

--*/

use caliptra_image_gen::ImageGeneratorCrypto;
use core::mem::size_of;
use zerocopy::AsBytes;

use crate::*;

/// Image Metadata Collection generator
pub struct ImcGenerator<Crypto: ImageGeneratorCrypto> {
    crypto: Crypto,
}

impl<Crypto: ImageGeneratorCrypto> ImcGenerator<Crypto> {
    /// Create an instance `ImcGenerator`
    pub fn new(crypto: Crypto) -> Self {
        Self { crypto }
    }

    pub fn generate(
        &self,
        config: &ImcGeneratorConfig,
    ) -> anyhow::Result<AuthManifestImageMetadataWithSignatures> {
        let mut imc = AuthManifestImageMetadataWithSignatures::default();

        if config.image_metadata_list.len() > AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT {
            eprintln!(
                "Unsupported image metadata count, only {} entries supported.",
                AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT
            );
            return Err(anyhow::anyhow!("Error converting image metadata list"));
        }

        // Generate the Image Metadata List.
        let slice = config.image_metadata_list.as_slice();
        imc.image_metadata.image_metadata_list[..slice.len()].copy_from_slice(slice);

        imc.image_metadata.header.entry_count = config.image_metadata_list.len() as u32;
        imc.image_metadata.header.revision = config.revision;

        // Hash the IMC.
        let imc_size = size_of::<AuthManifestImageMetadataSetHeader>()
            + size_of::<AuthManifestImageMetadata>()
                * imc.image_metadata.header.entry_count as usize;
        let digest = self
            .crypto
            .sha384_digest(&imc.image_metadata.as_bytes()[..imc_size])?;

        // Sign the IMC with the vendor manifest private key(s) if indicated in the flags.
        if config
            .flags
            .contains(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED)
        {
            if let Some(vendor_priv_keys) = config.vendor_man_key_info.priv_keys {
                let sig = self.crypto.ecdsa384_sign(
                    &digest,
                    &vendor_priv_keys.ecc_priv_key,
                    &config.vendor_man_key_info.pub_keys.ecc_pub_key,
                )?;
                imc.vendor_signatures.ecc_sig = sig;

                let lms_sig = self
                    .crypto
                    .lms_sign(&digest, &vendor_priv_keys.lms_priv_key)?;
                imc.vendor_signatures.lms_sig = lms_sig;
            }
        }

        // Sign the image metadata set with the owner manifest private key(s).
        if let Some(owner_man_config) = &config.owner_man_key_info {
            if let Some(owner_man_priv_keys) = &owner_man_config.priv_keys {
                let sig = self.crypto.ecdsa384_sign(
                    &digest,
                    &owner_man_priv_keys.ecc_priv_key,
                    &owner_man_config.pub_keys.ecc_pub_key,
                )?;
                imc.owner_signatures.ecc_sig = sig;

                let lms_sig = self
                    .crypto
                    .lms_sign(&digest, &owner_man_priv_keys.lms_priv_key)?;
                imc.owner_signatures.lms_sig = lms_sig;
            }
        }

        Ok(imc)
    }
}
