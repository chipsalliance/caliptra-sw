/*++

Licensed under the Apache-2.0 license.

File Name:

   generator.rs

Abstract:

    Caliptra Authorization Manifest generator

--*/

use caliptra_image_gen::ImageGeneratorCrypto;
use zerocopy::IntoBytes;

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
                "Unsupported image metadata count, only {} entries supported.",
                AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT
            );
            return Err(anyhow::anyhow!("Error converting image metadata list"));
        }

        // Generate the Image Metadata List.
        let slice = config.image_metadata_list.as_slice();
        auth_manifest.image_metadata_col.image_metadata_list[..slice.len()].copy_from_slice(slice);

        auth_manifest.image_metadata_col.entry_count = config.image_metadata_list.len() as u32;

        // Generate the preamble.
        auth_manifest.preamble.marker = AUTH_MANIFEST_MARKER;
        auth_manifest.preamble.size = size_of::<AuthManifestPreamble>() as u32;
        auth_manifest.preamble.version = config.version;
        auth_manifest.preamble.svn = config.svn;
        auth_manifest.preamble.flags = config.flags.bits();

        // Populate the Vendor Ext field BEFORE signing so the vendor signature (which covers
        // vendor_signed_data_range = version..=vendor_pub_keys) authenticates it. Emit the
        // 0x0001 command-auth PK-hash record when provided.
        if let Some(pk_hash) = config.vendor_cmd_auth_pk_hash {
            let mut off = 0usize;
            // id (u16 LE)
            auth_manifest.preamble.vendor_ext.0[off..off + 2]
                .copy_from_slice(&VENDOR_EXT_ID_AUTH_PK_HASH.to_le_bytes());
            off += 2;
            // len (u16 LE)
            auth_manifest.preamble.vendor_ext.0[off..off + 2]
                .copy_from_slice(&(VENDOR_EXT_AUTH_PK_HASH_LEN as u16).to_le_bytes());
            off += 2;
            // value (48 B)
            auth_manifest.preamble.vendor_ext.0[off..off + VENDOR_EXT_AUTH_PK_HASH_LEN]
                .copy_from_slice(&pk_hash);
            off += VENDOR_EXT_AUTH_PK_HASH_LEN;
            auth_manifest.preamble.vendor_ext_size = off as u32;
        }

        // Sign the vendor manifest public keys.
        if let Some(vendor_man_config) = &config.vendor_man_key_info {
            auth_manifest.preamble.vendor_pub_keys.ecc_pub_key =
                vendor_man_config.pub_keys.ecc_pub_key;
            let pqc_pub_key = match config.pqc_key_type {
                FwVerificationPqcKeyType::LMS => vendor_man_config.pub_keys.lms_pub_key.as_bytes(),
                FwVerificationPqcKeyType::MLDSA => {
                    vendor_man_config.pub_keys.mldsa_pub_key.0.as_bytes()
                }
            };
            auth_manifest.preamble.vendor_pub_keys.pqc_pub_key.0[..pqc_pub_key.len()]
                .copy_from_slice(pqc_pub_key);
        }

        if let Some(vendor_fw_config) = &config.vendor_fw_key_info {
            let range = AuthManifestPreamble::vendor_signed_data_range();

            if let Some(priv_keys) = vendor_fw_config.priv_keys {
                let data = auth_manifest
                    .preamble
                    .as_bytes()
                    .get(range.start as usize..)
                    .ok_or_else(|| anyhow::anyhow!("Failed to get vendor signed data range start"))?
                    .get(..range.len())
                    .ok_or(anyhow::anyhow!(
                        "Failed to get vendor signed data range length"
                    ))?;

                let digest_sha384 = self.crypto.sha384_digest(data)?;
                let sig = self.crypto.ecdsa384_sign(
                    &digest_sha384,
                    &priv_keys.ecc_priv_key,
                    &vendor_fw_config.pub_keys.ecc_pub_key,
                )?;
                auth_manifest.preamble.vendor_pub_keys_signatures.ecc_sig = sig;

                if config.pqc_key_type == FwVerificationPqcKeyType::LMS {
                    let lms_sig = self
                        .crypto
                        .lms_sign(&digest_sha384, &priv_keys.lms_priv_key)?;
                    let sig = lms_sig.as_bytes();
                    auth_manifest.preamble.vendor_pub_keys_signatures.pqc_sig.0[..sig.len()]
                        .copy_from_slice(sig);
                } else {
                    let data = auth_manifest
                        .preamble
                        .as_bytes()
                        .get(range.start as usize..)
                        .ok_or_else(|| {
                            anyhow::anyhow!("Failed to get vendor signed data range start")
                        })?
                        .get(..range.len())
                        .ok_or(anyhow::anyhow!(
                            "Failed to get vendor signed data range length"
                        ))?;
                    let mldsa_sig = self.crypto.mldsa_sign(
                        data,
                        &priv_keys.mldsa_priv_key,
                        &vendor_fw_config.pub_keys.mldsa_pub_key,
                    )?;

                    let sig = mldsa_sig.as_bytes();
                    auth_manifest.preamble.vendor_pub_keys_signatures.pqc_sig.0[..sig.len()]
                        .copy_from_slice(sig);
                }
            }
        }

        // Sign the owner manifest public keys.
        if let (Some(owner_fw_config), Some(owner_man_config)) =
            (&config.owner_fw_key_info, &config.owner_man_key_info)
        {
            auth_manifest.preamble.owner_pub_keys.ecc_pub_key =
                owner_man_config.pub_keys.ecc_pub_key;
            let pqc_pub_key = match config.pqc_key_type {
                FwVerificationPqcKeyType::LMS => owner_man_config.pub_keys.lms_pub_key.as_bytes(),
                FwVerificationPqcKeyType::MLDSA => {
                    owner_man_config.pub_keys.mldsa_pub_key.0.as_bytes()
                }
            };
            auth_manifest.preamble.owner_pub_keys.pqc_pub_key.0[..pqc_pub_key.len()]
                .copy_from_slice(pqc_pub_key);

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

                if config.pqc_key_type == FwVerificationPqcKeyType::LMS {
                    let lms_sig = self
                        .crypto
                        .lms_sign(&digest, &owner_fw_priv_keys.lms_priv_key)?;
                    let sig = lms_sig.as_bytes();
                    auth_manifest.preamble.owner_pub_keys_signatures.pqc_sig.0[..sig.len()]
                        .copy_from_slice(sig);
                } else {
                    let mldsa_sig = self.crypto.mldsa_sign(
                        auth_manifest.preamble.owner_pub_keys.as_bytes(),
                        &owner_fw_priv_keys.mldsa_priv_key,
                        &owner_fw_config.pub_keys.mldsa_pub_key,
                    )?;
                    let sig = mldsa_sig.as_bytes();
                    auth_manifest.preamble.owner_pub_keys_signatures.pqc_sig.0[..sig.len()]
                        .copy_from_slice(sig);
                }
            }
        }

        // Hash the IMC.
        let digest = self
            .crypto
            .sha384_digest(auth_manifest.image_metadata_col.as_bytes())?;

        // Sign the IMC with the vendor manifest public keys if indicated in the flags.
        if config
            .flags
            .contains(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED)
        {
            if let Some(vendor_man_config) = &config.vendor_man_key_info {
                if let Some(vendor_man_priv_keys) = vendor_man_config.priv_keys {
                    let sig = self.crypto.ecdsa384_sign(
                        &digest,
                        &vendor_man_priv_keys.ecc_priv_key,
                        &vendor_man_config.pub_keys.ecc_pub_key,
                    )?;
                    auth_manifest
                        .preamble
                        .vendor_image_metdata_signatures
                        .ecc_sig = sig;

                    if config.pqc_key_type == FwVerificationPqcKeyType::LMS {
                        let lms_sig = self
                            .crypto
                            .lms_sign(&digest, &vendor_man_priv_keys.lms_priv_key)?;
                        let sig = lms_sig.as_bytes();
                        auth_manifest
                            .preamble
                            .vendor_image_metdata_signatures
                            .pqc_sig
                            .0[..sig.len()]
                            .copy_from_slice(sig);
                    } else {
                        let mldsa_sig = self.crypto.mldsa_sign(
                            auth_manifest.image_metadata_col.as_bytes(),
                            &vendor_man_priv_keys.mldsa_priv_key,
                            &vendor_man_config.pub_keys.mldsa_pub_key,
                        )?;
                        let sig = mldsa_sig.as_bytes();
                        auth_manifest
                            .preamble
                            .vendor_image_metdata_signatures
                            .pqc_sig
                            .0[..sig.len()]
                            .copy_from_slice(sig);
                    }
                }
            }
        }

        // Sign the IMC with the owner manifest public keys.
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

                if config.pqc_key_type == FwVerificationPqcKeyType::LMS {
                    let lms_sig = self
                        .crypto
                        .lms_sign(&digest, &owner_man_priv_keys.lms_priv_key)?;

                    let sig = lms_sig.as_bytes();
                    auth_manifest
                        .preamble
                        .owner_image_metdata_signatures
                        .pqc_sig
                        .0[..sig.len()]
                        .copy_from_slice(sig);
                } else {
                    let mldsa_sig = self.crypto.mldsa_sign(
                        auth_manifest.image_metadata_col.as_bytes(),
                        &owner_man_priv_keys.mldsa_priv_key,
                        &owner_man_config.pub_keys.mldsa_pub_key,
                    )?;
                    let sig = mldsa_sig.as_bytes();
                    auth_manifest
                        .preamble
                        .owner_image_metdata_signatures
                        .pqc_sig
                        .0[..sig.len()]
                        .copy_from_slice(sig);
                }
            }
        }

        Ok(auth_manifest)
    }
}

#[cfg(test)]
mod test {
    use crate::default_test_manifest::{
        default_test_soc_manifest, DEFAULT_MCU_FW, DEFAULT_TEST_VENDOR_CMD_AUTH_PK_HASH,
    };
    use caliptra_auth_man_types::AUTH_MANIFEST_VERSION_V2;
    use caliptra_image_crypto::RustCrypto;
    use caliptra_image_types::FwVerificationPqcKeyType;

    #[test]
    fn test_default_manifest_emits_v2_vendor_ext() {
        let manifest = default_test_soc_manifest(
            &DEFAULT_MCU_FW,
            FwVerificationPqcKeyType::MLDSA,
            1,
            RustCrypto::default(),
        );
        // Generator emitted a v2 manifest.
        assert_eq!(manifest.preamble.version, AUTH_MANIFEST_VERSION_V2);
        // The 0x0001 command-auth PK-hash round-trips out of the signed Vendor Ext.
        assert_eq!(
            manifest.preamble.vendor_ext_auth_pk_hash(),
            Some(DEFAULT_TEST_VENDOR_CMD_AUTH_PK_HASH)
        );
    }
}
