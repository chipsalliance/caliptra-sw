// Licensed under the Apache-2.0 license

//! Signed malformed firmware images for testing image-format validation.

use caliptra_builder::ImageOptions;
use caliptra_drivers::CaliptraError;
use caliptra_image_crypto::OsslCrypto;
use caliptra_image_elf::ElfExecutable;
use caliptra_image_gen::{ImageGenerator, ImageGeneratorConfig};
use caliptra_image_types::{FwVerificationPqcKeyType, ImageBundle, ImageSignData};
use zerocopy::IntoBytes;

/// Corrupt each DMA-facing TOC field with all three non-word-aligned residues.
/// Re-sign the TOC and header so failures reach layout validation, rather than
/// stopping at authentication. The bundle itself remains word-aligned.
pub fn unaligned_images(image: &ImageBundle) -> Vec<(Vec<u8>, CaliptraError)> {
    let options = ImageOptions::default();
    let config = ImageGeneratorConfig {
        fmc: ElfExecutable::default(),
        runtime: ElfExecutable::default(),
        vendor_config: options.vendor_config,
        owner_config: options.owner_config,
        pqc_key_type: FwVerificationPqcKeyType::from_u8(image.manifest.pqc_key_type).unwrap(),
        fw_svn: image.manifest.header.svn,
    };
    let generator = ImageGenerator::new(OsslCrypto::default());
    (1..=3)
        .flat_map(|remainder| {
            [
                CaliptraError::IMAGE_VERIFIER_ERR_FMC_SIZE_UNALIGNED,
                CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_SIZE_UNALIGNED,
                CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_OFFSET_INVALID,
            ]
            .map(|error| {
                let mut manifest = image.manifest;
                match error {
                    CaliptraError::IMAGE_VERIFIER_ERR_FMC_SIZE_UNALIGNED => {
                        manifest.fmc.size -= remainder;
                        manifest.runtime.offset -= remainder;
                    }
                    CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_SIZE_UNALIGNED => {
                        manifest.runtime.size -= remainder
                    }
                    CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_OFFSET_INVALID => {
                        manifest.runtime.offset += remainder
                    }
                    _ => unreachable!(),
                }
                manifest.header.toc_digest = generator
                    .toc_digest(&manifest.fmc, &manifest.runtime)
                    .unwrap();
                let vendor_digest = generator
                    .vendor_header_digest_384(&manifest.header)
                    .unwrap();
                let vendor_bytes = generator.vendor_header_bytes(&manifest.header);
                let owner_digest = generator.owner_header_digest_384(&manifest.header).unwrap();
                let vendor_sign_data = ImageSignData {
                    digest_384: &vendor_digest,
                    mldsa_msg: Some(vendor_bytes),
                };
                let owner_sign_data = ImageSignData {
                    digest_384: &owner_digest,
                    mldsa_msg: Some(manifest.header.as_bytes()),
                };
                manifest.preamble = generator
                    .gen_preamble(
                        &config,
                        manifest.preamble.vendor_ecc_pub_key_idx,
                        manifest.preamble.vendor_pqc_pub_key_idx,
                        &vendor_sign_data,
                        &owner_sign_data,
                    )
                    .unwrap();
                let mut bytes = [manifest.as_bytes(), &image.fmc, &image.runtime].concat();
                // Keep shifted runtime sources in bounds to exercise gap validation.
                bytes.resize(bytes.len() + core::mem::size_of::<u32>(), 0);
                (bytes, error)
            })
        })
        .collect()
}
