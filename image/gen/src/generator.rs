/*++

Licensed under the Apache-2.0 license.

File Name:

   generator.rs

Abstract:

    Caliptra Image generator

--*/
use anyhow::bail;
use caliptra_image_types::*;
use memoffset::offset_of;
use zerocopy::IntoBytes;

use crate::*;

fn image_header_flags(vendor_config: &ImageGeneratorVendorConfig) -> u32 {
    let mut flags = 0;
    if vendor_config.pl0_pauser.is_some() {
        flags |= IMAGE_FLAGS_PL0_PAUSER;
    }
    if vendor_config.debug_image.unwrap_or(false) {
        flags |= IMAGE_FLAGS_DEBUG_IMAGE;
    }
    flags
}

/// Image generator
pub struct ImageGenerator<Crypto: ImageGeneratorCrypto> {
    crypto: Crypto,
}

impl<Crypto: ImageGeneratorCrypto> ImageGenerator<Crypto> {
    /// Create an instance `ImageGenerator`
    pub fn new(crypto: Crypto) -> Self {
        Self { crypto }
    }

    /// Generate image
    ///
    /// # Arguments
    ///
    /// * `config` - Image generator configuration
    ///
    /// # Returns
    ///
    /// * `ImageBundle` - Caliptra Image Bundle
    pub fn generate<E>(&self, config: &ImageGeneratorConfig<E>) -> anyhow::Result<ImageBundle>
    where
        E: ImageGeneratorExecutable,
    {
        let image_size = u64::from(IMAGE_MANIFEST_BYTE_SIZE as u32)
            + u64::from(config.fmc.size())
            + u64::from(config.runtime.size());
        if image_size > IMAGE_BYTE_SIZE as u64 {
            bail!(
                "Image larger than {IMAGE_BYTE_SIZE} bytes; image size:{} bytes",
                image_size
            );
        }

        // Create FMC TOC & Content
        let id = ImageTocEntryId::Fmc;
        let offset = IMAGE_MANIFEST_BYTE_SIZE as u32;
        let (fmc_toc, fmc) = self.gen_image(config, id, offset)?;

        // Create Runtime TOC & Content
        let id = ImageTocEntryId::Runtime;
        let offset = offset + fmc_toc.size;
        let (runtime_toc, runtime) = self.gen_image(config, id, offset)?;

        // Validate that load address ranges fit within the 32-bit address space.
        for (name, toc) in [("FMC", &fmc_toc), ("Runtime", &runtime_toc)] {
            if toc.size > 0
                && u64::from(toc.load_addr) + u64::from(toc.size) > u64::from(u32::MAX) + 1
            {
                bail!(
                    "{name}:[{:#x?}:{:#x?}] load address range overflows u32",
                    toc.load_addr,
                    u64::from(toc.load_addr) + u64::from(toc.size) - 1,
                );
            }
        }

        // Check if fmc and runtime image load address ranges don't overlap.
        if fmc_toc.overlaps(&runtime_toc) {
            bail!(
                "FMC:[{:#x?}:{:#x?}] and Runtime:[{:#x?}:{:#x?}] load address ranges overlap",
                fmc_toc.load_addr,
                u64::from(fmc_toc.load_addr) + u64::from(fmc_toc.size) - 1,
                runtime_toc.load_addr,
                u64::from(runtime_toc.load_addr) + u64::from(runtime_toc.size) - 1
            );
        }

        let ecc_key_idx = config.vendor_config.ecc_key_idx;
        let pqc_key_idx = config.vendor_config.pqc_key_idx;

        // Create Header
        let toc_digest = self.toc_digest(&fmc_toc, &runtime_toc)?;
        let header = self.gen_header(config, ecc_key_idx, pqc_key_idx, toc_digest)?;

        // Create Preamble
        let vendor_header_digest_384 = self.vendor_header_digest_384(&header)?;
        let mut vendor_header_signdata_holder = ImageSignData {
            digest_384: &vendor_header_digest_384,
            mldsa_msg: None,
        };

        let owner_header_digest_384 = self.owner_header_digest_384(&header)?;
        let mut owner_header_signdata_holder = ImageSignData {
            digest_384: &owner_header_digest_384,
            mldsa_msg: None,
        };

        // Update vendor_header_signdata_holder and owner_header_signdata_holder with data if MLDSA validation is required.
        if config.pqc_key_type == FwVerificationPqcKeyType::MLDSA {
            vendor_header_signdata_holder.mldsa_msg = Some(self.vendor_header_bytes(&header));
            owner_header_signdata_holder.mldsa_msg = Some(header.as_bytes());
        }

        let preamble = self.gen_preamble(
            config,
            ecc_key_idx,
            pqc_key_idx,
            &vendor_header_signdata_holder,
            &owner_header_signdata_holder,
        )?;

        // Create Manifest
        let manifest = ImageManifest {
            marker: MANIFEST_MARKER,
            size: core::mem::size_of::<ImageManifest>() as u32,
            pqc_key_type: config.pqc_key_type.into(),
            reserved: [0u8; 3],
            preamble,
            header,
            fmc: fmc_toc,
            runtime: runtime_toc,
        };

        // Create Image Bundle
        let image = ImageBundle {
            manifest,
            fmc,
            runtime,
        };

        Ok(image)
    }

    /// Create preamble
    pub fn gen_preamble<E>(
        &self,
        config: &ImageGeneratorConfig<E>,
        ecc_vendor_key_idx: u32,
        pqc_vendor_key_idx: u32,
        vendor_signdata_holder: &ImageSignData,
        owner_signdata_holder: &ImageSignData,
    ) -> anyhow::Result<ImagePreamble>
    where
        E: ImageGeneratorExecutable,
    {
        let mut vendor_sigs = ImageSignatures::default();
        let mut owner_sigs = ImageSignatures::default();

        // Add Vendor Header Signatures.
        if let Some(priv_keys) = config.vendor_config.priv_keys {
            let sig = self.crypto.ecdsa384_sign(
                vendor_signdata_holder.digest_384,
                &priv_keys.ecc_priv_keys[ecc_vendor_key_idx as usize],
                &config.vendor_config.pub_keys.ecc_pub_keys[ecc_vendor_key_idx as usize],
            )?;
            vendor_sigs.ecc_sig = sig;
            if config.pqc_key_type == FwVerificationPqcKeyType::LMS {
                let lms_sig = self.crypto.lms_sign(
                    vendor_signdata_holder.digest_384,
                    &priv_keys.lms_priv_keys[pqc_vendor_key_idx as usize],
                )?;
                let sig = lms_sig.as_bytes();
                vendor_sigs.pqc_sig.0[..sig.len()].copy_from_slice(sig);
            } else {
                let mldsa_sig = self.crypto.mldsa_sign(
                    vendor_signdata_holder.mldsa_msg.unwrap(),
                    &priv_keys.mldsa_priv_keys[pqc_vendor_key_idx as usize],
                    &config.vendor_config.pub_keys.mldsa_pub_keys[pqc_vendor_key_idx as usize],
                )?;

                let sig = mldsa_sig.as_bytes();
                vendor_sigs.pqc_sig.0[..sig.len()].copy_from_slice(sig);
            };
        }

        // Add Owner Header Signatures.
        if let Some(owner_config) = &config.owner_config {
            if let Some(priv_keys) = &owner_config.priv_keys {
                let sig = self.crypto.ecdsa384_sign(
                    owner_signdata_holder.digest_384,
                    &priv_keys.ecc_priv_key,
                    &owner_config.pub_keys.ecc_pub_key,
                )?;
                owner_sigs.ecc_sig = sig;
                if config.pqc_key_type == FwVerificationPqcKeyType::LMS {
                    let lms_sig = self
                        .crypto
                        .lms_sign(owner_signdata_holder.digest_384, &priv_keys.lms_priv_key)?;
                    let sig = lms_sig.as_bytes();
                    owner_sigs.pqc_sig.0[..sig.len()].copy_from_slice(sig);
                } else {
                    let mldsa_sig = self.crypto.mldsa_sign(
                        owner_signdata_holder.mldsa_msg.unwrap(),
                        &priv_keys.mldsa_priv_key,
                        &config.owner_config.as_ref().unwrap().pub_keys.mldsa_pub_key,
                    )?;
                    let sig = mldsa_sig.as_bytes();
                    owner_sigs.pqc_sig.0[..sig.len()].copy_from_slice(sig);
                };
            }
        }

        let mut vendor_pub_key_info = ImageVendorPubKeyInfo {
            ecc_key_descriptor: ImageEccKeyDescriptor {
                version: KEY_DESCRIPTOR_VERSION,
                reserved: 0,
                key_hash_count: config.vendor_config.ecc_key_count as u8,
                key_hash: ImageEccKeyHashes::default(),
            },
            pqc_key_descriptor: ImagePqcKeyDescriptor {
                version: KEY_DESCRIPTOR_VERSION,
                key_type: FwVerificationPqcKeyType::default() as u8,
                key_hash_count: 0,
                key_hash: ImagePqcKeyHashes::default(),
            },
        };

        // Hash the ECC vendor public keys.
        for i in 0..config.vendor_config.ecc_key_count {
            let ecc_pub_key = config.vendor_config.pub_keys.ecc_pub_keys[i as usize];
            let ecc_pub_key_digest = self.crypto.sha384_digest(ecc_pub_key.as_bytes())?;
            vendor_pub_key_info.ecc_key_descriptor.key_hash[i as usize] = ecc_pub_key_digest;
        }

        // Hash the LMS or MLDSA vendor public keys.
        if config.pqc_key_type == FwVerificationPqcKeyType::LMS {
            for i in 0..config.vendor_config.lms_key_count {
                vendor_pub_key_info.pqc_key_descriptor.key_hash[i as usize] =
                    self.crypto.sha384_digest(
                        config.vendor_config.pub_keys.lms_pub_keys[i as usize].as_bytes(),
                    )?;
            }
            vendor_pub_key_info.pqc_key_descriptor.key_type = FwVerificationPqcKeyType::LMS.into();
            vendor_pub_key_info.pqc_key_descriptor.key_hash_count =
                config.vendor_config.lms_key_count as u8;
        } else {
            for i in 0..config.vendor_config.mldsa_key_count {
                vendor_pub_key_info.pqc_key_descriptor.key_hash[i as usize] =
                    self.crypto.sha384_digest(
                        config.vendor_config.pub_keys.mldsa_pub_keys[i as usize].as_bytes(),
                    )?;
            }
            vendor_pub_key_info.pqc_key_descriptor.key_type =
                FwVerificationPqcKeyType::MLDSA.into();
            vendor_pub_key_info.pqc_key_descriptor.key_hash_count =
                config.vendor_config.mldsa_key_count as u8;
        }

        let mut preamble = ImagePreamble {
            vendor_pub_key_info,
            vendor_ecc_pub_key_idx: ecc_vendor_key_idx,
            vendor_ecc_active_pub_key: config.vendor_config.pub_keys.ecc_pub_keys
                [ecc_vendor_key_idx as usize],
            vendor_pqc_pub_key_idx: pqc_vendor_key_idx,
            vendor_sigs,
            owner_sigs,
            ..Default::default()
        };

        // Store the PQC (LMS or MLDSA) vendor public key in the Preamble.
        let pqc_pub_key = match config.pqc_key_type {
            FwVerificationPqcKeyType::LMS => {
                config.vendor_config.pub_keys.lms_pub_keys[pqc_vendor_key_idx as usize].as_bytes()
            }
            FwVerificationPqcKeyType::MLDSA => config.vendor_config.pub_keys.mldsa_pub_keys
                [pqc_vendor_key_idx as usize]
                .0
                .as_bytes(),
        };
        preamble.vendor_pqc_active_pub_key.0[..pqc_pub_key.len()].copy_from_slice(pqc_pub_key);

        if let Some(owner_config) = &config.owner_config {
            // Store the ECC owner public key in the Preamble.
            preamble.owner_pub_keys.ecc_pub_key = owner_config.pub_keys.ecc_pub_key;

            // Store the PQC (LMS or MLDSA) owner public key in the Preamble.
            let pqc_pub_key = match config.pqc_key_type {
                FwVerificationPqcKeyType::LMS => owner_config.pub_keys.lms_pub_key.as_bytes(),
                FwVerificationPqcKeyType::MLDSA => owner_config.pub_keys.mldsa_pub_key.0.as_bytes(),
            };
            preamble.owner_pub_keys.pqc_pub_key.0[..pqc_pub_key.len()].copy_from_slice(pqc_pub_key);
        }

        Ok(preamble)
    }

    /// Generate header
    fn gen_header<E>(
        &self,
        config: &ImageGeneratorConfig<E>,
        ecc_key_idx: u32,
        lms_key_idx: u32,
        digest: ImageDigest384,
    ) -> anyhow::Result<ImageHeader>
    where
        E: ImageGeneratorExecutable,
    {
        let mut header = ImageHeader {
            vendor_ecc_pub_key_idx: ecc_key_idx,
            vendor_pqc_pub_key_idx: lms_key_idx,
            flags: image_header_flags(&config.vendor_config),
            toc_len: MAX_TOC_ENTRY_COUNT,
            toc_digest: digest,
            svn: config.fw_svn,
            ..Default::default()
        };

        header.vendor_data.vendor_not_before = config.vendor_config.not_before;
        header.vendor_data.vendor_not_after = config.vendor_config.not_after;

        if let Some(pauser) = config.vendor_config.pl0_pauser {
            header.pl0_pauser = pauser;
        }

        if let Some(owner_config) = &config.owner_config {
            header.owner_data.owner_not_before = owner_config.not_before;
            header.owner_data.owner_not_after = owner_config.not_after;
        }

        Ok(header)
    }

    /// Calculate header digest for vendor.
    /// Vendor digest is calculated up to the `owner_data` field.
    pub fn vendor_header_digest_384(&self, header: &ImageHeader) -> anyhow::Result<ImageDigest384> {
        let offset = offset_of!(ImageHeader, owner_data);
        self.crypto
            .sha384_digest(header.as_bytes().get(..offset).unwrap())
    }

    /// Calculate header digest for owner.
    pub fn owner_header_digest_384(&self, header: &ImageHeader) -> anyhow::Result<ImageDigest384> {
        self.crypto.sha384_digest(header.as_bytes())
    }

    pub fn vendor_header_bytes<'a>(&self, header: &'a ImageHeader) -> &'a [u8] {
        let offset = offset_of!(ImageHeader, owner_data);
        header.as_bytes().get(..offset).unwrap()
    }

    /// Calculate owner public key descriptor digest.
    pub fn owner_pubkey_digest(&self, preamble: &ImagePreamble) -> anyhow::Result<ImageDigest384> {
        self.crypto
            .sha384_digest(preamble.owner_pub_keys.as_bytes())
    }

    /// Calculate vendor public key descriptor digest.
    pub fn vendor_pubkey_info_digest(
        &self,
        preamble: &ImagePreamble,
    ) -> anyhow::Result<ImageDigest384> {
        self.crypto
            .sha384_digest(preamble.vendor_pub_key_info.as_bytes())
    }

    /// Generate image
    fn gen_image<E>(
        &self,
        config: &ImageGeneratorConfig<E>,
        id: ImageTocEntryId,
        offset: u32,
    ) -> anyhow::Result<(ImageTocEntry, Vec<u8>)>
    where
        E: ImageGeneratorExecutable,
    {
        let image = match id {
            ImageTocEntryId::Fmc => &config.fmc,
            ImageTocEntryId::Runtime => &config.runtime,
        };

        let toc_type = ImageTocEntryType::Executable;
        let digest = self.crypto.sha384_digest(image.content())?;

        let load_addr = image.load_addr();
        let entry_point = image.entry_point();
        if entry_point != load_addr {
            let name = match id {
                ImageTocEntryId::Fmc => "FMC",
                ImageTocEntryId::Runtime => "Runtime",
            };
            bail!(
                "{name} entry_point {entry_point:#010x} != load_addr {load_addr:#010x}; \
                 firmware must be built with _fw_entry trampoline at load address"
            );
        }

        let entry = ImageTocEntry {
            id: id.into(),
            toc_type: toc_type.into(),
            revision: *image.rev(),
            version: image.version(),
            reserved: [0; 2],
            load_addr,
            entry_point,
            offset,
            size: image.content().len() as u32,
            digest,
        };

        Ok((entry, image.content().clone()))
    }

    /// Calculate TOC digest
    pub fn toc_digest(
        &self,
        fmc_toc: &ImageTocEntry,
        rt_toc: &ImageTocEntry,
    ) -> anyhow::Result<ImageDigest384> {
        let mut toc_content: Vec<u8> = Vec::new();
        toc_content.extend_from_slice(fmc_toc.as_bytes());
        toc_content.extend_from_slice(rt_toc.as_bytes());
        self.crypto.sha384_digest(&toc_content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optional_debug_image_header_flag() {
        for debug_image in [None, Some(false)] {
            let config = ImageGeneratorVendorConfig {
                debug_image,
                ..Default::default()
            };
            assert_eq!(image_header_flags(&config) & IMAGE_FLAGS_DEBUG_IMAGE, 0);
        }

        let config = ImageGeneratorVendorConfig {
            debug_image: Some(true),
            ..Default::default()
        };
        assert_eq!(
            image_header_flags(&config) & IMAGE_FLAGS_DEBUG_IMAGE,
            IMAGE_FLAGS_DEBUG_IMAGE
        );

        let config = ImageGeneratorVendorConfig {
            pl0_pauser: Some(1),
            ..Default::default()
        };
        assert_eq!(
            image_header_flags(&config) & IMAGE_FLAGS_PL0_PAUSER,
            IMAGE_FLAGS_PL0_PAUSER
        );
    }

    #[derive(Default)]
    struct DummyExec {
        load_addr: u32,
        content: Vec<u8>,
        rev: ImageRevision,
    }

    impl ImageGeneratorExecutable for DummyExec {
        fn version(&self) -> u32 {
            1
        }
        fn rev(&self) -> &ImageRevision {
            &self.rev
        }
        fn load_addr(&self) -> u32 {
            self.load_addr
        }
        fn entry_point(&self) -> u32 {
            self.load_addr
        }
        fn content(&self) -> &Vec<u8> {
            &self.content
        }
        fn size(&self) -> u32 {
            self.content.len() as u32
        }
    }

    struct DummyHasher;
    impl ImageGeneratorHasher for DummyHasher {
        type Output = [u32; SHA256_DIGEST_WORD_SIZE];
        fn update(&mut self, _data: &[u8]) {}
        fn finish(self) -> Self::Output {
            [0; SHA256_DIGEST_WORD_SIZE]
        }
    }

    struct DummyCrypto;
    impl ImageGeneratorCrypto for DummyCrypto {
        type Sha256Hasher = DummyHasher;
        fn sha256_start(&self) -> Self::Sha256Hasher {
            DummyHasher
        }
        fn sha384_digest(&self, _data: &[u8]) -> anyhow::Result<ImageDigest384> {
            Ok([0; SHA384_DIGEST_WORD_SIZE])
        }
        fn sha512_digest(&self, _data: &[u8]) -> anyhow::Result<ImageDigest512> {
            Ok([0; SHA512_DIGEST_WORD_SIZE])
        }
        fn ecdsa384_sign(
            &self,
            _digest: &ImageDigest384,
            _priv_key: &ImageEccPrivKey,
            _pub_key: &ImageEccPubKey,
        ) -> anyhow::Result<ImageEccSignature> {
            unreachable!()
        }
        fn lms_sign(
            &self,
            _digest: &ImageDigest384,
            _priv_key: &ImageLmsPrivKey,
        ) -> anyhow::Result<ImageLmsSignature> {
            unreachable!()
        }
        fn mldsa_sign(
            &self,
            _msg: &[u8],
            _priv_key: &ImageMldsaPrivKey,
            _pub_key: &ImageMldsaPubKey,
        ) -> anyhow::Result<ImageMldsaSignature> {
            unreachable!()
        }
        fn ecc_pub_key_from_pem_bytes(_key_bytes: &[u8]) -> anyhow::Result<ImageEccPubKey> {
            unreachable!()
        }
        fn ecc_priv_key_from_pem_bytes(_key_bytes: &[u8]) -> anyhow::Result<ImageEccPrivKey> {
            unreachable!()
        }
    }

    #[test]
    fn test_generate_rejects_overflowing_and_overlapping_load_ranges_without_panic() {
        let gen = ImageGenerator::new(DummyCrypto);

        // Overflowing FMC range overlapping Runtime must return Err without panicking.
        let overflowing_cfg = ImageGeneratorConfig {
            fmc: DummyExec {
                load_addr: u32::MAX - 4,
                content: vec![0u8; 16],
                rev: ImageRevision::default(),
            },
            runtime: DummyExec {
                load_addr: u32::MAX - 2,
                content: vec![0u8; 4],
                rev: ImageRevision::default(),
            },
            ..Default::default()
        };
        let err = gen.generate(&overflowing_cfg).unwrap_err();
        assert!(err.to_string().contains("overflows u32"));

        // Non-overflowing overlapping ranges must still return an overlap error.
        let overlapping_cfg = ImageGeneratorConfig {
            fmc: DummyExec {
                load_addr: 0x4000_0000,
                content: vec![0u8; 0x100],
                rev: ImageRevision::default(),
            },
            runtime: DummyExec {
                load_addr: 0x4000_0080,
                content: vec![0u8; 0x100],
                rev: ImageRevision::default(),
            },
            ..Default::default()
        };
        let err = gen.generate(&overlapping_cfg).unwrap_err();
        assert!(err.to_string().contains("overlap"));

        // Executable sizes whose u32 sum wraps must be rejected without panicking.
        #[derive(Default)]
        struct HugeSizeExec {
            size: u32,
            content: Vec<u8>,
            rev: ImageRevision,
        }
        impl ImageGeneratorExecutable for HugeSizeExec {
            fn version(&self) -> u32 {
                1
            }
            fn rev(&self) -> &ImageRevision {
                &self.rev
            }
            fn load_addr(&self) -> u32 {
                0x4000_0000
            }
            fn entry_point(&self) -> u32 {
                0x4000_0000
            }
            fn content(&self) -> &Vec<u8> {
                &self.content
            }
            fn size(&self) -> u32 {
                self.size
            }
        }
        let huge_cfg = ImageGeneratorConfig {
            fmc: HugeSizeExec {
                size: u32::MAX,
                ..Default::default()
            },
            runtime: HugeSizeExec {
                size: 16,
                ..Default::default()
            },
            ..Default::default()
        };
        let err = gen.generate(&huge_cfg).unwrap_err();
        assert!(err.to_string().contains("Image larger than"));
    }
}
