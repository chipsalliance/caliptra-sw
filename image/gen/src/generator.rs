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
use zerocopy::AsBytes;

use crate::*;

/// Image generator
pub struct ImageGenerator<Crypto: ImageGeneratorCrypto> {
    crypto: Crypto,
}

impl<Crypto: ImageGeneratorCrypto> ImageGenerator<Crypto> {
    const DEFAULT_FLAGS: u32 = 0;

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
        E: ImageGenratorExecutable,
    {
        if IMAGE_MANIFEST_BYTE_SIZE as u32 + config.fmc.size() + config.runtime.size()
            > IMAGE_BYTE_SIZE as u32
        {
            bail!("Image larger than {IMAGE_BYTE_SIZE} bytes");
        }

        // Create FMC TOC & Content
        let id = ImageTocEntryId::Fmc;
        let offset = IMAGE_MANIFEST_BYTE_SIZE as u32;
        let (fmc_toc, fmc) = self.gen_image(&config.fmc, id, offset)?;

        // Create Runtime TOC & Content
        let id = ImageTocEntryId::Runtime;
        let offset = offset + fmc_toc.size;
        let (runtime_toc, runtime) = self.gen_image(&config.runtime, id, offset)?;

        // Check if fmc and runtime image load address ranges don't overlap.
        if fmc_toc.overlaps(&runtime_toc) {
            bail!(
                "FMC:[{0}:{1}] and Runtime:[{2}:{3}] load address ranges overlap",
                fmc_toc.load_addr,
                fmc_toc.load_addr + fmc_toc.size - 1,
                runtime_toc.load_addr,
                runtime_toc.load_addr + runtime_toc.size - 1
            );
        }

        let ecc_key_idx = config.vendor_config.ecc_key_idx;
        let lms_key_idx = config.vendor_config.lms_key_idx;

        // Create Header
        let toc_digest = self.toc_digest(&fmc_toc, &runtime_toc)?;
        let header = self.gen_header(
            config,
            ecc_key_idx,
            lms_key_idx,
            Self::DEFAULT_FLAGS,
            toc_digest,
        )?;

        // Create Preamable
        let header_digest_vendor = self.header_digest_vendor(&header)?;
        let header_digest_owner = self.header_digest_owner(&header)?;
        let preamble = self.gen_preamble(
            config,
            ecc_key_idx,
            lms_key_idx,
            &header_digest_vendor,
            &header_digest_owner,
        )?;

        // Create Manifest
        let manifest = ImageManifest {
            marker: MANIFEST_MARKER,
            size: core::mem::size_of::<ImageManifest>() as u32,
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

    /// Create preable
    pub fn gen_preamble<E>(
        &self,
        config: &ImageGeneratorConfig<E>,
        ecc_vendor_key_idx: u32,
        lms_vendor_key_idx: u32,
        digest_vendor: &ImageDigest,
        digest_owner: &ImageDigest,
    ) -> anyhow::Result<ImagePreamble>
    where
        E: ImageGenratorExecutable,
    {
        let mut vendor_sigs = ImageSignatures::default();
        let mut owner_sigs = ImageSignatures::default();

        if let Some(priv_keys) = config.vendor_config.priv_keys {
            let sig = self.crypto.ecdsa384_sign(
                digest_vendor,
                &priv_keys.ecc_priv_keys[ecc_vendor_key_idx as usize],
                &config.vendor_config.pub_keys.ecc_pub_keys[ecc_vendor_key_idx as usize],
            )?;
            vendor_sigs.ecc_sig = sig;
            let lms_sig = self.crypto.lms_sign(
                digest_vendor,
                &priv_keys.lms_priv_keys[lms_vendor_key_idx as usize],
            )?;
            vendor_sigs.lms_sig = lms_sig;
        }

        if let Some(owner_config) = &config.owner_config {
            if let Some(priv_keys) = &owner_config.priv_keys {
                let sig = self.crypto.ecdsa384_sign(
                    digest_owner,
                    &priv_keys.ecc_priv_key,
                    &owner_config.pub_keys.ecc_pub_key,
                )?;
                owner_sigs.ecc_sig = sig;
                let lms_sig = self
                    .crypto
                    .lms_sign(digest_owner, &priv_keys.lms_priv_key)?;
                owner_sigs.lms_sig = lms_sig;
            }
        }

        let mut preamble = ImagePreamble {
            vendor_pub_keys: config.vendor_config.pub_keys,
            vendor_ecc_pub_key_idx: ecc_vendor_key_idx,
            vendor_lms_pub_key_idx: lms_vendor_key_idx,
            vendor_sigs,
            owner_sigs,
            ..Default::default()
        };

        if let Some(owner_config) = &config.owner_config {
            preamble.owner_pub_keys = owner_config.pub_keys;
        }

        Ok(preamble)
    }

    /// Generate header
    fn gen_header<E>(
        &self,
        config: &ImageGeneratorConfig<E>,
        ecc_key_idx: u32,
        lms_key_idx: u32,
        flags: u32,
        digest: ImageDigest,
    ) -> anyhow::Result<ImageHeader>
    where
        E: ImageGenratorExecutable,
    {
        let mut header = ImageHeader {
            vendor_ecc_pub_key_idx: ecc_key_idx,
            vendor_lms_pub_key_idx: lms_key_idx,
            flags,
            toc_len: MAX_TOC_ENTRY_COUNT,
            toc_digest: digest,
            ..Default::default()
        };

        header.vendor_data.vendor_not_before = config.vendor_config.not_before;
        header.vendor_data.vendor_not_after = config.vendor_config.not_after;

        if let Some(owner_config) = &config.owner_config {
            header.owner_data.owner_not_before = owner_config.not_before;
            header.owner_data.owner_not_after = owner_config.not_after;
        }

        Ok(header)
    }

    /// Calculate header digest for vendor.
    /// Vendor digest is calculated upto the `owner_data` field.
    pub fn header_digest_vendor(&self, header: &ImageHeader) -> anyhow::Result<ImageDigest> {
        let offset = offset_of!(ImageHeader, owner_data);
        self.crypto
            .sha384_digest(header.as_bytes().get(..offset).unwrap())
    }

    /// Calculate header digest for owner.
    pub fn header_digest_owner(&self, header: &ImageHeader) -> anyhow::Result<ImageDigest> {
        self.crypto.sha384_digest(header.as_bytes())
    }

    /// Calculate owner public key(s) digest
    pub fn owner_pubkey_digest(&self, preamble: &ImagePreamble) -> anyhow::Result<ImageDigest> {
        self.crypto
            .sha384_digest(preamble.owner_pub_keys.as_bytes())
    }

    /// Calculate vendor public key(s) digest
    pub fn vendor_pubkey_digest(&self, preamble: &ImagePreamble) -> anyhow::Result<ImageDigest> {
        self.crypto
            .sha384_digest(preamble.vendor_pub_keys.as_bytes())
    }

    /// Generate image
    fn gen_image<E>(
        &self,
        image: &E,
        id: ImageTocEntryId,
        offset: u32,
    ) -> anyhow::Result<(ImageTocEntry, Vec<u8>)>
    where
        E: ImageGenratorExecutable,
    {
        let r#type = ImageTocEntryType::Executable;
        let digest = self.crypto.sha384_digest(image.content())?;

        let entry = ImageTocEntry {
            id: id.into(),
            r#type: r#type.into(),
            revision: *image.rev(),
            svn: image.svn(),
            min_svn: image.min_svn(),
            load_addr: image.load_addr(),
            entry_point: image.entry_point(),
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
    ) -> anyhow::Result<ImageDigest> {
        let mut toc_content: Vec<u8> = Vec::new();
        toc_content.extend_from_slice(fmc_toc.as_bytes());
        toc_content.extend_from_slice(rt_toc.as_bytes());
        self.crypto.sha384_digest(&toc_content)
    }
}
