/*++

Licensed under the Apache-2.0 license.

File Name:

   generator.rs

Abstract:

    Caliptra Image generator

--*/
use anyhow::bail;
use caliptra_image_types::*;
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

        let ecc_key_idx = config.vendor_config.ecc_key_idx;

        // Create Header
        let toc_digest = self.toc_digest(&fmc_toc, &runtime_toc)?;
        let header = self.gen_header(ecc_key_idx, Self::DEFAULT_FLAGS, toc_digest)?;

        // Create Preamable
        let header_digest = self.header_digest(&header)?;
        let preamble = self.gen_preamble(config, ecc_key_idx, &header_digest)?;

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
        ecc_key_idx: u32,
        digest: &ImageDigest,
    ) -> anyhow::Result<ImagePreamble>
    where
        E: ImageGenratorExecutable,
    {
        let mut vendor_sigs = ImageSignatures::default();
        let mut owner_sigs = ImageSignatures::default();

        if let Some(priv_keys) = config.vendor_config.priv_keys {
            let sig = self.crypto.ecdsa384_sign(
                digest,
                &priv_keys.ecc_priv_keys[ecc_key_idx as usize],
                &config.vendor_config.pub_keys.ecc_pub_keys[ecc_key_idx as usize],
            )?;
            vendor_sigs.ecc_sig = sig;
        }

        if let Some(owner_config) = &config.owner_config {
            if let Some(priv_keys) = &owner_config.priv_keys {
                let sig = self.crypto.ecdsa384_sign(
                    digest,
                    &priv_keys.ecc_priv_key,
                    &owner_config.pub_keys.ecc_pub_key,
                )?;
                owner_sigs.ecc_sig = sig;
            }
        }

        let mut preamble = ImagePreamble {
            vendor_pub_keys: config.vendor_config.pub_keys,
            vendor_ecc_pub_key_idx: ecc_key_idx,
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
    fn gen_header(
        &self,
        ecc_key_idx: u32,
        flags: u32,
        digest: ImageDigest,
    ) -> anyhow::Result<ImageHeader> {
        let header = ImageHeader {
            vendor_ecc_pub_key_idx: ecc_key_idx,
            flags,
            toc_len: MAX_TOC_ENTRY_COUNT,
            toc_digest: digest,
            ..Default::default()
        };
        Ok(header)
    }

    /// Calculate header digest
    pub fn header_digest(&self, header: &ImageHeader) -> anyhow::Result<ImageDigest> {
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
