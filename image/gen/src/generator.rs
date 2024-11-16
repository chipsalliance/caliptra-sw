/*++

Licensed under the Apache-2.0 license.

File Name:

   generator.rs

Abstract:

    Caliptra Image generator

--*/
use anyhow::bail;
use caliptra_image_types::*;
use fips204::ml_dsa_87::{PrivateKey, PublicKey, SIG_LEN};
use fips204::traits::{SerDes, Signer};
use memoffset::offset_of;
use rand::rngs::StdRng;
use rand::SeedableRng;
use zerocopy::AsBytes;

use crate::*;

/// Image generator
pub struct ImageGenerator<Crypto: ImageGeneratorCrypto> {
    crypto: Crypto,
}

impl<Crypto: ImageGeneratorCrypto> ImageGenerator<Crypto> {
    const DEFAULT_FLAGS: u32 = 0;
    const PL0_PAUSER_FLAG: u32 = (1 << 0);

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
        let image_size =
            IMAGE_MANIFEST_BYTE_SIZE as u32 + config.fmc.size() + config.runtime.size();
        if image_size > IMAGE_BYTE_SIZE as u32 {
            bail!(
                "Image larger than {IMAGE_BYTE_SIZE} bytes; image size:{} bytes",
                image_size
            );
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
                "FMC:[{:#x?}:{:#x?}] and Runtime:[{:#x?}:{:#x?}] load address ranges overlap",
                fmc_toc.load_addr,
                fmc_toc.load_addr + fmc_toc.size - 1,
                runtime_toc.load_addr,
                runtime_toc.load_addr + runtime_toc.size - 1
            );
        }

        let ecc_key_idx = config.vendor_config.ecc_key_idx;
        let pqc_key_idx = config.vendor_config.pqc_key_idx;

        // Create Header
        let toc_digest = self.toc_digest(&fmc_toc, &runtime_toc)?;
        let header = self.gen_header(config, ecc_key_idx, pqc_key_idx, toc_digest)?;

        // Create Preamble
        let header_digest_vendor = self.header_digest_vendor(&header)?;
        let header_digest_owner = self.header_digest_owner(&header)?;
        let preamble = self.gen_preamble(
            config,
            ecc_key_idx,
            pqc_key_idx,
            &header_digest_vendor,
            &header_digest_owner,
        )?;

        // Create Manifest
        let manifest = ImageManifest {
            marker: MANIFEST_MARKER,
            size: core::mem::size_of::<ImageManifest>() as u32,
            fw_image_type: config.fw_image_type.into(),
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

    fn mldsa_sign(
        &self,
        digest: &ImageDigest,
        priv_key: &ImageMldsaPrivKey,
        pub_key: &ImageMldsaPubKey,
    ) -> anyhow::Result<ImageMldsaSignature> {
        /// Convert the slice to hardware format
        fn to_hw_format<const NUM_WORDS: usize>(value: &[u8]) -> [u32; NUM_WORDS] {
            let mut result = [0u32; NUM_WORDS];
            for i in 0..result.len() {
                result[i] = u32::from_be_bytes(value[i * 4..][..4].try_into().unwrap())
            }
            result
        }

        let mut rng = StdRng::from_seed([0u8; 32]);

        let priv_key = {
            let key_bytes: [u8; MLDSA87_PRIV_KEY_BYTE_SIZE] =
                priv_key.0.as_bytes().try_into().unwrap();
            PrivateKey::try_from_bytes(key_bytes).unwrap()
        };

        let pub_key = {
            let key_bytes: [u8; MLDSA87_PUB_KEY_BYTE_SIZE] =
                pub_key.0.as_bytes().try_into().unwrap();
            PublicKey::try_from_bytes(key_bytes).unwrap()
        };

        let signature = priv_key
            .try_sign_with_rng(&mut rng, digest.as_bytes(), &[])
            .unwrap();

        let signature_extended = {
            let mut sig = [0; SIG_LEN + 1];
            sig[..SIG_LEN].copy_from_slice(&signature);
            sig
        };
        let sig: ImageMldsaSignature;
        sig.0[..signature_extended.len()].copy_from_slice(&signature_extended);
        Ok(sig)
    }

    /// Create preamble
    pub fn gen_preamble<E>(
        &self,
        config: &ImageGeneratorConfig<E>,
        ecc_vendor_key_idx: u32,
        pqc_vendor_key_idx: u32,
        digest_vendor: &ImageDigest,
        digest_owner: &ImageDigest,
    ) -> anyhow::Result<ImagePreamble>
    where
        E: ImageGeneratorExecutable,
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
            let pqc_sig = if config.fw_image_type == FwImageType::EccLms {
                let lms_sig = self.crypto.lms_sign(
                    digest_vendor,
                    &priv_keys.lms_priv_keys[pqc_vendor_key_idx as usize],
                )?;
                lms_sig.as_bytes()
            } else {
                let mldsa_sig = self.mldsa_sign(
                    digest_vendor,
                    &priv_keys.mldsa_priv_keys[pqc_vendor_key_idx as usize],
                )?;
                mldsa_sig.as_bytes()
            };

            vendor_sigs.pqc_sig[..pqc_sig.len()].copy_from_slice(pqc_sig);
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

        let mut vendor_pub_key_info = ImageVendorPubKeyInfo {
            ecc_key_descriptor: ImageEccKeyDescriptor {
                version: KEY_DESCRIPTOR_VERSION,
                intent: Intent::Vendor.into(),
                reserved: 0,
                key_hash_count: config.vendor_config.ecc_key_count as u8,
                key_hash: ImageEccKeyHashes::default(),
            },
            pqc_key_descriptor: ImagePqcKeyDescriptor {
                version: KEY_DESCRIPTOR_VERSION,
                intent: Intent::Vendor.into(),
                key_type: KeyType::LMS.into(),
                key_hash_count: config.vendor_config.lms_key_count as u8,
                key_hash: ImagePqcKeyHashes::default(),
            },
        };

        // Hash the ECC and LMS vendor public keys.
        for i in 0..config.vendor_config.ecc_key_count {
            let ecc_pub_key = config.vendor_config.pub_keys.ecc_pub_keys[i as usize];
            let ecc_pub_key_digest = self.crypto.sha384_digest(ecc_pub_key.as_bytes())?;
            vendor_pub_key_info.ecc_key_descriptor.key_hash[i as usize] = ecc_pub_key_digest;
        }
        for i in 0..config.vendor_config.lms_key_count {
            let lms_pub_key = config.vendor_config.pub_keys.lms_pub_keys[i as usize];
            let lms_pub_key_digest = self.crypto.sha384_digest(lms_pub_key.as_bytes())?;
            vendor_pub_key_info.pqc_key_descriptor.key_hash[i as usize] = lms_pub_key_digest;
        }

        let mut preamble = ImagePreamble {
            vendor_pub_key_info,
            vendor_ecc_pub_key_idx: ecc_vendor_key_idx,
            vendor_ecc_active_pub_key: config.vendor_config.pub_keys.ecc_pub_keys
                [ecc_vendor_key_idx as usize],
            vendor_lms_pub_key_idx: pqc_vendor_key_idx,
            vendor_lms_active_pub_key: config.vendor_config.pub_keys.lms_pub_keys
                [pqc_vendor_key_idx as usize],
            vendor_sigs,
            owner_sigs,
            ..Default::default()
        };

        if let Some(owner_config) = &config.owner_config {
            let mut owner_pub_key_info = ImageOwnerPubKeyInfo {
                ecc_key_descriptor: ImageEccKeyDescriptor {
                    version: KEY_DESCRIPTOR_VERSION,
                    intent: Intent::Owner.into(),
                    reserved: 0,
                    key_hash_count: 1,
                    key_hash: ImageEccKeyHashes::default(),
                },
                pqc_key_descriptor: ImagePqcKeyDescriptor {
                    version: KEY_DESCRIPTOR_VERSION,
                    intent: Intent::Owner.into(),
                    key_type: KeyType::LMS.into(),
                    key_hash_count: 1,
                    key_hash: ImagePqcKeyHashes::default(),
                },
            };

            // Hash the ECC owner public key.
            let ecc_pub_key = owner_config.pub_keys.ecc_pub_key;
            let ecc_pub_key_digest = self.crypto.sha384_digest(ecc_pub_key.as_bytes())?;
            owner_pub_key_info.ecc_key_descriptor.key_hash[0_usize] = ecc_pub_key_digest;

            // Store the ECC public key in the Preamble.
            preamble.owner_pub_keys.ecc_pub_key = owner_config.pub_keys.ecc_pub_key;

            // Hash the LMS or MLDSA owner public key.
            let pqc_pub_key: &[u8];
            if config.fw_image_type == FwImageType::EccLms {
                pqc_pub_key = owner_config.pub_keys.lms_pub_key.as_bytes();
            } else {
                pqc_pub_key = owner_config.pub_keys.mldsa_pub_key.as_bytes();
            }
            let pqc_pub_key_digest = self.crypto.sha384_digest(pqc_pub_key)?;
            owner_pub_key_info.pqc_key_descriptor.key_hash[0_usize] = pqc_pub_key_digest;

            // Store the public key hashes
            preamble.owner_pub_key_info = owner_pub_key_info;

            // Store the LMS or MLDSA public key in the Preamble.
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
        digest: ImageDigest,
    ) -> anyhow::Result<ImageHeader>
    where
        E: ImageGeneratorExecutable,
    {
        let mut header = ImageHeader {
            vendor_ecc_pub_key_idx: ecc_key_idx,
            vendor_lms_pub_key_idx: lms_key_idx,
            flags: Self::DEFAULT_FLAGS,
            toc_len: MAX_TOC_ENTRY_COUNT,
            toc_digest: digest,
            ..Default::default()
        };

        header.vendor_data.vendor_not_before = config.vendor_config.not_before;
        header.vendor_data.vendor_not_after = config.vendor_config.not_after;

        if let Some(pauser) = config.vendor_config.pl0_pauser {
            header.flags |= Self::PL0_PAUSER_FLAG;
            header.pl0_pauser = pauser;
        }

        if let Some(owner_config) = &config.owner_config {
            header.owner_data.owner_not_before = owner_config.not_before;
            header.owner_data.owner_not_after = owner_config.not_after;
            header.owner_data.epoch = owner_config.epoch;
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

    /// Calculate owner public key descriptor digest.
    pub fn owner_pubkey_digest(&self, preamble: &ImagePreamble) -> anyhow::Result<ImageDigest> {
        self.crypto
            .sha384_digest(preamble.owner_pub_key_info.as_bytes())
    }

    /// Calculate vendor public key descriptor digest.
    pub fn vendor_pubkey_digest(&self, preamble: &ImagePreamble) -> anyhow::Result<ImageDigest> {
        self.crypto
            .sha384_digest(preamble.vendor_pub_key_info.as_bytes())
    }

    /// Generate image
    fn gen_image<E>(
        &self,
        image: &E,
        id: ImageTocEntryId,
        offset: u32,
    ) -> anyhow::Result<(ImageTocEntry, Vec<u8>)>
    where
        E: ImageGeneratorExecutable,
    {
        let r#type = ImageTocEntryType::Executable;
        let digest = self.crypto.sha384_digest(image.content())?;

        let entry = ImageTocEntry {
            id: id.into(),
            r#type: r#type.into(),
            revision: *image.rev(),
            version: image.version(),
            svn: image.svn(),
            reserved: 0,
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
