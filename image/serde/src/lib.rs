/*++

Licensed under the Apache-2.0 license.

File Name:

   lib.rs

Abstract:

    Caliptra Image Bundle serialization & deserialization routines.

--*/
use caliptra_image_types::*;
use std::io::Write;
use zerocopy::AsBytes;

/// Image Bundle Writer
pub struct ImageBundleWriter<W: Write> {
    writer: W,
}

impl<W: Write> ImageBundleWriter<W> {
    /// Create an instance of `ImageBundleWriter`
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    /// Write Image Bundle
    pub fn write(&mut self, image: &ImageBundle) -> anyhow::Result<()> {
        //
        // Manifest - Start
        //
        let manifest = &image.manifest;
        self.writer.write_all(manifest.marker.as_bytes())?;
        self.writer.write_all(manifest.size.as_bytes())?;
        self.writer
            .write_all(std::slice::from_ref(&manifest.fw_image_type))?;
        self.writer.write_all(&manifest.reserved)?;

        //
        // Preamble - Start
        //

        // Add the ECC vendor key descriptor.
        let vendor_pub_key_info = &image.manifest.preamble.vendor_pub_key_info;
        self.writer
            .write_all(vendor_pub_key_info.ecc_key_descriptor.as_bytes())?;
        // Add the ECC vendor public key hashes.
        self.writer.write_all(
            (&vendor_pub_key_info.ecc_pub_key_hashes)
                [..vendor_pub_key_info.ecc_key_descriptor.key_hash_count as usize]
                .as_bytes(),
        )?;

        // Add the LMS vendor key descriptor.
        self.writer
            .write_all(vendor_pub_key_info.lms_key_descriptor.as_bytes())?;
        // Add the LMS vendor public key hashes.
        self.writer.write_all(
            (&vendor_pub_key_info.lms_pub_key_hashes)
                [..vendor_pub_key_info.lms_key_descriptor.key_hash_count as usize]
                .as_bytes(),
        )?;

        let preamble = &image.manifest.preamble;
        self.writer
            .write_all(preamble.vendor_ecc_pub_key_idx.as_bytes())?;
        self.writer
            .write_all(preamble.vendor_ecc_active_pub_key.as_bytes())?;
        self.writer
            .write_all(preamble.vendor_lms_pub_key_idx.as_bytes())?;
        self.writer
            .write_all(preamble.vendor_lms_active_pub_key.as_bytes())?;
        self.writer.write_all(preamble.vendor_sigs.as_bytes())?;
        self.writer
            .write_all(preamble.owner_pub_key_info.as_bytes())?;
        self.writer.write_all(preamble.owner_pub_keys.as_bytes())?;
        self.writer.write_all(preamble.owner_sigs.as_bytes())?;
        self.writer.write_all(preamble._rsvd.as_bytes())?;

        //
        // Preamble - End
        //

        self.writer.write_all(manifest.header.as_bytes())?;
        self.writer.write_all(manifest.fmc.as_bytes())?;
        self.writer.write_all(manifest.runtime.as_bytes())?;

        //
        // Manifest - End
        //

        self.writer.write_all(&image.fmc)?;
        self.writer.write_all(&image.runtime)?;
        Ok(())
    }
}
