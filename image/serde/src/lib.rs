/*++

Licensed under the Apache-2.0 license.

File Name:

   lib.rs

Abstract:

    Caliptra Image Bundle serialization & deserialization routines.

--*/
use caliptra_image_types::*;
use memoffset::offset_of;
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
        // Add fields till the ECC vendor key descriptor.
        let offset = offset_of!(ImageManifest, preamble);
        let ptr = &image.manifest as *const _ as *const u8;
        let slice = unsafe { std::slice::from_raw_parts(ptr, offset) };
        self.writer.write_all(slice)?;

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

        // Add the remaining fields of the preamble.
        let start = offset_of!(ImagePreamble, vendor_ecc_pub_key_idx);
        let preamble_size = std::mem::size_of::<ImagePreamble>();
        let ptr = &image.manifest.preamble as *const ImagePreamble as *const u8;
        let slice = unsafe { std::slice::from_raw_parts(ptr.add(start), preamble_size - start) };
        self.writer.write_all(slice)?;

        self.writer.write_all(&image.fmc)?;
        self.writer.write_all(&image.runtime)?;
        Ok(())
    }
}
