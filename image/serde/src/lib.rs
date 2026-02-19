/*++

Licensed under the Apache-2.0 license.

File Name:

   lib.rs

Abstract:

    Caliptra Image Bundle serialization & deserialization routines.

--*/
use caliptra_image_types::*;
use std::io::Write;
use zerocopy::IntoBytes;

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
        self.writer.write_all(image.manifest.as_bytes())?;

        self.writer.write_all(&image.fmc)?;
        self.writer.write_all(&image.runtime)?;
        // Pad to IMAGE_ALIGNMENT boundary
        let total = image.manifest.as_bytes().len() + image.fmc.len() + image.runtime.len();
        let padded = total.next_multiple_of(IMAGE_ALIGNMENT);
        if padded > total {
            self.writer.write_all(&vec![0u8; padded - total])?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn test_writer_alignment() {
        let manifest_size = size_of::<ImageManifest>();
        let fmc = vec![0u8; 100];
        let runtime = vec![0u8; 37];
        let mut manifest = ImageManifest::default();
        manifest.fmc.offset = manifest_size as u32;
        manifest.fmc.size = fmc.len() as u32;
        manifest.runtime.offset = (manifest_size + fmc.len()) as u32;
        manifest.runtime.size = runtime.len() as u32;
        let bundle = ImageBundle {
            manifest,
            fmc,
            runtime,
        };
        let mut buf = Vec::new();
        let mut writer = ImageBundleWriter::new(&mut buf);
        writer.write(&bundle).unwrap();
        assert_eq!(
            buf.len() % IMAGE_ALIGNMENT,
            0,
            "ImageBundleWriter output must be a multiple of IMAGE_ALIGNMENT ({})",
            IMAGE_ALIGNMENT
        );
    }
}
