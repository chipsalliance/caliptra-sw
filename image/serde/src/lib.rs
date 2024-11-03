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
        self.writer.write_all(image.manifest.as_bytes())?;

        self.writer.write_all(&image.fmc)?;
        self.writer.write_all(&image.runtime)?;
        Ok(())
    }
}
