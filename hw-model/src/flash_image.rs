// Licensed under the Apache-2.0 license

//! Flash image builder for creating flash images in the MCU ROM format.
//!
//! The flash image format consists of:
//! - A [`FlashHeader`] with magic number "FLSH", version, image count, and checksum
//! - An array of [`ImageHeader`] entries describing each image
//! - The image data itself, padded to 256-byte alignment
//!
//! This matches the format expected by the MCU ROM's flash boot path in caliptra-mcu-sw.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub const CALIPTRA_FMC_RT_IDENTIFIER: u32 = 0x0000_0000;
pub const SOC_MANIFEST_IDENTIFIER: u32 = 0x0000_0001;
pub const MCU_RT_IDENTIFIER: u32 = 0x0000_0002;

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct FlashHeader {
    pub magic: [u8; 4],
    pub version: u16,
    pub image_count: u16,
    pub image_headers_offset: u32,
    pub header_checksum: u32,
}

impl FlashHeader {
    pub const HEADER_VERSION: u16 = 0x0001;
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct ImageHeader {
    pub identifier: u32,
    pub offset: u32,
    pub size: u32,
    pub image_checksum: u32,
    pub image_header_checksum: u32,
}

fn calculate_checksum(data: &[u8]) -> u32 {
    let sum = data
        .iter()
        .fold(0u32, |acc, &byte| acc.wrapping_add(byte as u32));
    0u32.wrapping_sub(sum)
}

fn pad_to_256(data: &[u8]) -> Vec<u8> {
    let padded_len = data.len().next_multiple_of(256);
    let mut padded = data.to_vec();
    padded.resize(padded_len, 0);
    padded
}

/// Build a flash image from raw firmware data and return it as bytes.
///
/// The resulting image can be loaded into `primary_flash_initial_contents`
/// for flash-based boot testing instead of using the I3C recovery interface.
pub fn build_flash_image_bytes(
    caliptra_fw: Option<&[u8]>,
    soc_manifest: Option<&[u8]>,
    mcu_runtime: Option<&[u8]>,
) -> Vec<u8> {
    let mut images: Vec<(u32, Vec<u8>)> = Vec::new();

    if let Some(data) = caliptra_fw {
        images.push((CALIPTRA_FMC_RT_IDENTIFIER, pad_to_256(data)));
    }
    if let Some(data) = soc_manifest {
        images.push((SOC_MANIFEST_IDENTIFIER, pad_to_256(data)));
    }
    if let Some(data) = mcu_runtime {
        images.push((MCU_RT_IDENTIFIER, pad_to_256(data)));
    }

    if images.is_empty() {
        return Vec::new();
    }

    let header_size = core::mem::size_of::<FlashHeader>();
    let image_header_size = core::mem::size_of::<ImageHeader>();

    // Calculate offsets for image data
    let data_start = header_size + image_header_size * images.len();
    let mut current_offset = data_start as u32;

    // Build image headers
    let image_headers: Vec<ImageHeader> = images
        .iter()
        .map(|(id, data)| {
            let image_checksum = calculate_checksum(data);
            let mut hdr = ImageHeader {
                identifier: *id,
                offset: current_offset,
                size: data.len() as u32,
                image_checksum,
                image_header_checksum: 0,
            };
            // Checksum covers all fields except image_header_checksum
            let hdr_bytes = hdr.as_bytes();
            let checksum_offset = core::mem::offset_of!(ImageHeader, image_header_checksum);
            hdr.image_header_checksum = calculate_checksum(&hdr_bytes[..checksum_offset]);
            current_offset += data.len() as u32;
            hdr
        })
        .collect();

    // Build flash header
    let mut flash_header = FlashHeader {
        magic: *b"FLSH",
        version: FlashHeader::HEADER_VERSION,
        image_count: images.len() as u16,
        image_headers_offset: header_size as u32,
        header_checksum: 0,
    };
    let hdr_bytes = flash_header.as_bytes();
    let checksum_offset = core::mem::offset_of!(FlashHeader, header_checksum);
    flash_header.header_checksum = calculate_checksum(&hdr_bytes[..checksum_offset]);

    // Assemble the final image
    let mut result = Vec::new();
    result.extend_from_slice(flash_header.as_bytes());
    for hdr in &image_headers {
        result.extend_from_slice(hdr.as_bytes());
    }
    for (_, data) in &images {
        result.extend_from_slice(data);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_flash_image_bytes_empty() {
        let result = build_flash_image_bytes(None, None, None);
        assert!(result.is_empty());
    }

    #[test]
    fn test_build_flash_image_roundtrip() {
        let fw = vec![0xAAu8; 100];
        let manifest = vec![0xBBu8; 200];
        let mcu = vec![0xCCu8; 50];

        let image = build_flash_image_bytes(Some(&fw), Some(&manifest), Some(&mcu));
        assert!(!image.is_empty());

        // Parse and verify the header
        let header = FlashHeader::read_from_prefix(&image).unwrap().0;
        assert_eq!(&header.magic, b"FLSH");
        assert_eq!(header.version, FlashHeader::HEADER_VERSION);
        assert_eq!(header.image_count, 3);

        // Verify header checksum
        let checksum_offset = core::mem::offset_of!(FlashHeader, header_checksum);
        let expected = calculate_checksum(&image[..checksum_offset]);
        assert_eq!(header.header_checksum, expected);

        // Parse image headers
        let hdr_offset = header.image_headers_offset as usize;
        let hdr_size = core::mem::size_of::<ImageHeader>();

        for i in 0..3 {
            let off = hdr_offset + i * hdr_size;
            let img_hdr = ImageHeader::read_from_prefix(&image[off..]).unwrap().0;

            // Verify image header checksum
            let ih_checksum_offset = core::mem::offset_of!(ImageHeader, image_header_checksum);
            let ih_bytes = img_hdr.as_bytes();
            let expected = calculate_checksum(&ih_bytes[..ih_checksum_offset]);
            assert_eq!(img_hdr.image_header_checksum, expected);

            // Verify image data checksum
            let data =
                &image[img_hdr.offset as usize..img_hdr.offset as usize + img_hdr.size as usize];
            assert_eq!(img_hdr.image_checksum, calculate_checksum(data));
        }

        // Verify identifiers
        let hdr0 = ImageHeader::read_from_prefix(&image[hdr_offset..])
            .unwrap()
            .0;
        let hdr1 = ImageHeader::read_from_prefix(&image[hdr_offset + hdr_size..])
            .unwrap()
            .0;
        let hdr2 = ImageHeader::read_from_prefix(&image[hdr_offset + 2 * hdr_size..])
            .unwrap()
            .0;
        assert_eq!(hdr0.identifier, CALIPTRA_FMC_RT_IDENTIFIER);
        assert_eq!(hdr1.identifier, SOC_MANIFEST_IDENTIFIER);
        assert_eq!(hdr2.identifier, MCU_RT_IDENTIFIER);

        // Verify sizes are padded to 256
        assert_eq!(hdr0.size, 256); // 100 -> 256
        assert_eq!(hdr1.size, 256); // 200 -> 256
        assert_eq!(hdr2.size, 256); // 50 -> 256
    }
}
