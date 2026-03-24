// Licensed under the Apache-2.0 license
//! Extracts vendor and owner PK hashes from a Caliptra FW image bundle.
//! Usage: extract-pk-hashes <fw-image.bin>

use caliptra_image_types::ImageManifest;
use sha2::{Digest, Sha384};
use zerocopy::IntoBytes;
use zerocopy::FromBytes;

fn main() {
    let path = std::env::args().nth(1).expect("Usage: extract-pk-hashes <fw-image.bin>");
    let data = std::fs::read(&path).expect("Failed to read file");

    let (manifest, _) =
        ImageManifest::ref_from_prefix(&data).expect("Failed to parse manifest from image");

    let vendor_hash = Sha384::digest(manifest.preamble.vendor_pub_key_info.as_bytes());
    let owner_hash = Sha384::digest(manifest.preamble.owner_pub_keys.as_bytes());

    // Convert to big-endian u32 words and print as hex
    let to_hex = |hash: &[u8]| -> String {
        let mut s = String::with_capacity(96);
        for chunk in hash.chunks(4) {
            s.push_str(&format!(
                "{:08x}",
                u32::from_be_bytes(chunk.try_into().unwrap())
            ));
        }
        s
    };

    println!("VENDOR_PK_HASH={}", to_hex(&vendor_hash));
    println!("OWNER_PK_HASH={}", to_hex(&owner_hash));
}
