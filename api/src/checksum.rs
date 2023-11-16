// Licensed under the Apache-2.0 license

/// Verify checksum
pub fn verify_checksum(checksum: u32, cmd: u32, data: &[u8]) -> bool {
    calc_checksum(cmd, data) == checksum
}

/// Calculate the checksum
/// 0 - (SUM(command code bytes) + SUM(request/response bytes))
pub fn calc_checksum(cmd: u32, data: &[u8]) -> u32 {
    let mut checksum = 0u32;
    for c in cmd.to_le_bytes().iter() {
        checksum = checksum.wrapping_add(*c as u32);
    }
    for d in data {
        checksum = checksum.wrapping_add(*d as u32);
    }
    0u32.wrapping_sub(checksum)
}

#[cfg(all(test, target_family = "unix"))]
mod tests {
    use super::*;

    #[test]
    fn test_calc_checksum() {
        assert_eq!(calc_checksum(0xe8dc3994, &[0x83, 0xe7, 0x25]), 0xfffffbe0);
    }

    #[test]
    fn test_checksum_overflow() {
        let data = vec![0xff; 16843007];
        assert_eq!(calc_checksum(0xe8dc3994, &data), 0xffffff6e);
        assert!(verify_checksum(0xffffff6e, 0xe8dc3994, &data));
    }

    #[test]
    fn test_verify_checksum() {
        assert!(verify_checksum(0xfffffbe0, 0xe8dc3994, &[0x83, 0xe7, 0x25]));
        assert!(!verify_checksum(
            0xfffffbdf,
            0xe8dc3994,
            &[0x83, 0xe7, 0x25]
        ));
        assert!(!verify_checksum(
            0xfffffbe1,
            0xe8dc3994,
            &[0x83, 0xe7, 0x25]
        ));

        // subtraction overflow; would panic in debug mode if non-wrapping
        // subtraction was used.
        assert!(!verify_checksum(
            0xffffffff,
            0xe8dc3994,
            &[0x83, 0xe7, 0x25]
        ));
    }

    #[test]
    fn test_round_trip() {
        let cmd = 0x00000001u32;
        let data = [0x00000000u32; 1];
        let checksum = calc_checksum(cmd, data[0].to_le_bytes().as_ref());
        assert!(verify_checksum(checksum, cmd, &data[0].to_le_bytes()));
    }
}
