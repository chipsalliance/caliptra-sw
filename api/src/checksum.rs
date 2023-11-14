// Licensed under the Apache-2.0 license

/// Verify checksum
pub fn verify_checksum(checksum: i32, cmd: u32, data: &[u8]) -> bool {
    calc_checksum(cmd, data) == checksum
}

/// Calculate the checksum
/// 0 - (SUM(command code bytes) + SUM(request/response bytes))
pub fn calc_checksum(cmd: u32, data: &[u8]) -> i32 {
    let mut checksum = 0i32;
    for c in cmd.to_le_bytes().iter() {
        checksum = checksum.wrapping_add(*c as i32);
    }
    for d in data {
        checksum = checksum.wrapping_add(*d as i32);
    }
    0i32.wrapping_sub(checksum)
}

#[cfg(all(test, target_family = "unix"))]
mod tests {
    use super::*;

    #[test]
    fn test_calc_checksum() {
        assert_eq!(calc_checksum(0xe8dc3994, &[0x83, 0xe7, 0x25]), -1056);
    }

    #[test]
    fn test_checksum_overflow() {
        let data = vec![0xff; 16843007];
        assert_eq!(calc_checksum(0xe8dc3994, &data), -146);
        assert!(verify_checksum(-146, 0xe8dc3994, &data));
    }

    #[test]
    fn test_verify_checksum() {
        assert!(verify_checksum(-1056, 0xe8dc3994, &[0x83, 0xe7, 0x25]));
        assert!(!verify_checksum(-1057, 0xe8dc3994, &[0x83, 0xe7, 0x25]));
        assert!(!verify_checksum(-1055, 0xe8dc3994, &[0x83, 0xe7, 0x25]));

        // subtraction overflow; would panic in debug mode if non-wrapping
        // subtraction was used.
        assert!(!verify_checksum(
            2147483647,
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
