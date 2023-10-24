// Licensed under the Apache-2.0 license

/// Verify checksum
pub fn verify_checksum(checksum: i32, cmd: u32, data: &[u8]) -> bool {
    calc_checksum(cmd, data) - checksum == 0
}

/// Calculate the checksum
/// 0 - (SUM(command code bytes) + SUM(request/response bytes))
pub fn calc_checksum(cmd: u32, data: &[u8]) -> i32 {
    let mut checksum = 0i32;
    for c in cmd.to_le_bytes().iter() {
        checksum += *c as i32;
    }
    for d in data {
        checksum += *d as i32;
    }

    0 - checksum
}

#[cfg(all(test, target_family = "unix"))]
mod tests {
    use super::*;

    #[test]
    fn test_verify_checksum() {
        let cmd = 0x00000001u32;
        let data = [0x00000000u32; 1];
        let checksum = calc_checksum(cmd, data[0].to_le_bytes().as_ref());
        assert!(verify_checksum(checksum, cmd, &data[0].to_le_bytes()));
    }
}
