// Licensed under the Apache-2.0 license

#![no_std]

/// Code shared between the caliptra-drivers integration_test.rs (running on the
/// host) and the test binaries (running inside the hw-model).
use core::fmt::Debug;
use zerocopy::{AsBytes, FromBytes};

pub const DOE_TEST_IV: [u32; 4] = [0xc6b407a2, 0xd119a37d, 0xb7a5bdeb, 0x26214aed];

pub const DOE_TEST_HMAC_KEY: [u32; 12] = [
    0x15f4a700, 0xd79bd4e1, 0x0f92b714, 0x3a38d570, 0x7cf2ebb4, 0xab47cc6e, 0xa4827e80, 0x32e6d3b4,
    0xc6879874, 0x0aa49a0f, 0x4e740e9c, 0x2c9f9aad,
];

pub struct HexWord(u32);
impl Debug for HexWord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x{:08x}", self.0)
    }
}

pub struct HexWordSlice<'a>(&'a [u32]);
impl Debug for HexWordSlice<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut l = f.debug_list();
        for val in self.0 {
            l.entry(&HexWord(*val));
        }
        l.finish()
    }
}

#[derive(AsBytes, Clone, Copy, Default, Eq, PartialEq, FromBytes)]
#[repr(C)]
pub struct DoeTestResults {
    /// HMAC result of the UDS as key, and b"Hello world!" as data.
    pub hmac_uds_as_key: [u32; 12],

    /// HMAC result of HMAC_KEY as key, and UDS as data.
    pub hmac_uds_as_data: [u32; 12],

    // HMAC result of of the field entropy (including padding) as key, and
    // b"Hello world" as data.
    pub hmac_field_entropy_as_key: [u32; 12],

    /// HMAC result of HMAC_KEY as key, and field entropy (excluding padding) as
    /// data.
    pub hmac_field_entropy_as_data: [u32; 12],
}
impl Debug for DoeTestResults {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DoeTestResults")
            .field("hmac_uds_as_key", &HexWordSlice(&self.hmac_uds_as_key))
            .field("hmac_uds_as_data", &HexWordSlice(&self.hmac_uds_as_data))
            .field(
                "hmac_field_entropy_as_key",
                &HexWordSlice(&self.hmac_field_entropy_as_key),
            )
            .field(
                "hmac_field_entropy_as_data",
                &HexWordSlice(&self.hmac_field_entropy_as_data),
            )
            .finish()
    }
}
