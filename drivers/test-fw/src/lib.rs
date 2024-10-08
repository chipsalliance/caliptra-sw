// Licensed under the Apache-2.0 license

#![no_std]

use caliptra_drivers::Ecc384PubKey;

/// Code shared between the caliptra-drivers integration_test.rs (running on the
/// host) and the test binaries (running inside the hw-model).
use core::fmt::Debug;
use zerocopy::{AsBytes, FromBytes};

pub const DOE_TEST_IV: [u32; 4] = [0xc6b407a2, 0xd119a37d, 0xb7a5bdeb, 0x26214aed];

pub const DOE_TEST_HMAC_KEY: [u32; 12] = [
    0x15f4a700, 0xd79bd4e1, 0x0f92b714, 0x3a38d570, 0x7cf2ebb4, 0xab47cc6e, 0xa4827e80, 0x32e6d3b4,
    0xc6879874, 0x0aa49a0f, 0x4e740e9c, 0x2c9f9aad,
];

#[derive(AsBytes, Clone, Copy, Default, FromBytes)]
#[repr(C)]
pub struct DoeTestResults {
    /// HMAC result of the UDS as key, and b"Hello world!" as data.
    pub hmac_uds_as_key_out_pub: Ecc384PubKey,

    /// HMAC result of HMAC_KEY as key, and UDS as data.
    pub hmac_uds_as_data_out_pub: Ecc384PubKey,

    // HMAC result of of the field entropy (including padding) as key, and
    // b"Hello world" as data.
    pub hmac_field_entropy_as_key_out_pub: Ecc384PubKey,

    /// HMAC result of HMAC_KEY as key, and field entropy (excluding padding) as
    /// data.
    pub hmac_field_entropy_as_data_out_pub: Ecc384PubKey,
}
impl Debug for DoeTestResults {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DoeTestResults")
            .field("hmac_uds_as_key_out_pub", &self.hmac_uds_as_key_out_pub)
            .field("hmac_uds_as_data_out_pub", &self.hmac_uds_as_data_out_pub)
            .field(
                "hmac_field_entropy_as_key_out_pub",
                &self.hmac_field_entropy_as_key_out_pub,
            )
            .field(
                "hmac_field_entropy_as_data_out_pub",
                &self.hmac_field_entropy_as_data_out_pub,
            )
            .finish()
    }
}
