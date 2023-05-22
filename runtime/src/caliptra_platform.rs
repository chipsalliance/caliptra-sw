// Licensed under the Apache-2.0 license

use platform::{Platform, PlatformError, MAX_CHUNK_SIZE};

pub struct CaliptraPlatform;

impl Platform for CaliptraPlatform {
    fn get_certificate_chain(
        offset: u32,
        size: u32,
        out: &mut [u8; MAX_CHUNK_SIZE],
    ) -> Result<u32, PlatformError> {
        Err(PlatformError::NotImplemented)
    }
}