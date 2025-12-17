/*++

Licensed under the Apache-2.0 license.

File Name:

    tci.rs

Abstract:

    File contains execution routines for TCI computation

Environment:

    FMC


--*/
use crate::fmc_env::FmcEnvNonCrypto;
use caliptra_drivers::{Array4x12, CaliptraResult};
use zerocopy::IntoBytes;

pub struct Tci {}

impl Tci {
    /// Compute Image Manifest Digest
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    pub fn image_manifest_digest(env: &mut FmcEnvNonCrypto) -> CaliptraResult<Array4x12> {
        let manifest = env.persistent_data.get().rom.manifest1;
        env.sha2_512_384.sha384_digest(manifest.as_bytes())
    }
}
