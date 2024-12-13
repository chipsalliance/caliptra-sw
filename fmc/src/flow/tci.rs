/*++

Licensed under the Apache-2.0 license.

File Name:

    tci.rs

Abstract:

    File contains execution routines for TCI computation

Environment:

    FMC


--*/
use crate::fmc_env::FmcEnv;
use caliptra_common::crypto;
use caliptra_drivers::{Array4x12, CaliptraResult};
use zerocopy::AsBytes;

pub struct Tci {}

impl Tci {
    /// Compute Image Manifest Digest
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    pub fn image_manifest_digest(env: &mut FmcEnv) -> CaliptraResult<Array4x12> {
        let manifest = env.persistent_data.get().manifest1;
        crypto::sha384_digest(&mut env.sha2_512_384, manifest.as_bytes())
    }
}
