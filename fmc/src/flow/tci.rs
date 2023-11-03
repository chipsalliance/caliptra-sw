/*++

Licensed under the Apache-2.0 license.

File Name:

    tci.rs

Abstract:

    File contains execution routines for TCI computation

Environment:

    FMC


--*/
use crate::flow::crypto::Crypto;
use crate::fmc_env::FmcEnv;
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
        Crypto::sha384_digest(env, manifest.as_bytes())
    }
}
