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
use crate::HandOff;
use caliptra_drivers::{Array4x12, CaliptraResult};
use caliptra_image_types::ImageManifest;
use core::mem::size_of;

pub struct Tci {}

impl Tci {
    /// Compute Image Manifest Digest
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `hand_off` - HandOff
    pub fn image_manifest_digest(
        env: &mut FmcEnv,
        hand_off: &HandOff,
    ) -> CaliptraResult<Array4x12> {
        let image_manifest_bytes = unsafe {
            core::slice::from_raw_parts_mut(
                hand_off.image_manifest_address(env) as *mut u8,
                size_of::<ImageManifest>(),
            )
        };

        Crypto::sha384_digest(env, image_manifest_bytes)
    }

    ///  RtFw Digest
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `hand_off` - HandOff
    pub fn rt_tci(env: &mut FmcEnv, hand_off: &HandOff) -> CaliptraResult<Array4x12> {
        Ok(hand_off.rt_tci(env))
    }
}
