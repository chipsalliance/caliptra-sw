/*++

Licensed under the Apache-2.0 license.

File Name:

    x509.rs

Abstract:

    File contains X509 Certificate & CSR related utility functions

--*/
use crate::cprintln;
use crate::crypto::Crypto;
use crate::rom_env::RomEnv;
use caliptra_common::{
    crypto::{self, PubKey},
    x509,
};
use caliptra_drivers::*;
use core::mem::size_of;

/// X509 API
pub enum X509 {}

impl X509 {
    /// Get Initial Device ID Cert Subject Key Identifier
    ///
    /// # Arguments
    ///
    /// * `env`     - ROM Environment
    /// * `pub_key` - ECC or MLDSA Public Key
    ///
    /// # Returns
    ///
    /// `[u8; 20]` - X509 Subject Key Identifier
    pub fn idev_subj_key_id(env: &mut RomEnv, pub_key: &PubKey) -> CaliptraResult<[u8; 20]> {
        let mut pub_key_bytes: [u8; size_of::<Mldsa87PubKey>()] = [0; size_of::<Mldsa87PubKey>()];
        let pub_key_size = x509::X509::get_pubkey_bytes(pub_key, &mut pub_key_bytes);
        let data: &[u8] = &pub_key_bytes[..pub_key_size];

        // [CAP2][TODO] Get the hash algorithm if the key is MLDSA.

        let digest: [u8; 20] = match env.soc_ifc.fuse_bank().idev_id_x509_key_id_algo() {
            X509KeyIdAlgo::Sha1 => {
                cprintln!("[idev] Sha1 KeyId Algorithm");
                let digest = Crypto::sha1_digest(env, data);
                okref(&digest)?.into()
            }
            X509KeyIdAlgo::Sha256 => {
                cprintln!("[idev] Sha256 KeyId Algorithm");
                let digest = crypto::sha256_digest(&mut env.sha256, data);
                let digest: [u8; 32] = okref(&digest)?.into();
                digest[..20].try_into().unwrap()
            }
            X509KeyIdAlgo::Sha384 => {
                cprintln!("[idev] Sha384 KeyId Algorithm");
                let digest = crypto::sha384_digest(&mut env.sha2_512_384, data);
                let digest: [u8; 48] = okref(&digest)?.into();
                digest[..20].try_into().unwrap()
            }
            X509KeyIdAlgo::Fuse => {
                cprintln!("[idev] Fuse KeyId");
                env.soc_ifc.fuse_bank().subject_key_id()
            }
        };

        Ok(digest)
    }
}
