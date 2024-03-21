/*++

Licensed under the Apache-2.0 license.

File Name:

    x509.rs

Abstract:

    File contains X509 Certificate & CSR related utility functions

--*/
use super::crypto::Crypto;
use crate::cprintln;
use crate::rom_env::RomEnv;
use caliptra_drivers::*;

/// Wrapper to hold certificate buffer and length
pub struct Certificate<'a, const LEN: usize> {
    buf: &'a [u8; LEN],
    len: usize,
}

impl<'a, const LEN: usize> Certificate<'a, LEN> {
    /// Create an instance of `Certificate`
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer
    /// * `len` - Buffer length  
    pub fn new(buf: &'a [u8; LEN], len: usize) -> Self {
        Self { buf, len }
    }

    /// Get the buffer
    pub fn get(&self) -> Option<&[u8]> {
        self.buf.get(..self.len)
    }
}

/// X509 API
pub enum X509 {}

impl X509 {
    /// Get Initial Device ID Cert Subject Key Identifier
    ///
    /// # Arguments
    ///
    /// * `env`     - ROM Environment
    /// * `pub_key` - Public Key
    ///
    /// # Returns
    ///
    /// `[u8; 20]` - X509 Subject Key Identifier
    pub fn idev_subj_key_id(env: &mut RomEnv, pub_key: &Ecc384PubKey) -> CaliptraResult<[u8; 20]> {
        let data = pub_key.to_der();

        let digest: [u8; 20] = match env.soc_ifc.fuse_bank().idev_id_x509_key_id_algo() {
            X509KeyIdAlgo::Sha1 => {
                cprintln!("[idev] Using Sha1 for KeyId Algorithm");
                let digest = Crypto::sha1_digest(env, &data);
                okref(&digest)?.into()
            }
            X509KeyIdAlgo::Sha256 => {
                cprintln!("[idev] Using Sha256 for KeyId Algorithm");
                let digest = caliptra_common::crypto::Crypto::sha256_digest(&mut env.sha256, &data);
                let digest: [u8; 32] = okref(&digest)?.into();
                digest[..20].try_into().unwrap()
            }
            X509KeyIdAlgo::Sha384 => {
                cprintln!("[idev] Using Sha384 for KeyId Algorithm");
                let digest = caliptra_common::crypto::Crypto::sha384_digest(&mut env.sha384, &data);
                let digest: [u8; 48] = okref(&digest)?.into();
                digest[..20].try_into().unwrap()
            }
            X509KeyIdAlgo::Fuse => {
                cprintln!("[idev] Using Fuse for KeyId");
                env.soc_ifc.fuse_bank().subject_key_id()
            }
        };

        Ok(digest)
    }
}
