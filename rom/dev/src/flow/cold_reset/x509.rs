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
    /// Get device serial number
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    ///
    /// # Returns
    ///
    /// `[u8; 17]` - Byte 0 - Ueid Type, Bytes 1-16 Unique Endpoint Identifier
    pub fn ueid(env: &RomEnv) -> CaliptraResult<[u8; 17]> {
        let ueid = env.soc_ifc.fuse_bank().ueid();
        Ok(ueid)
    }

    /// Get X509 Subject Serial Number
    ///
    /// # Arguments
    ///
    /// * `env`     - ROM Environment
    /// * `pub_key` - Public Key
    ///
    /// # Returns
    ///
    /// `[u8; 64]` - X509 Subject Identifier serial number
    pub fn subj_sn(env: &mut RomEnv, pub_key: &Ecc384PubKey) -> CaliptraResult<[u8; 64]> {
        let data = pub_key.to_der();
        let digest = Crypto::sha256_digest(env, &data);
        let digest = okref(&digest)?;
        Ok(Self::hex(&digest.into()))
    }

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
                let digest = Crypto::sha256_digest(env, &data);
                let digest: [u8; 32] = okref(&digest)?.into();
                digest[..20].try_into().unwrap()
            }
            X509KeyIdAlgo::Sha384 => {
                cprintln!("[idev] Using Sha384 for KeyId Algorithm");
                let digest = Crypto::sha384_digest(env, &data);
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

    /// Get Cert Subject Key Identifier
    ///
    /// # Arguments
    ///
    /// * `env`     - ROM Environment
    /// * `pub_key` - Public Key
    ///
    /// # Returns
    ///
    /// `[u8; 20]` - X509 Subject Key Identifier
    pub fn subj_key_id(env: &mut RomEnv, pub_key: &Ecc384PubKey) -> CaliptraResult<[u8; 20]> {
        let data = pub_key.to_der();
        let digest = Crypto::sha256_digest(env, &data);
        let digest: [u8; 32] = okref(&digest)?.into();
        Ok(digest[..20].try_into().unwrap())
    }

    /// Get Cert Serial Number
    ///
    /// # Arguments
    ///
    /// * `env`     - ROM Environment
    /// * `pub_key` - Public Key
    ///
    /// # Returns
    ///
    /// `[u8; 20]` - X509 Serial Number
    pub fn cert_sn(env: &mut RomEnv, pub_key: &Ecc384PubKey) -> CaliptraResult<[u8; 20]> {
        let data = pub_key.to_der();
        let digest = Crypto::sha256_digest(env, &data);
        let mut digest: [u8; 32] = okref(&digest)?.into();

        // Ensure the encoded integer is positive, and that the first octet
        // is non-zero (otherwise it will be considered padding, and the integer
        // will fail to parse if the MSB of the second octet is zero).
        digest[0] &= !0x80;
        digest[0] |= 0x04;

        Ok(digest[..20].try_into().unwrap())
    }

    /// Return the hex representation of the input `buf`
    ///
    /// # Arguments
    ///
    /// `buf` - Buffer
    ///
    /// # Returns
    ///
    /// `[u8; 64]` - Hex representation of the buffer
    fn hex(buf: &[u8; 32]) -> [u8; 64] {
        fn ch(byte: u8) -> u8 {
            match byte & 0x0F {
                b @ 0..=9 => 48 + b,
                b @ 10..=15 => 55 + b,
                _ => unreachable!(),
            }
        }

        let mut hex = [0u8; 64];

        for (index, byte) in buf.iter().enumerate() {
            hex[index << 1] = ch((byte & 0xF0) >> 4);
            hex[(index << 1) + 1] = ch(byte & 0x0F);
        }

        hex
    }
}
