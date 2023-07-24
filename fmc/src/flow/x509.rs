/*++

Licensed under the Apache-2.0 license.

File Name:

    x509.rs

Abstract:

    File contains X509 Certificate & CSR related utility functions

--*/
use super::crypto::Crypto;
use crate::fmc_env::FmcEnv;
use caliptra_drivers::*;

/// X509 API
pub enum X509 {}

impl X509 {
    /// Get X509 Subject Serial Number
    ///
    /// # Arguments
    ///
    /// * `env`     - FMC Environment
    /// * `pub_key` - Public Key
    ///
    /// # Returns
    ///
    /// `[u8; 64]` - X509 Subject Identifier serial number
    pub fn subj_sn(env: &mut FmcEnv, pub_key: &Ecc384PubKey) -> CaliptraResult<[u8; 64]> {
        let data = pub_key.to_der();
        let digest = Crypto::sha256_digest(env, &data);
        let digest = okref(&digest)?;
        Ok(Self::hex(&digest.into()))
    }

    /// Get Cert Subject Key Identifier
    ///
    /// # Arguments
    ///
    /// * `env`     - FMC Environment
    /// * `pub_key` - Public Key
    ///
    /// # Returns
    ///
    /// `[u8; 20]` - X509 Subject Key Identifier
    pub fn subj_key_id(env: &mut FmcEnv, pub_key: &Ecc384PubKey) -> CaliptraResult<[u8; 20]> {
        let data = pub_key.to_der();
        let digest = Crypto::sha256_digest(env, &data);
        let digest: [u8; 32] = okref(&digest)?.into();
        let mut out = [0u8; 20];
        out.copy_from_slice(&digest[..20]);
        Ok(out)
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
    pub fn cert_sn(env: &mut FmcEnv, pub_key: &Ecc384PubKey) -> CaliptraResult<[u8; 20]> {
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

    /// Get device serial number
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    ///
    /// # Returns
    ///
    /// `[u8; 8]` - 64-bit Unique Endpoint Identifier
    pub fn ueid(env: &FmcEnv) -> CaliptraResult<[u8; 8]> {
        let ueid = env.soc_ifc.fuse_bank().ueid();
        Ok(ueid)
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
