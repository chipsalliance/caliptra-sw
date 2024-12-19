/*++

Licensed under the Apache-2.0 license.

File Name:

    x509.rs

Abstract:

    File contains X509 Certificate & CSR related utility functions

--*/
use crate::crypto::{self, PubKey};
use caliptra_drivers::*;
use core::mem::size_of;
use core::usize;
use zerocopy::AsBytes;

/// X509 API
pub enum X509 {}

impl X509 {
    /// Get device serial number
    ///
    /// # Arguments
    ///
    /// * `soc_ifc` - SOC Interface object
    ///
    /// # Returns
    ///
    /// `[u8; 17]` - Byte 0 - Ueid Type, Bytes 1-16 Unique Endpoint Identifier
    pub fn ueid(soc_ifc: &SocIfc) -> CaliptraResult<[u8; 17]> {
        let ueid = soc_ifc.fuse_bank().ueid();
        Ok(ueid)
    }

    /// Get public key bytes. Reverses the endianness of each dword in the public key.
    ///
    /// # Arguments
    ///
    /// * `pub_key` - ECC or MLDSA Public Key
    /// * `pub_key_bytes` - Buffer to hold the public key bytes
    ///
    /// # Returns
    ///
    /// `usize` - Number of bytes written to the buffer
    #[inline(always)]
    #[allow(clippy::cast_ptr_alignment)]
    pub fn get_pubkey_bytes(pub_key: &PubKey, pub_key_bytes: &mut [u8]) -> usize {
        fn copy_and_swap_endianess(src: &[u8], dst: &mut [u8]) {
            for i in (0..src.len()).step_by(4) {
                if i + 3 < src.len() && i + 3 < dst.len() {
                    dst[i] = src[i + 3];
                    dst[i + 1] = src[i + 2];
                    dst[i + 2] = src[i + 1];
                    dst[i + 3] = src[i];
                }
            }
        }

        match pub_key {
            PubKey::Ecc(pub_key) => {
                let ecc_pubkey_der = pub_key.to_der();
                pub_key_bytes[..ecc_pubkey_der.len()].copy_from_slice(&ecc_pubkey_der);
                ecc_pubkey_der.len()
            }
            PubKey::Mldsa(pub_key) => {
                // pub_key is in Caliptra Hw format (big-endian DWORDs). Convert it to little-endian DWORDs.
                copy_and_swap_endianess(pub_key.0.as_bytes(), pub_key_bytes);
                pub_key_bytes.len()
            }
        }
    }

    fn pub_key_digest(sha256: &mut Sha256, pub_key: &PubKey) -> CaliptraResult<Array4x8> {
        // Define an array large enough to hold the largest public key.
        let mut pub_key_bytes: [u8; size_of::<Mldsa87PubKey>()] = [0; size_of::<Mldsa87PubKey>()];
        let pub_key_size = Self::get_pubkey_bytes(pub_key, &mut pub_key_bytes);
        crypto::sha256_digest(sha256, &pub_key_bytes[..pub_key_size])
    }

    /// Get X509 Subject Serial Number from public key
    ///
    /// # Arguments
    ///
    /// * `sha256`  - SHA256 Driver
    /// * `pub_key` - ECC or MLDSA Public Key
    ///
    /// # Returns
    ///
    /// `[u8; 64]` - X509 Subject Identifier serial number
    pub fn subj_sn(sha256: &mut Sha256, pub_key: &PubKey) -> CaliptraResult<[u8; 64]> {
        let digest = Self::pub_key_digest(sha256, pub_key);
        let digest = okref(&digest)?;
        Ok(Self::hex(&digest.into()))
    }

    /// Get Cert Subject Key Identifier
    ///
    /// # Arguments
    ///
    /// * `sha256`  - SHA256 Driver
    /// * `pub_key` - Public Key
    ///
    /// # Returns
    ///
    /// `[u8; 20]` - X509 Subject Key Identifier
    pub fn subj_key_id(sha256: &mut Sha256, pub_key: &PubKey) -> CaliptraResult<[u8; 20]> {
        let digest = Self::pub_key_digest(sha256, pub_key);
        let digest: [u8; 32] = okref(&digest)?.into();
        Ok(digest[..20].try_into().unwrap())
    }

    /// Get Serial Number for ECC certificate.
    ///
    /// # Arguments
    ///
    /// * `sha256`  - SHA256 Driver
    /// * `pub_key` - ECC Public Key
    ///
    /// # Returns
    ///
    /// `[u8; 20]` - X509 Serial Number
    pub fn ecc_cert_sn(sha256: &mut Sha256, pub_key: &Ecc384PubKey) -> CaliptraResult<[u8; 20]> {
        let data = pub_key.to_der();
        let digest = crypto::sha256_digest(sha256, &data);
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
