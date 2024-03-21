/*++

Licensed under the Apache-2.0 license.

File Name:

    x509.rs

Abstract:

    File contains X509 Certificate & CSR related utility functions

--*/
use caliptra_drivers::{okref, CaliptraResult, Ecc384PubKey, Sha256, SocIfc};
use caliptra_image_types::ImageManifest;

use crate::crypto::Crypto;
use zeroize::Zeroize;

pub const NOT_BEFORE: &str = "20230101000000Z";
pub const NOT_AFTER: &str = "99991231235959Z";

#[derive(Debug, Zeroize)]
pub struct NotBefore {
    pub value: [u8; 15],
}

impl Default for NotBefore {
    fn default() -> Self {
        let mut nb: NotBefore = NotBefore { value: [0u8; 15] };

        nb.value.copy_from_slice(NOT_BEFORE.as_bytes());
        nb
    }
}

#[derive(Debug, Zeroize)]
pub struct NotAfter {
    pub value: [u8; 15],
}

impl Default for NotAfter {
    fn default() -> Self {
        let mut nf: NotAfter = NotAfter { value: [0u8; 15] };

        nf.value.copy_from_slice(NOT_AFTER.as_bytes());
        nf
    }
}

/// X509 API
pub enum X509 {}

impl X509 {
    /// Process the certificate validity info
    ///
    /// # Arguments
    /// * `manifest` - Manifest
    ///
    /// # Returns
    /// * `NotBefore` - Valid Not Before Time
    /// * `NotAfter`  - Valid Not After Time
    ///
    pub fn get_cert_validity_info(manifest: &ImageManifest) -> (NotBefore, NotAfter) {
        // If there is a valid value in the manifest for the not_before and not_after times,
        // use those. Otherwise use the default values.
        let mut nb = NotBefore::default();
        let mut nf = NotAfter::default();
        let null_time = [0u8; 15];

        if manifest.header.vendor_data.vendor_not_after != null_time
            && manifest.header.vendor_data.vendor_not_before != null_time
        {
            nf.value = manifest.header.vendor_data.vendor_not_after;
            nb.value = manifest.header.vendor_data.vendor_not_before;
        }

        // Owner values take preference.
        if manifest.header.owner_data.owner_not_after != null_time
            && manifest.header.owner_data.owner_not_before != null_time
        {
            nf.value = manifest.header.owner_data.owner_not_after;
            nb.value = manifest.header.owner_data.owner_not_before;
        }

        (nb, nf)
    }

    /// Get X509 Subject Serial Number
    ///
    /// # Arguments
    ///
    /// * `sha256`  - Sha256 Driver
    /// * `pub_key` - Public Key
    ///
    /// # Returns
    ///
    /// `[u8; 64]` - X509 Subject Identifier serial number
    pub fn subj_sn(sha256: &mut Sha256, pub_key: &Ecc384PubKey) -> CaliptraResult<[u8; 64]> {
        let data = pub_key.to_der();
        let digest = Crypto::sha256_digest(sha256, &data);
        let digest = okref(&digest)?;
        Ok(Self::hex(&digest.into()))
    }

    /// Get Cert Subject Key Identifier
    ///
    /// # Arguments
    ///
    /// * `sha256`  - Sha256 Driver
    /// * `pub_key` - Public Key
    ///
    /// # Returns
    ///
    /// `[u8; 20]` - X509 Subject Key Identifier
    pub fn subj_key_id(sha256: &mut Sha256, pub_key: &Ecc384PubKey) -> CaliptraResult<[u8; 20]> {
        let data = pub_key.to_der();
        let digest = Crypto::sha256_digest(sha256, &data);
        let digest: [u8; 32] = okref(&digest)?.into();
        let mut out = [0u8; 20];
        out.copy_from_slice(&digest[..20]);
        Ok(out)
    }

    /// Get Cert Serial Number
    ///
    /// # Arguments
    ///
    /// * `sha256`  - Sha256 Driver
    /// * `pub_key` - Public Key
    ///
    /// # Returns
    ///
    /// `[u8; 20]` - X509 Serial Number
    pub fn cert_sn(sha256: &mut Sha256, pub_key: &Ecc384PubKey) -> CaliptraResult<[u8; 20]> {
        let data = pub_key.to_der();
        let digest = Crypto::sha256_digest(sha256, &data);
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
    /// * `soc_ifc` - SoC Interface
    ///
    /// # Returns
    ///
    /// `[u8; 17]` - Byte 0 - Ueid Type, Bytes 1-16 Unique Endpoint Identifier
    pub fn ueid(soc_ifc: &SocIfc) -> CaliptraResult<[u8; 17]> {
        let ueid = soc_ifc.fuse_bank().ueid();
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
    pub fn hex(buf: &[u8; 32]) -> [u8; 64] {
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
