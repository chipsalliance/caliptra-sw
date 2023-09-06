// Licensed under the Apache-2.0 license

use crypto::Digest;
use dpe::{
    x509::{Name, X509CertWriter},
    DPE_PROFILE,
};
use platform::{Platform, PlatformError, MAX_CHUNK_SIZE};

pub struct DpePlatform {
    auto_init_locality: u32,
    hashed_rt_pub_key: Digest,
}

pub const VENDOR_ID: u32 = u32::from_be_bytes(*b"CTRA");
pub const VENDOR_SKU: u32 = u32::from_be_bytes(*b"CTRA");

impl DpePlatform {
    pub fn new(auto_init_locality: u32, hashed_rt_pub_key: Digest) -> Self {
        Self {
            auto_init_locality,
            hashed_rt_pub_key,
        }
    }
}

impl Platform for DpePlatform {
    fn get_certificate_chain(
        &mut self,
        _offset: u32,
        _size: u32,
        _out: &mut [u8; MAX_CHUNK_SIZE],
    ) -> Result<u32, PlatformError> {
        Err(PlatformError::NotImplemented)
    }

    fn get_vendor_id(&mut self) -> Result<u32, PlatformError> {
        Ok(VENDOR_ID)
    }

    fn get_vendor_sku(&mut self) -> Result<u32, PlatformError> {
        Ok(VENDOR_SKU)
    }

    fn get_auto_init_locality(&mut self) -> Result<u32, PlatformError> {
        Ok(self.auto_init_locality)
    }

    fn get_issuer_name(&mut self, out: &mut [u8; MAX_CHUNK_SIZE]) -> Result<usize, PlatformError> {
        const CALIPTRA_CN: &[u8] = b"Caliptra Rt Alias";
        let mut issuer_writer = X509CertWriter::new(out, true);

        let mut serial = [0u8; DPE_PROFILE.get_hash_size() * 2];
        Digest::write_hex_str(&self.hashed_rt_pub_key, &mut serial)
            .map_err(|_| PlatformError::IssuerNameError)?;

        let name = Name {
            cn: CALIPTRA_CN,
            serial,
        };
        let issuer_len = issuer_writer
            .encode_rdn(&name)
            .map_err(|_| PlatformError::IssuerNameError)?;

        Ok(issuer_len)
    }
}
