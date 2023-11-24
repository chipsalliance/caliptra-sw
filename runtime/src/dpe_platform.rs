// Licensed under the Apache-2.0 license

use core::cmp::min;

use arrayvec::ArrayVec;
use caliptra_drivers::cprintln;
use crypto::Digest;
use dpe::{
    x509::{CertWriter, DirectoryString, Name},
    DPE_PROFILE,
};
use platform::{Platform, PlatformError, MAX_CHUNK_SIZE};

use crate::MAX_CERT_CHAIN_SIZE;

pub struct DpePlatform<'a> {
    auto_init_locality: u32,
    hashed_rt_pub_key: Digest,
    cert_chain: &'a mut ArrayVec<u8, MAX_CERT_CHAIN_SIZE>,
}

pub const VENDOR_ID: u32 = u32::from_be_bytes(*b"CTRA");
pub const VENDOR_SKU: u32 = u32::from_be_bytes(*b"CTRA");

impl<'a> DpePlatform<'a> {
    pub fn new(
        auto_init_locality: u32,
        hashed_rt_pub_key: Digest,
        cert_chain: &'a mut ArrayVec<u8, 4096>,
    ) -> Self {
        Self {
            auto_init_locality,
            hashed_rt_pub_key,
            cert_chain,
        }
    }
}

impl Platform for DpePlatform<'_> {
    fn get_certificate_chain(
        &mut self,
        offset: u32,
        size: u32,
        out: &mut [u8; MAX_CHUNK_SIZE],
    ) -> Result<u32, PlatformError> {
        let len = self.cert_chain.len() as u32;
        if offset >= len {
            return Err(PlatformError::CertificateChainError);
        }

        let cert_chunk_range_end = min(offset + size, len);
        let bytes_written = cert_chunk_range_end - offset;
        if bytes_written as usize > MAX_CHUNK_SIZE {
            return Err(PlatformError::CertificateChainError);
        }

        out.get_mut(..bytes_written as usize)
            .ok_or(PlatformError::CertificateChainError)?
            .copy_from_slice(
                self.cert_chain
                    .get(offset as usize..cert_chunk_range_end as usize)
                    .ok_or(PlatformError::CertificateChainError)?,
            );
        Ok(bytes_written)
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
        const CALIPTRA_CN: &[u8] = b"Caliptra 1.0 Rt Alias";
        let mut issuer_writer = CertWriter::new(out, true);

        // Caliptra RDN SerialNumber field is always a Sha256 hash
        let mut serial = [0u8; 64];
        Digest::write_hex_str(&self.hashed_rt_pub_key, &mut serial)
            .map_err(|e| PlatformError::IssuerNameError(e.get_error_detail().unwrap_or(0)))?;

        let name = Name {
            cn: DirectoryString::Utf8String(CALIPTRA_CN),
            serial: DirectoryString::PrintableString(&serial),
        };
        let issuer_len = issuer_writer
            .encode_rdn(&name)
            .map_err(|e| PlatformError::IssuerNameError(e.get_error_detail().unwrap_or(0)))?;

        Ok(issuer_len)
    }

    fn write_str(&mut self, str: &str) -> Result<(), PlatformError> {
        cprintln!("{}", str);
        Ok(())
    }
}
