/*++

Licensed under the Apache-2.0 license.

File Name:

    dpe_platform.rs

Abstract:

    File contains DpePlatform implementation.

--*/

use core::cmp::min;

use arrayvec::ArrayVec;
use caliptra_drivers::cprintln;
use caliptra_image_types::{ImageHeader, ImageManifest};
use caliptra_x509::{NotAfter, NotBefore};
use crypto::Digest;
use dpe::{
    x509::{CertWriter, DirectoryString, Name},
    DPE_PROFILE,
};
use platform::{
    CertValidity, Platform, PlatformError, SignerIdentifier, MAX_CHUNK_SIZE, MAX_ISSUER_NAME_SIZE,
    MAX_KEY_IDENTIFIER_SIZE, MAX_SN_SIZE,
};
use zerocopy::AsBytes;

use crate::MAX_CERT_CHAIN_SIZE;

pub struct DpePlatform<'a> {
    auto_init_locality: u32,
    hashed_rt_pub_key: Digest,
    cert_chain: &'a mut ArrayVec<u8, MAX_CERT_CHAIN_SIZE>,
    not_before: &'a NotBefore,
    not_after: &'a NotAfter,
}

pub const VENDOR_ID: u32 = u32::from_be_bytes(*b"CTRA");
pub const VENDOR_SKU: u32 = u32::from_be_bytes(*b"CTRA");

impl<'a> DpePlatform<'a> {
    pub fn new(
        auto_init_locality: u32,
        hashed_rt_pub_key: Digest,
        cert_chain: &'a mut ArrayVec<u8, 4096>,
        not_before: &'a NotBefore,
        not_after: &'a NotAfter,
    ) -> Self {
        Self {
            auto_init_locality,
            hashed_rt_pub_key,
            cert_chain,
            not_before,
            not_after,
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

    fn get_issuer_name(
        &mut self,
        out: &mut [u8; MAX_ISSUER_NAME_SIZE],
    ) -> Result<usize, PlatformError> {
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

    /// See X509::subj_key_id in fmc/src/flow/x509.rs for code that generates the
    /// SubjectKeyIdentifier extension in the RT alias certificate.
    fn get_signer_identifier(&mut self) -> Result<SignerIdentifier, PlatformError> {
        let mut ski = [0u8; MAX_KEY_IDENTIFIER_SIZE];
        let hashed_rt_pub_key = self.hashed_rt_pub_key.bytes();
        if hashed_rt_pub_key.len() < MAX_KEY_IDENTIFIER_SIZE {
            return Err(PlatformError::SubjectKeyIdentifierError(0));
        }
        ski.copy_from_slice(&hashed_rt_pub_key[..MAX_KEY_IDENTIFIER_SIZE]);
        let mut ski_vec = ArrayVec::new();
        ski_vec
            .try_extend_from_slice(&ski)
            .map_err(|_| PlatformError::SubjectKeyIdentifierError(0))?;
        Ok(SignerIdentifier::SubjectKeyIdentifier(ski_vec))
    }

    fn get_issuer_key_identifier(
        &mut self,
        out: &mut [u8; MAX_KEY_IDENTIFIER_SIZE],
    ) -> Result<(), PlatformError> {
        let hashed_rt_pub_key = self.hashed_rt_pub_key.bytes();
        if hashed_rt_pub_key.len() < MAX_KEY_IDENTIFIER_SIZE {
            return Err(PlatformError::IssuerKeyIdentifierError(0));
        }
        out.copy_from_slice(&hashed_rt_pub_key[..MAX_KEY_IDENTIFIER_SIZE]);
        Ok(())
    }

    fn write_str(&mut self, str: &str) -> Result<(), PlatformError> {
        cprintln!("{}", str);
        Ok(())
    }

    fn get_cert_validity(&mut self) -> Result<CertValidity, PlatformError> {
        let mut not_before = ArrayVec::new();
        not_before
            .try_extend_from_slice(&self.not_before.value)
            .map_err(|_| PlatformError::CertValidityError(0))?;
        let mut not_after = ArrayVec::new();
        not_after
            .try_extend_from_slice(&self.not_after.value)
            .map_err(|_| PlatformError::CertValidityError(0))?;
        Ok(CertValidity {
            not_before,
            not_after,
        })
    }
}
