/*++

Licensed under the Apache-2.0 license.

File Name:

    cert_bldr.rs

Abstract:

    X509 API to construct Certificate or Certificate Signing Request
    from "To Be Signed" blob and ECDSA-384 Signature.

--*/

use crate::{der_encode_len, der_encode_uint, der_uint_len};

/// DER Bit String Tag
const DER_BIT_STR_TAG: u8 = 0x03;

/// DER Sequence Tag
const DER_SEQ_TAG: u8 = 0x30;

/// Trait for signature types
pub trait Signature<const MAX_DER_SIZE: usize> {
    /// Convert the signature to DER format
    fn to_der(&self, buf: &mut [u8; MAX_DER_SIZE]) -> Option<usize>;

    /// DER Encoded Sequence with signature algorithm OID
    fn oid_der() -> &'static [u8];
}

/// ECDSA-384 Signature
#[derive(Debug)]
pub struct Ecdsa384Signature {
    /// Signature R-Coordinate
    pub r: [u8; Self::ECDSA_COORD_LEN],

    /// Signature S-Coordinate
    pub s: [u8; Self::ECDSA_COORD_LEN],
}

impl Default for Ecdsa384Signature {
    fn default() -> Self {
        Self {
            r: [0; Self::ECDSA_COORD_LEN],
            s: [0; Self::ECDSA_COORD_LEN],
        }
    }
}

impl Ecdsa384Signature {
    /// ECDSA Coordinate length
    pub const ECDSA_COORD_LEN: usize = 48;
}

impl Signature<108> for Ecdsa384Signature {
    fn to_der(&self, buf: &mut [u8; 108]) -> Option<usize> {
        // Encode Signature R Coordinate
        let r_uint_len = der_uint_len(&self.r)?;

        // Encode Signature S Coordinate
        let s_uint_len = der_uint_len(&self.s)?;

        //
        // Signature DER Sequence encoding
        //
        // sig_seq_len = TAG (1 byte) + LEN (1 byte) + r_uint_len + s_uint_len
        //
        let sig_seq_len = 2 + r_uint_len + s_uint_len;

        let mut pos = 0;

        // Encode Signature DER Bit String
        *buf.get_mut(pos)? = DER_BIT_STR_TAG;
        pos += 1;
        *buf.get_mut(pos)? = (1 + sig_seq_len) as u8;
        pos += 1;
        *buf.get_mut(pos)? = 0x0;
        pos += 1;

        // Encode Signature DER Sequence
        *buf.get_mut(pos)? = DER_SEQ_TAG;
        pos += 1;
        *buf.get_mut(pos)? = (r_uint_len + s_uint_len) as u8;
        pos += 1;

        // Encode R-Coordinate
        pos += der_encode_uint(&self.r, buf.get_mut(pos..)?)?;

        // Encode S-Coordinate
        pos += der_encode_uint(&self.s, buf.get_mut(pos..)?)?;

        Some(pos)
    }

    fn oid_der() -> &'static [u8] {
        &[
            0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03,
        ]
    }
}

/// Ml-Dsa87 Signature
pub struct Mldsa87Signature {
    pub sig: [u8; 4627],
}

impl Default for Mldsa87Signature {
    /// Returns the "default value" for a type.
    fn default() -> Self {
        Self { sig: [0; 4627] }
    }
}

impl Signature<4635> for Mldsa87Signature {
    fn to_der(&self, buf: &mut [u8; 4635]) -> Option<usize> {
        let ml_dsa_signature_len = der_uint_len(&self.sig)?;

        //
        // Signature DER Sequence encoding
        //
        // sig_seq_len = TAG (1 byte) + LEN (3 byte) + ml_dsa_signature_len
        //
        let sig_seq_len = 4 + ml_dsa_signature_len;
        let mut pos = 0;

        // Encode Signature DER Bit String
        *buf.get_mut(pos)? = DER_BIT_STR_TAG;
        pos += 1;
        pos += der_encode_len(1 + sig_seq_len, buf.get_mut(pos..)?)?;
        // Not sure?
        *buf.get_mut(pos)? = 0x0;
        pos += 1;

        // Encode Signature DER Sequence
        *buf.get_mut(pos)? = DER_SEQ_TAG;
        pos += 1;
        pos += der_encode_len(ml_dsa_signature_len, buf.get_mut(pos..)?)?;

        // Encode Ml-Dsa87 signature
        pos += der_encode_uint(&self.sig, buf.get_mut(pos..)?)?;

        Some(pos)
    }

    fn oid_der() -> &'static [u8] {
        // TODO this is wrong and just copied from ECC
        &[
            0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03,
        ]
    }
}

/// Generic Certificate Builder
#[derive(Debug)]
pub struct CertBuilder<'a, S: Signature<MAX_DER_SIZE>, const MAX_DER_SIZE: usize> {
    /// DER encoded To be signed portion
    tbs: &'a [u8],

    /// Signature of the To be signed portion
    sig: &'a S,

    /// Length of the signed Cert/CSR
    len: usize,
}

impl<'a, S: Signature<MAX_DER_SIZE>, const MAX_DER_SIZE: usize> CertBuilder<'a, S, MAX_DER_SIZE> {
    /// Create an instance of `CertBuilder`
    ///
    /// # Arguments
    ///
    /// * `tbs` - DER encoded To be signed portion
    /// * `sig` - Signature of the To be signed portion
    pub fn new(tbs: &'a [u8], sig: &'a S) -> Option<Self> {
        let mut sig_buf = [0u8; MAX_DER_SIZE];
        let sig_len = sig.to_der(&mut sig_buf)?;
        let len = Self::compute_len(tbs.len(), sig_len, S::oid_der().len())?;
        Some(Self { tbs, sig, len })
    }

    /// Build the Certificate or Certificate Signing Request
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to construct the certificate in
    pub fn build(&self, buf: &mut [u8]) -> Option<usize> {
        if buf.len() < self.len {
            return None;
        }

        let mut pos = 0;

        // Copy Tag
        *buf.get_mut(pos)? = DER_SEQ_TAG;
        pos += 1;

        // Copy Length
        let mut sig_buf = [0u8; MAX_DER_SIZE];
        let sig_len = self.sig.to_der(&mut sig_buf)?;
        let len = self.tbs.len() + S::oid_der().len() + sig_len;

        if buf.len() < len + 4 {
            return None;
        }

        pos += der_encode_len(len, buf.get_mut(pos..)?)?;

        // Copy Value

        // Copy TBS DER
        buf.get_mut(pos..pos + self.tbs.len())?
            .copy_from_slice(self.tbs);
        pos += self.tbs.len();

        // Copy OID DER
        buf.get_mut(pos..pos + S::oid_der().len())?
            .copy_from_slice(S::oid_der());
        pos += S::oid_der().len();

        // Copy Signature DER
        buf.get_mut(pos..pos + sig_len)?
            .copy_from_slice(sig_buf.get(..sig_len)?);
        pos += sig_len;

        Some(pos)
    }

    /// Return the length of Certificate or Certificate Signing Request
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.len
    }

    // Compute length of the X509 certificate or cert signing request
    fn compute_len(tbs_len: usize, sig_der_len: usize, oid_len: usize) -> Option<usize> {
        let len = tbs_len + oid_len + sig_der_len;

        // Max Cert or CSR size is 4096 bytes
        let len_bytes = match len {
            0..=0x7f => 1_usize,
            0x80..=0xff => 2,
            0x100..=0xffff => 3,
            _ => None?,
        };

        //
        // Length of the CSR or Certificate
        //
        // Certificate is encoded as DER Sequence
        // TAG (1 byte) + LEN (len_bytes bytes) + len (Length of the sequence contents)
        Some(1 + len_bytes + len)
    }
}

// Type alias for ECDSA-384 Certificate Builder
pub type Ecdsa384CertBuilder<'a> = CertBuilder<'a, Ecdsa384Signature, 108>;
pub type Ecdsa384CsrBuilder<'a> = Ecdsa384CertBuilder<'a>;

// Type alias for Ml-Dsa87 Certificate Builder
pub type MlDsa87CertBuilder<'a> = CertBuilder<'a, Mldsa87Signature, 4627>;
pub type MlDsa87CsrBuilder<'a> = MlDsa87CertBuilder<'a>;
