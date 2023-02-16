/*++

Licensed under the Apache-2.0 license.

File Name:

    cert_bldr.rs

Abstract:

    X509 API to construct Certificate or Certificate Signing Request
    from "To Be Signed" blob and ECDSA-384 Signature.

--*/

pub type Ecdsa384CsrBuilder<'a> = Ecdsa384CertBuilder<'a>;

/// MAX Signature length
const MAX_ECDSA384_SIG_LEN: usize = 108;

/// DER Integer Tag
const DER_INTEGER_TAG: u8 = 0x02;

/// DER Bit String Tag
const DER_BIT_STR_TAG: u8 = 0x03;

/// DER Sequence Tag
const DER_SEQ_TAG: u8 = 0x30;

/// ECDSA-384 Signature
#[derive(Debug)]
pub struct Ecdsa384Signature {
    /// Signature R-Coordinate
    pub r: [u8; Self::ECDSA_COORD_LEN],

    /// Signature S-Coordinate
    pub s: [u8; Self::ECDSA_COORD_LEN],
}

impl Default for Ecdsa384Signature {
    /// Returns the "default value" for a type.
    fn default() -> Self {
        Self {
            r: [0u8; Self::ECDSA_COORD_LEN],
            s: [0u8; Self::ECDSA_COORD_LEN],
        }
    }
}

impl Ecdsa384Signature {
    /// ECDSA Coordinate length
    const ECDSA_COORD_LEN: usize = 48;

    /// Convert the signature to DER format
    fn to_der(&self) -> ([u8; MAX_ECDSA384_SIG_LEN], usize) {
        //
        // Encode Signature R Coordinate
        //
        // r_uint_len = TAG (1 byte) + LEN (1 byte) + R-Coordinate Len (48 bytes)
        //
        // R is unsigned so in DER encoding if the msb of first byte is set we
        // need to add a leading zero
        // if r[0] > 127 -> r_uint_len +1
        //
        let r_uint_len = 2 + self.r.len() + if self.r[0] > 127 { 1 } else { 0 };

        //
        // Encode Signature S Coordinate
        //
        // s_uint_len = TAG (1 byte) + LEN (1 byte) + S-Coordinate Len (48 bytes)
        //
        // S is unsigned so in DER encoding if the msb of first byte is set we
        // need to add a leading zero
        // if s[0] > 127 -> s_uint_len +1
        //
        let s_uint_len = 2 + self.s.len() + if self.s[0] > 127 { 1 } else { 0 };

        //
        // Signature DER Sequence encoding
        //
        // sig_seq_len = TAG (1 byte) + LEN (1 byte) + r_uint_len + s_uint_len
        //
        let sig_seq_len = 2 + r_uint_len + s_uint_len;

        //
        // Signature BIT String len encoding
        //
        // len = TAG (1 byte) + LEN (1 byte) + UNUSED_BITS(1 byte) + sig_seq_len
        let _ = 3 + sig_seq_len;

        let mut buf = [0u8; MAX_ECDSA384_SIG_LEN];
        let mut pos = 0;

        // Encode Signature DER Bit String
        buf[pos] = DER_BIT_STR_TAG;
        pos += 1;
        buf[pos] = (1 + sig_seq_len) as u8;
        pos += 1;
        buf[pos] = 0x0;
        pos += 1;

        // Encode Signature DER Sequence
        buf[pos] = DER_SEQ_TAG;
        pos += 1;
        buf[pos] = (r_uint_len + s_uint_len) as u8;
        pos += 1;

        // Encode R-Coordinate
        buf[pos] = DER_INTEGER_TAG;
        pos += 1;

        if self.r[0] > 127 {
            buf[pos] = (self.r.len() + 1) as u8;
            // Add leading zero
            buf[pos + 1] = 0x00;
            pos += 2;
        } else {
            buf[pos] = self.r.len() as u8;
            pos += 1;
        }
        buf[pos..pos + self.r.len()].copy_from_slice(&self.r);
        pos += self.r.len();

        // Encode S-Coordinate
        buf[pos] = DER_INTEGER_TAG;
        pos += 1;
        if self.s[0] > 127 {
            buf[pos] = (self.s.len() + 1) as u8;
            // Add leading zero
            buf[pos + 1] = 0x00;
            pos += 2;
        } else {
            buf[pos] = self.s.len() as u8;
            pos += 1;
        }
        buf[pos..pos + self.s.len()].copy_from_slice(&self.s);
        pos += self.s.len();

        (buf, pos)
    }
}

/// ECDSA-384 Certificate Builder
#[derive(Debug)]
pub struct Ecdsa384CertBuilder<'a> {
    /// DER encoded To be signed portion
    tbs: &'a [u8],

    /// DER encoded Signature
    sig: [u8; MAX_ECDSA384_SIG_LEN],

    /// DER encoded Signature length
    sig_len: usize,

    /// Length of the signed Cert/CSR
    len: usize,
}

impl<'a> Ecdsa384CertBuilder<'a> {
    // DER Encoded Sequence with ecdsa-with-SHA384 OID
    const OID_DER: [u8; 12] = [
        0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03,
    ];

    /// Create an instance of `Ecdsa384CertBuilder`
    ///
    /// # Arguments
    ///
    /// * `tbs` - DER encoded To be signed portion
    /// * `sig` - Signature of the To be signed portion
    pub fn new(tbs: &'a [u8], sig: &Ecdsa384Signature) -> Option<Self> {
        let (sig, sig_len) = sig.to_der();
        let len = Self::compute_len(tbs.len(), sig_len)?;
        Some(Self {
            tbs,
            sig,
            sig_len,
            len,
        })
    }

    /// Build the Certificate or Certificate Signing Request
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to construct the certificate in
    pub fn build(&self, buf: &mut [u8]) -> Option<()> {
        if buf.len() < self.len {
            None?;
        }

        let mut pos = 0;

        // Copy Tag
        buf[pos] = DER_SEQ_TAG;
        pos += 1;

        // Copy Length
        let len = self.tbs.len() + Self::OID_DER.len() + self.sig_len;
        match len {
            0..=127 => {
                buf[pos] = len as u8;
                pos += 1;
            }
            128..=255 => {
                buf[pos] = 0x81;
                buf[pos + 1] = len as u8;
                pos += 2;
            }
            256..=4096 => {
                buf[pos] = 0x82;
                buf[pos + 1] = (len >> u8::BITS) as u8;
                buf[pos + 2] = (len as u8) & u8::MAX;
                pos += 3;
            }
            _ => None?,
        }

        // Copy Value

        // Copy TBS DER
        buf[pos..pos + self.tbs.len()].copy_from_slice(self.tbs);
        pos += self.tbs.len();

        // Copy OID DER
        buf[pos..pos + Self::OID_DER.len()].copy_from_slice(&Self::OID_DER);
        pos += Self::OID_DER.len();

        // Copy Signature DER
        buf[pos..pos + self.sig_len].copy_from_slice(&self.sig[..self.sig_len]);

        Some(())
    }

    /// Return the length of Certificate or Certificate Signing Request
    pub fn len(&self) -> usize {
        self.len
    }

    // Compute length of the X509 certificate or cert signing request
    fn compute_len(tbs_len: usize, sig_der_len: usize) -> Option<usize> {
        let len = tbs_len + Self::OID_DER.len() + sig_der_len;

        // Max Cert or CSR size is 4096 bytes
        let len_bytes = match len {
            0..=127 => 1_usize,
            128..=255 => 2,
            256..=4096 => 3,
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
