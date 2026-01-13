// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::HpkeAlgorithms;
use caliptra_error::CaliptraError;

/// Describes a HPKE CipherSuite.
pub struct CipherSuite {
    kem: KemId,
    kdf: KdfId,
    aead: AeadId,
}

impl CipherSuite {
    /// ML_KEM based ciphersuite
    pub const ML_KEM_1024: Self = Self {
        kem: KemId::ML_KEM_1024,
        kdf: KdfId::HKDF_SHA384,
        aead: AeadId::AES_256_GCM,
    };
}

impl TryFrom<CipherSuite> for HpkeAlgorithms {
    type Error = CaliptraError;
    fn try_from(value: CipherSuite) -> Result<Self, Self::Error> {
        match value {
            CipherSuite { kem, .. } if kem == KemId::ML_KEM_1024 => {
                Ok(HpkeAlgorithms::ML_KEM_1024_HKDF_SHA384_AES_256_GCM)
            }
            _ => Err(CaliptraError::RUNTIME_DRIVER_HPKE_CONVERT_INVALID_CIPHER_SUITE),
        }
    }
}

impl From<&CipherSuite> for [u8; 6] {
    fn from(value: &CipherSuite) -> Self {
        // Truncate u16 to u8. This is safe because the IDs only use the lower 8 bits.
        let kem = value.kem.0 as u8;
        let kdf = value.kdf.0 as u8;
        let aead = value.aead.0 as u8;
        [0x0, kem, 0x0, kdf.to_be(), 0x0, aead.to_be()]
    }
}

#[derive(Copy, Clone)]
pub struct KdfId(u16);
impl KdfId {
    pub const HKDF_SHA384: Self = Self(0x0002);
}

#[derive(Copy, Clone)]
pub struct AeadId(u16);
impl AeadId {
    pub const AES_256_GCM: Self = Self(0x0002);
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct KemId(u16);
impl KemId {
    pub const ML_KEM_1024: Self = Self(0x0042);
}

#[derive(Copy, Clone)]
pub struct KemIdExt([u8; 5]);
impl KemIdExt {
    /// ML-KEM-1024: KEM + 0x00 + 0x42 (hex: 4b454d0042)
    /// Source: https://www.ietf.org/archive/id/draft-ietf-hpke-pq-03.html#section-3-4.
    pub const ML_KEM_1024: Self = Self([0x4b, 0x45, 0x4d, 0x00, 0x42]);
}

impl AsRef<[u8]> for KemIdExt {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
