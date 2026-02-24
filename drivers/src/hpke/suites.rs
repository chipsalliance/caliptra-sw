// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::HpkeAlgorithms;

/// The type of cipher suite
/// HPKE differentiates KEM & HPKE cipher suites.
pub enum CipherSuite {
    Kem(KemId),
    Hpke(HpkeCipherSuite),
}

impl CipherSuite {
    /// In HPKE, an ikm in a KEM algorithm (e.g. derive key pair) SHALL use the following for the
    /// suite-id: suite_id = concat("KEM", I2OSP(kem_id, 2))
    ///
    /// If it not used by a KEM algorithm, the IKM SHALL use the following for the suite-id:
    /// suite_id = concat(
    ///  "HPKE",
    ///  I2OSP(kem_id, 2),
    ///  I2OSP(kdf_id, 2),
    ///  I2OSP(aead_id, 2)
    /// )
    pub fn ikm_prefix(&self) -> &'static [u8] {
        match self {
            Self::Kem(_) => &b"KEM"[..],
            Self::Hpke(_) => &b"HPKE"[..],
        }
    }
}

impl AsRef<[u8]> for CipherSuite {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Kem(kem) => kem.as_ref(),
            Self::Hpke(hpke) => hpke.as_ref(),
        }
    }
}

/// Describes a HPKE CipherSuite.
pub struct HpkeCipherSuite {
    pub val: [u8; 6],
    pub alg: HpkeAlgorithms,
    pub kem: KemId,
}

impl HpkeCipherSuite {
    /// ML_KEM based ciphersuite
    pub const ML_KEM_1024: Self = Self::new(
        HpkeAlgorithms::ML_KEM_1024_HKDF_SHA384_AES_256_GCM,
        KemId::ML_KEM_1024,
        KdfId::HKDF_SHA384,
        AeadId::AES_256_GCM,
    );

    /// ML_KEM + P-384 based ciphersuite
    pub const ML_KEM_1024_P384: Self = Self::new(
        HpkeAlgorithms::ML_KEM_1024_ECDH_P384_HKDF_SHA384_AES_256_GCM,
        KemId::ML_KEM_1024_P384,
        KdfId::HKDF_SHA384,
        AeadId::AES_256_GCM,
    );

    /// P-384 based ciphersuite
    pub const P_384: Self = Self::new(
        HpkeAlgorithms::ECDH_P384_HKDF_SHA384_AES_256_GCM,
        KemId::P_384,
        KdfId::HKDF_SHA384,
        AeadId::AES_256_GCM,
    );
    const fn new(alg: HpkeAlgorithms, kem: KemId, kdf: KdfId, aead: AeadId) -> Self {
        let serialized_kem = kem.value as u8;
        let kdf = kdf.0 as u8;
        let aead = aead.0 as u8;
        Self {
            val: [0x0, serialized_kem, 0x0, kdf.to_be(), 0x0, aead.to_be()],
            alg,
            kem,
        }
    }
}

impl From<HpkeCipherSuite> for HpkeAlgorithms {
    fn from(value: HpkeCipherSuite) -> Self {
        value.alg
    }
}

impl AsRef<[u8]> for HpkeCipherSuite {
    fn as_ref(&self) -> &[u8] {
        &self.val
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
pub struct KemId {
    value: u16,
    /// Split out a serialized big-endian representation so we can use it in our derivations without
    /// any allocations.
    serialized_be: [u8; 2],
}
impl KemId {
    pub const ML_KEM_1024: Self = Self {
        value: 0x0042,
        serialized_be: [0x00, 0x42],
    };
    pub const ML_KEM_1024_P384: Self = Self {
        value: 0x0051,
        serialized_be: [0x00, 0x51],
    };
    pub const P_384: Self = Self {
        value: 0x0011,
        serialized_be: [0x00, 0x11],
    };
}

impl AsRef<[u8]> for KemId {
    fn as_ref(&self) -> &[u8] {
        &self.serialized_be
    }
}
