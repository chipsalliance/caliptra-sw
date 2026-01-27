// Licensed under the Apache-2.0 license

use caliptra_error::{CaliptraError, CaliptraResult};

use crate::{
    hkdf::{hkdf_expand_ext, hkdf_extract_ext},
    Array4x12, Array4x16, Hmac, HmacKey, HmacMode, HmacTag, Sha3, Trng,
};

use super::{
    aead::{Aes256GCM, EncryptionKey, Nonce},
    encryption_context::ExporterSecret,
    kem::{MlKem, SharedSecret},
    suites::{CipherSuite, HpkeCipherSuite},
};

use zerocopy::{Immutable, IntoBytes, KnownLayout};

/// Represents the key schedule context as described in https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02#name-creating-the-encryption-con
#[repr(C, packed)]
#[derive(IntoBytes, KnownLayout, Immutable)]
pub struct KeyScheduleContext {
    pub mode: u8,
    pub psk_id_hash: [u8; Hmac384::NH],
    pub info_id_hash: [u8; Hmac384::NH],
}

const _: () =
    assert!(size_of::<KeyScheduleContext>() == core::mem::size_of::<u8>() + (2 * Hmac384::NH));

/// Represents the HPKE Mode
///
/// Currently OCP LOCK only uses the `BASE` mode.
pub struct Mode(u8);

impl Mode {
    pub const BASE: Self = Self(0x0);
    // Only `BASE` is used by the spec.
    #[allow(dead_code)]
    pub const PSK: Self = Self(0x1);
    #[allow(dead_code)]
    pub const RSVD1: Self = Self(0x2);
    #[allow(dead_code)]
    pub const RSVD2: Self = Self(0x3);
}

/// The `L` parameter for HKDF expand
pub struct L(u16);

impl L {
    pub const fn new<const T: usize>() -> Self {
        const {
            assert!(T.div_ceil(Hmac384::NH) == 1, "The HKDF expand implementation assumes that N is 1. Either your L value is too large or you need to update the implementation")
        };
        Self(T as u16)
    }
}

/// Implements the functionality needed in HPKE for HMAC-384 KDF
pub struct Hmac384<'a> {
    hmac: &'a mut Hmac,
}

impl<'a> Hmac384<'a> {
    pub fn new(hmac: &'a mut Hmac) -> Self {
        Self { hmac }
    }
}

impl Hmac384<'_> {
    /// The hash length
    pub const NH: usize = 48;

    /// Implements labeled extract as described in https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02#section-4
    pub fn labeled_extract(
        &mut self,
        trng: &mut Trng,
        suite_id: &CipherSuite,
        salt: &[u8],
        label: &[u8],
        ikm: &[u8],
    ) -> CaliptraResult<[u8; Hmac384::NH]> {
        let labeled_ikm = [
            &b"HPKE-v1"[..],
            suite_id.ikm_prefix(),
            suite_id.as_ref(),
            label,
            ikm,
        ];
        let mut prk = Array4x12::default();
        hkdf_extract_ext(
            self.hmac,
            labeled_ikm.iter(),
            salt,
            trng,
            HmacTag::Array4x12(&mut prk),
            HmacMode::Hmac384,
        )?;
        Ok(prk.into())
    }

    /// Implements labeled expand as described in https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02#section-4
    #[allow(clippy::too_many_arguments)]
    pub fn labeled_expand(
        &mut self,
        trng: &mut Trng,
        suite_id: &CipherSuite,
        prk: HmacKey,
        label: &[u8],
        info: &[u8],
        l: L,
        okm: HmacTag,
    ) -> CaliptraResult<()> {
        let labeled_info = [
            &l.0.to_be_bytes(),
            &b"HPKE-v1"[..],
            suite_id.ikm_prefix(),
            suite_id.as_ref(),
            label,
            info,
        ];
        hkdf_expand_ext(
            self.hmac,
            prk,
            labeled_info.iter(),
            trng,
            okm,
            HmacMode::Hmac384,
        )
    }

    /// Implements "CombineSecrets_TwoStage" from https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02#section-5.1.
    pub fn combine_secrets<const NSECRET: usize>(
        &mut self,
        trng: &mut Trng,
        suite_id: HpkeCipherSuite,
        shared_secret: SharedSecret<NSECRET>,
        info: &[u8],
    ) -> CaliptraResult<(EncryptionKey, Nonce, ExporterSecret)> {
        let suite_id = CipherSuite::Hpke(suite_id);

        let psk_id_hash = self.labeled_extract(trng, &suite_id, b"", b"psk_id_hash", &[])?;
        let info_id_hash = self.labeled_extract(trng, &suite_id, b"", b"info_hash", info)?;
        let key_schedule_context = KeyScheduleContext {
            mode: Mode::BASE.0,
            psk_id_hash,
            info_id_hash,
        };
        let key_schedule_context = key_schedule_context.as_bytes();

        let secret =
            self.labeled_extract(trng, &suite_id, shared_secret.as_ref(), b"secret", &[])?;
        let secret = Array4x12::from(secret);

        let prk = HmacKey::Array4x12(&secret);
        let mut key = Array4x12::default();
        self.labeled_expand(
            trng,
            &suite_id,
            prk,
            b"key",
            key_schedule_context,
            L::new::<{ Aes256GCM::NK }>(),
            HmacTag::Array4x12(&mut key),
        )?;

        let mut base_nonce = Array4x12::default();
        self.labeled_expand(
            trng,
            &suite_id,
            prk,
            b"base_nonce",
            key_schedule_context,
            L::new::<{ Aes256GCM::NN }>(),
            HmacTag::Array4x12(&mut base_nonce),
        )?;

        let mut exporter_secret = Array4x12::default();
        self.labeled_expand(
            trng,
            &suite_id,
            prk,
            b"exp",
            key_schedule_context,
            L::new::<{ Hmac384::NH }>(),
            HmacTag::Array4x12(&mut exporter_secret),
        )?;

        Ok((key.into(), base_nonce.into(), exporter_secret.into()))
    }

    /// Implements "ExtractAndExpand_TwoStage" from https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02#section-4.1.
    pub fn extract_and_expand(
        &mut self,
        trng: &mut Trng,
        suite_id: CipherSuite,
        dh: &[u8],
        enc: &[u8],
        pk_rm: &[u8],
        l: L,
    ) -> CaliptraResult<SharedSecret<{ Hmac384::NH }>> {
        let eae_prk = self.labeled_extract(trng, &suite_id, b"", b"eae_prk", dh)?;
        let eae_prk = Array4x12::from(eae_prk);

        // Instead of calling labeled expand, we re-implement it here to avoid any allocations.
        let labeled_info = [
            &l.0.to_be_bytes(),
            &b"HPKE-v1"[..],
            suite_id.ikm_prefix(),
            suite_id.as_ref(),
            &b"shared_secret"[..],
            enc,
            pk_rm,
        ];

        let mut okm = Array4x12::default();
        hkdf_expand_ext(
            self.hmac,
            HmacKey::Array4x12(&eae_prk),
            labeled_info.iter(),
            trng,
            HmacTag::Array4x12(&mut okm),
            HmacMode::Hmac384,
        )?;

        Ok(SharedSecret::<{ Hmac384::NH }>::from(okm))
    }
}

/// HPKE `DeriveKeyPair` uses a SHAKE256 KDF to derive a 64 byte seed for ML-KEM.
///
/// https://www.ietf.org/archive/id/draft-ietf-hpke-pq-03.html#section-3
pub struct Shake256<const NSK: usize>;

impl Shake256<{ MlKem::NSK }> {
    /// Implements labeled derive as described in
    /// https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-02#name-cryptographic-dependencies.
    pub fn labeled_derive(
        shake: &mut Sha3,
        suite_id: CipherSuite,
        ikm: &[u8],
        label: &[u8],
        context: &[u8],
    ) -> CaliptraResult<[u8; MlKem::NSK]> {
        let label_len = u16::try_from(label.len())
            .map_err(|_| CaliptraError::RUNTIME_DRIVER_HPKE_SHAKE_INVALID_LABEL_LEN)?
            .to_be_bytes();

        // Truncate NSK to a u16.
        // `MlKem::NSK` is `64` so this will always fit.
        let l = (MlKem::NSK as u16).to_be_bytes();

        let output: Array4x16 = {
            let mut digest_op = shake.shake256_digest_init()?;
            digest_op.update(ikm)?;
            digest_op.update(b"HPKE-v1")?;
            digest_op.update(suite_id.ikm_prefix())?;
            digest_op.update(suite_id.as_ref())?;
            digest_op.update(&label_len)?;
            digest_op.update(label)?;
            digest_op.update(&l)?;
            digest_op.update(context)?;
            digest_op.finalize()?
        };
        Ok(output.into())
    }
}
