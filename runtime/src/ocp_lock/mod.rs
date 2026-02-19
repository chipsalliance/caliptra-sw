// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{CommandId, WrappedKey, OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN};
use caliptra_cfi_lib_git::{cfi_assert, cfi_assert_eq};
use caliptra_common::keyids::ocp_lock::{
    KEY_ID_EPK, KEY_ID_HEK, KEY_ID_LOCKED_MPK_ENCRYPTION_KEY, KEY_ID_MDK, KEY_ID_MEK_SECRETS,
    KEY_ID_VEK,
};
use caliptra_drivers::{
    cmac_kdf, hmac_kdf,
    hpke::{
        aead::Aes256GCM, suites::HpkeCipherSuite, EncryptionContext, HpkeContext, HpkeContextIter,
        HpkeHandle, Receiver,
    },
    preconditioned_aes::{preconditioned_aes_decrypt, preconditioned_aes_encrypt},
    sha2_512_384::Sha2DigestOpTrait,
    Abr, Aes, AesKey, AesOperation, Array4x12, Dma, Hmac, HmacKey, HmacMode, HmacTag, KeyReadArgs,
    KeyUsage, KeyVault, KeyWriteArgs, LEArray4x16, LEArray4x8, OcpLockFlags,
    OcpLockMetadataFirmware, Sha2_512_384, Sha3, SocIfc, Trng,
};
use caliptra_error::{CaliptraError, CaliptraResult};

use enable_mpk::EnableMpkCmd;
use endorse_hpke_pubkey::EndorseHpkePubkeyCmd;
use enumerate_hpke_handles::EnumerateHpkeHandles;
use generate_mek::GenerateMekCmd;
use generate_mpk::GenerateMpkCmd;
use rewrap_mpk::RewrapMpkCmd;
use rotate_hpke_key::RotateHpkeKeyCmd;
use test_access_key::TestAccessKeyCmd;
use zerocopy::{transmute, FromBytes, Immutable, IntoBytes, KnownLayout};
use zeroize::ZeroizeOnDrop;

mod clear_key_cache;
mod derive_mek;
mod enable_mpk;
mod endorse_hpke_pubkey;
mod enumerate_hpke_handles;
mod generate_mek;
mod generate_mpk;
mod get_algorithms;
mod get_status;
mod initialize_mek_secret;
mod mix_mpk;
mod rewrap_mpk;
mod rotate_hpke_key;
mod test_access_key;
mod unload_mek;

pub use clear_key_cache::ClearKeyCacheCmd;
pub use derive_mek::DeriveMekCmd;
pub use get_algorithms::GetAlgorithmsCmd;
pub use get_status::GetStatusCmd;
pub use initialize_mek_secret::InitializeMekSecretCmd;
pub use mix_mpk::MixMpkCmd;
pub use unload_mek::UnloadMekCmd;

use crate::{Drivers, PauserPrivileges};

const ACCESS_KEY_LEN: usize = 32;

// TODO(clundin): Use a shared generic base for the WrappedKey types?

/// Represents the VEK type from OCP LOCK.
/// The VEK is used to encrypt an MPK. This transitions the MPK to the "enabled" state and it can
/// be mixed into an MEK.
///
/// The VEK is erased on cold reset
pub struct Vek;

impl Vek {
    /// Generate `Vek` per OCP LOCK v1.0rc2 figure 5 if `Vek` has not yet been generated.
    ///
    /// On success updates `OcpLockMetadataFirmware` to store VEK state
    /// in persistent_data.
    fn generate(
        hmac: &mut Hmac,
        trng: &mut Trng,
        state: &mut OcpLockMetadataFirmware,
    ) -> CaliptraResult<()> {
        if state.flags.contains(OcpLockFlags::VEK_AVAILABLE) {
            return Ok(());
        }

        let context = trng.generate()?;
        hmac_kdf(
            hmac,
            HmacKey::Key(KeyReadArgs::new(KEY_ID_HEK)),
            Vek::KDF_LABEL,
            Some(context.as_bytes()),
            trng,
            HmacTag::Key(KeyWriteArgs {
                id: KEY_ID_VEK,
                usage: KeyUsage::default().set_hmac_key_en(),
            }),
            HmacMode::Hmac512,
        )?;
        state.flags.set(OcpLockFlags::VEK_AVAILABLE, true);
        Ok(())
    }
}

impl Vek {
    const KDF_LABEL: &'static [u8] = b"ocp_lock_vek";
}

/// Represents the SEK type from OCP LOCK.
#[derive(IntoBytes, KnownLayout, Immutable, ZeroizeOnDrop)]
pub struct Sek(pub [u8; 32]);

use core::marker::PhantomData;

/// Represents the DPK type from OCP LOCK.
#[derive(IntoBytes, KnownLayout, Immutable, ZeroizeOnDrop)]
pub struct Dpk(pub [u8; 32]);

/// This trait is used to statically prevent mixing access keys.
pub trait AccessKeyState {}

/// The current access key
pub struct Current;

/// The new access key
pub struct New;

impl AccessKeyState for Current {}
impl AccessKeyState for New {}

/// Represents an encrypted Access Key
pub struct EncryptedAccessKey<K>
where
    K: AccessKeyState,
{
    pub tag: [u8; Aes256GCM::NT],
    pub ciphertext: [u8; ACCESS_KEY_LEN],
    _state: PhantomData<K>,
}

impl<K> EncryptedAccessKey<K>
where
    K: AccessKeyState,
{
    pub fn new(tag: [u8; Aes256GCM::NT], ciphertext: [u8; ACCESS_KEY_LEN]) -> Self {
        Self {
            tag,
            ciphertext,
            _state: PhantomData,
        }
    }
}

/// Represents the Access Key supplied by the drive firwmare.
#[repr(transparent)]
#[derive(IntoBytes, KnownLayout, Immutable, ZeroizeOnDrop)]
pub struct AccessKey<K>
where
    K: AccessKeyState,
{
    key: [u8; ACCESS_KEY_LEN],
    _kind: PhantomData<K>,
}

impl<K> AccessKey<K>
where
    K: AccessKeyState,
{
    const KEY_LEN: usize = ACCESS_KEY_LEN;
    pub fn from_ciphertext(
        aes: &mut Aes,
        trng: &mut Trng,
        ctx: &mut EncryptionContext<Receiver>,
        aad: &[u8],
        tag: &[u8; Aes256GCM::NT],
        ct: &[u8; ACCESS_KEY_LEN],
    ) -> CaliptraResult<Self> {
        let mut key = [0; ACCESS_KEY_LEN];
        ctx.open(aes, trng, aad, tag, ct, &mut key)?;
        Ok(Self {
            key,
            _kind: PhantomData,
        })
    }
}

/// Represents an MPK type from OCP LOCK.
#[derive(IntoBytes, KnownLayout, Immutable, ZeroizeOnDrop)]
pub struct Mpk([u8; 32]);

impl Mpk {
    fn generate(trng: &mut Trng) -> CaliptraResult<Self> {
        let seed: [u8; 64] = {
            let seed = trng.generate16()?;
            transmute!(seed)
        };
        let mut key = [0; 32];
        key.clone_from_slice(&seed[..32]);
        Ok(Self(key))
    }
}

impl AsMut<[u8; 32]> for Mpk {
    fn as_mut(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }
}

/// Represents the Intermediate MEK Secret from OCP LOCK.
/// This is constructed from the EPK + DPK.
///
/// NOTE: MPKs will be mixed into `IntermediateMekSecret`
pub struct IntermediateMekSecret;

/// Represents a `WrappedMek`
///
/// OCP LOCK version 1.0 RC2, Section "Common mailbox types".
pub struct WrappedMek {
    salt: [u8; 12],
    iv: [u8; 12],
    encrypted_key: [u8; Self::KEY_LEN],
    tag: [u8; Aes256GCM::NT],
}

#[derive(IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct WrappedMekAad {
    key_type: u16,
    metadata_len: u32,
}
const _: () = assert!(
    core::mem::size_of::<WrappedMekAad>()
        == core::mem::size_of::<u16>() + core::mem::size_of::<u32>()
);

impl WrappedMek {
    const KEY_TYPE: u16 = 0x03;
    const KEY_LEN: usize = 64;
}

impl TryFrom<WrappedMek> for WrappedKey {
    type Error = CaliptraError;
    fn try_from(value: WrappedMek) -> Result<Self, Self::Error> {
        let mut ciphertext_and_auth_tag = [0; 80];
        ciphertext_and_auth_tag[..WrappedMek::KEY_LEN].copy_from_slice(&value.encrypted_key);
        ciphertext_and_auth_tag[WrappedMek::KEY_LEN..].copy_from_slice(&value.tag);

        Ok(Self {
            key_type: WrappedMek::KEY_TYPE,
            salt: value.salt,
            metadata_len: 0,
            key_len: WrappedMek::KEY_LEN as u32,
            iv: value.iv,
            ciphertext_and_auth_tag,
            ..Default::default()
        })
    }
}

/// Represents a `LockedMpk`
///
/// OCP LOCK version 1.0 RC2, Section "Common mailbox types".
pub struct LockedMpk {
    salt: [u8; 12],
    iv: [u8; 12],
    encrypted_key: [u8; Self::KEY_LEN],
    tag: [u8; Aes256GCM::NT],
    metadata: [u8; OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN],
    metadata_len: u32,
}

impl LockedMpk {
    const KEY_TYPE: u16 = 0x01;
    const KEY_LEN: usize = 32;
}

#[derive(IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct LockedMpkAad {
    key_type: u16,
    metadata_len: u32,
    metadata: [u8; OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN],
}

impl LockedMpkAad {
    fn new(metadata: &[u8]) -> CaliptraResult<Self> {
        let mut metadata_aad = [0; OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN];
        metadata_aad
            .get_mut(..metadata.len())
            .ok_or(CaliptraError::RUNTIME_OCP_LOCK_DESERIALIZE_METADATA_FAILURE)?
            .clone_from_slice(metadata);
        Ok(Self {
            key_type: LockedMpk::KEY_TYPE,
            metadata_len: metadata.len() as u32,
            metadata: metadata_aad,
        })
    }

    fn serialize(&self) -> CaliptraResult<&[u8]> {
        self.as_bytes()
            .get(..size_of::<u16>() + size_of::<u32>() + self.metadata_len as usize)
            .ok_or(CaliptraError::RUNTIME_OCP_LOCK_SERIALIZE_METADATA_FAILURE)
    }
}

impl TryFrom<LockedMpk> for WrappedKey {
    type Error = CaliptraError;
    fn try_from(value: LockedMpk) -> Result<Self, Self::Error> {
        let mut ciphertext_and_auth_tag = [0; 80];
        ciphertext_and_auth_tag[..LockedMpk::KEY_LEN].copy_from_slice(&value.encrypted_key);
        ciphertext_and_auth_tag[LockedMpk::KEY_LEN..LockedMpk::KEY_LEN + Aes256GCM::NT]
            .copy_from_slice(&value.tag);

        Ok(Self {
            key_type: LockedMpk::KEY_TYPE,
            salt: value.salt,
            metadata_len: value.metadata_len,
            key_len: LockedMpk::KEY_LEN as u32,
            iv: value.iv,
            ciphertext_and_auth_tag,
            metadata: value.metadata,
            ..Default::default()
        })
    }
}

impl TryFrom<&WrappedKey> for LockedMpk {
    type Error = CaliptraError;
    fn try_from(value: &WrappedKey) -> Result<Self, Self::Error> {
        if value.key_type != LockedMpk::KEY_TYPE {
            return Err(CaliptraError::RUNTIME_OCP_LOCK_INVALID_WRAPPED_KEY_TYPE);
        }
        let mut encrypted_key = [0; LockedMpk::KEY_LEN];
        encrypted_key.copy_from_slice(&value.ciphertext_and_auth_tag[..LockedMpk::KEY_LEN]);
        let mut tag = [0; Aes256GCM::NT];
        tag.copy_from_slice(
            &value.ciphertext_and_auth_tag[LockedMpk::KEY_LEN..LockedMpk::KEY_LEN + Aes256GCM::NT],
        );

        Ok(Self {
            salt: value.salt,
            iv: value.iv,
            encrypted_key,
            tag,
            metadata: value.metadata,
            metadata_len: value.metadata_len,
        })
    }
}

/// Represents an `EnabledMpk`
///
/// OCP LOCK version 1.0 RC2, Section "Common mailbox types".
pub struct EnabledMpk {
    salt: [u8; 12],
    iv: [u8; 12],
    encrypted_key: [u8; Self::KEY_LEN],
    tag: [u8; Aes256GCM::NT],
    metadata: [u8; OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN],
    metadata_len: u32,
}

impl EnabledMpk {
    const KEY_TYPE: u16 = 0x02;
    const KEY_LEN: usize = 32;
    const KDF_LABEL: &'static [u8] = b"ocp_lock_enabled_mpk";
}

impl From<&LockedMpk> for EnabledMpk {
    fn from(value: &LockedMpk) -> Self {
        Self {
            salt: value.salt,
            iv: value.iv,
            encrypted_key: value.encrypted_key,
            tag: value.tag,
            metadata: value.metadata,
            metadata_len: value.metadata_len,
        }
    }
}

impl TryFrom<EnabledMpk> for WrappedKey {
    type Error = CaliptraError;
    fn try_from(value: EnabledMpk) -> Result<Self, Self::Error> {
        let mut ciphertext_and_auth_tag = [0; 80];
        ciphertext_and_auth_tag[..EnabledMpk::KEY_LEN].copy_from_slice(&value.encrypted_key);
        ciphertext_and_auth_tag[EnabledMpk::KEY_LEN..EnabledMpk::KEY_LEN + Aes256GCM::NT]
            .copy_from_slice(&value.tag);

        Ok(Self {
            key_type: EnabledMpk::KEY_TYPE,
            salt: value.salt,
            metadata_len: value.metadata_len,
            key_len: EnabledMpk::KEY_LEN as u32,
            iv: value.iv,
            ciphertext_and_auth_tag,
            metadata: value.metadata,
            ..Default::default()
        })
    }
}

impl TryFrom<&WrappedKey> for EnabledMpk {
    type Error = CaliptraError;
    fn try_from(value: &WrappedKey) -> Result<Self, Self::Error> {
        if value.key_type != EnabledMpk::KEY_TYPE {
            return Err(CaliptraError::RUNTIME_OCP_LOCK_INVALID_WRAPPED_KEY_TYPE);
        }
        let mut encrypted_key = [0; EnabledMpk::KEY_LEN];
        encrypted_key.copy_from_slice(&value.ciphertext_and_auth_tag[..EnabledMpk::KEY_LEN]);
        let mut tag = [0; Aes256GCM::NT];
        tag.copy_from_slice(
            &value.ciphertext_and_auth_tag
                [EnabledMpk::KEY_LEN..EnabledMpk::KEY_LEN + Aes256GCM::NT],
        );

        Ok(Self {
            salt: value.salt,
            iv: value.iv,
            encrypted_key,
            tag,
            metadata: value.metadata,
            metadata_len: value.metadata_len,
        })
    }
}

#[derive(IntoBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
pub struct EnabledMpkAad {
    key_type: u16,
    metadata_len: u32,
    metadata: [u8; OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN],
}

impl EnabledMpkAad {
    fn new(metadata: &[u8]) -> CaliptraResult<Self> {
        let mut metadata_aad = [0; OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN];
        metadata_aad
            .get_mut(..metadata.len())
            .ok_or(CaliptraError::RUNTIME_OCP_LOCK_DESERIALIZE_METADATA_FAILURE)?
            .clone_from_slice(metadata);
        Ok(Self {
            key_type: EnabledMpk::KEY_TYPE,
            metadata_len: metadata.len() as u32,
            metadata: metadata_aad,
        })
    }

    fn serialize(&self) -> CaliptraResult<&[u8]> {
        self.as_bytes()
            .get(..size_of::<u16>() + size_of::<u32>() + self.metadata_len as usize)
            .ok_or(CaliptraError::RUNTIME_OCP_LOCK_SERIALIZE_METADATA_FAILURE)
    }
}

impl From<LockedMpkAad> for EnabledMpkAad {
    fn from(value: LockedMpkAad) -> Self {
        Self {
            key_type: EnabledMpk::KEY_TYPE,
            metadata: value.metadata,
            metadata_len: value.metadata_len,
        }
    }
}

/// An `MEK` encrypted by the `MDK`.
#[derive(ZeroizeOnDrop)]
pub struct SingleEncryptedMek {
    key: [u8; 64],
}

impl AsRef<[u8]> for SingleEncryptedMek {
    fn as_ref(&self) -> &[u8] {
        &self.key
    }
}

/// A `MEK`
#[derive(ZeroizeOnDrop)]
pub struct Mek {
    key: [u8; 64],
}

impl Mek {
    /// Generate a new `Mek`
    pub fn generate(trng: &mut Trng) -> CaliptraResult<Self> {
        let key = {
            let seed = trng.generate16()?;
            transmute!(seed)
        };
        Ok(Self { key })
    }

    /// Consumes `Mek` and encrypts `Mek` with the `Mdk` and returns a `SingleEncryptedMek`
    pub fn encrypt(self, aes: &mut Aes) -> CaliptraResult<SingleEncryptedMek> {
        let mut output = [0; 64];
        aes.aes_256_ecb(
            AesKey::KV(KeyReadArgs::new(KEY_ID_MDK)),
            AesOperation::Encrypt,
            &self.key,
            &mut output,
        )?;
        Ok(SingleEncryptedMek { key: output })
    }
}

impl IntermediateMekSecret {
    /// Consumes `Self` to produce a derived `MekSecret`.
    fn derive_mek_secret<'a>(
        self,
        hmac: &mut Hmac,
        trng: &mut Trng,
        kv: &'a mut KeyVault,
    ) -> CaliptraResult<MekSecret<'a>> {
        hmac_kdf(
            hmac,
            HmacKey::Key(KeyReadArgs::new(KEY_ID_MEK_SECRETS)),
            b"ocp_lock_derived_mek",
            None,
            trng,
            HmacTag::Key(KeyWriteArgs::new(
                KEY_ID_MEK_SECRETS,
                KeyUsage::default().set_aes_key_en(),
            )),
            HmacMode::Hmac512,
        )?;
        Ok(MekSecret { kv })
    }

    /// Consumes `Self` to produce a `MekSecret`
    /// The `MekSecret` will be used encrypt other secrets
    fn wrapping_mek_secret<'a>(
        self,
        hmac: &mut Hmac,
        trng: &mut Trng,
        kv: &'a mut KeyVault,
    ) -> CaliptraResult<MekSecret<'a>> {
        hmac_kdf(
            hmac,
            HmacKey::Key(KeyReadArgs::new(KEY_ID_MEK_SECRETS)),
            b"ocp_lock_wrapped_mek",
            None,
            trng,
            HmacTag::Key(KeyWriteArgs::new(
                KEY_ID_MEK_SECRETS,
                KeyUsage::default().set_hmac_key_en(),
            )),
            HmacMode::Hmac512,
        )?;
        Ok(MekSecret { kv })
    }

    /// Mixes `mpk` into `Self`
    fn mix_mpk(&mut self, hmac: &mut Hmac, trng: &mut Trng, mpk: Mpk) -> CaliptraResult<()> {
        hmac_kdf(
            hmac,
            HmacKey::Key(KeyReadArgs::new(KEY_ID_MEK_SECRETS)),
            b"ocp_lock_mix_mpk",
            Some(mpk.as_bytes()),
            trng,
            HmacTag::Key(KeyWriteArgs::new(
                KEY_ID_MEK_SECRETS,
                KeyUsage::default().set_hmac_key_en(),
            )),
            HmacMode::Hmac512,
        )?;
        Ok(())
    }
}

/// Represents the MEK Secret from OCP LOCK.
/// This is constructed from `IntermediateMekSecret`
pub struct MekSecret<'a> {
    kv: &'a mut KeyVault,
}

impl MekSecret<'_> {
    /// Consumes `Self` to produce a `MekSeed`.
    /// NOTE: This will erase the `MEK_SECRET` key vault.
    fn derive_mek_seed(self, aes: &mut Aes) -> CaliptraResult<MekSeed> {
        Ok(MekSeed(cmac_kdf(
            aes,
            AesKey::KV(KeyReadArgs::new(KEY_ID_MEK_SECRETS)),
            b"ocp_lock_mek_seed",
            None,
            4,
        )?))
    }

    /// Consumes `Self` to produce a `SingleEncryptedMek`.
    /// NOTE: This will erase the `MEK_SECRET` key vault.
    fn generate_mek(
        self,
        aes: &mut Aes,
        trng: &mut Trng,
        hmac: &mut Hmac,
    ) -> CaliptraResult<WrappedMek> {
        let mek = Mek::generate(trng)?;
        let mek = mek.encrypt(aes)?;

        let aad = WrappedMekAad {
            key_type: WrappedMek::KEY_TYPE,
            metadata_len: 0,
        };
        let aad = aad.as_bytes();

        let mut encrypted_key = [0; WrappedMek::KEY_LEN];
        let result = preconditioned_aes_encrypt(
            aes,
            hmac,
            trng,
            self.kv,
            HmacKey::Key(KeyReadArgs::new(KEY_ID_MEK_SECRETS)),
            AesKey::KV(KeyReadArgs::new(KEY_ID_MEK_SECRETS)),
            b"wrapped_mek",
            aad,
            mek.as_ref(),
            &mut encrypted_key,
        )?;

        Ok(WrappedMek {
            encrypted_key,
            salt: result.salt.into(),
            iv: result.iv.into(),
            tag: result.tag.into(),
        })
    }
}

impl Drop for MekSecret<'_> {
    // From Spec:
    //   > Held in the Key Vault and zeroized after each use.
    fn drop(&mut self) {
        // We don't set a write or use lock so this should never fail.
        let _ = self.kv.erase_key(KEY_ID_MEK_SECRETS);
    }
}

/// Checksum of an `Mek`
#[derive(Default, IntoBytes, KnownLayout, Immutable, ZeroizeOnDrop, PartialEq, Eq)]
pub struct MekChecksum(pub [u8; 16]);

/// Represents the MEK Seed from OCP LOCK.
/// This is constructed from `MekSecret`
#[derive(IntoBytes, KnownLayout, Immutable, ZeroizeOnDrop)]
pub struct MekSeed(LEArray4x16);

impl AsRef<LEArray4x16> for MekSeed {
    fn as_ref(&self) -> &LEArray4x16 {
        &self.0
    }
}

impl MekSeed {
    fn checksum(&self, aes: &mut Aes) -> CaliptraResult<MekChecksum> {
        let key = self
            .0
            .as_bytes()
            .get(0..32)
            .ok_or(CaliptraError::RUNTIME_OCP_LOCK_INVALID_MEK_SEED_SIZE)?;
        let key = LEArray4x8::ref_from_bytes(key)
            .map_err(|_| CaliptraError::RUNTIME_OCP_LOCK_INVALID_MEK_SEED_SIZE)?;
        let mut output = [0; 16];
        aes.aes_256_ecb(
            AesKey::Array(key),
            AesOperation::Encrypt,
            &[0; 16],
            &mut output,
        )?;
        Ok(MekChecksum(output))
    }
}

/// Represents the EPK type from OCP LOCK.
/// This is constructed from the HEK + SEK.
struct Epk<'a> {
    kv: &'a mut KeyVault,
}

impl<'a> Epk<'a> {
    const EPK_LABEL: &'static [u8] = b"ocp_lock_epk";
    const INTERMEDIATE_MEK_SECRET_LABEL: &'static [u8] = b"ocp_lock_intermediate_mek_secret";
    const LOCKED_MPK_ENCRYPTION_KEY_LABEL: &'static [u8] = b"ocp_lock_locked_mpk_encryption_key";
    const LOCKED_MPK_LABEL: &'static [u8] = b"ocp_lock_locked_mpk";

    /// Derive EPK. The EPK is only valid for the lifetime of `Self`.
    fn new(
        hmac: &mut Hmac,
        trng: &mut Trng,
        kv: &'a mut KeyVault,
        sek: Sek,
    ) -> CaliptraResult<Self> {
        hmac_kdf(
            hmac,
            HmacKey::Key(KeyReadArgs::new(KEY_ID_HEK)),
            Self::EPK_LABEL,
            Some(sek.as_bytes()),
            trng,
            HmacTag::Key(KeyWriteArgs::new(
                KEY_ID_EPK,
                KeyUsage::default().set_hmac_key_en(),
            )),
            HmacMode::Hmac512,
        )?;
        Ok(Self { kv })
    }

    /// Consumes `Self` and DPK to produce a `IntermediateMekSecret`
    fn derive_intermediate_mek_secret(
        self,
        hmac: &mut Hmac,
        trng: &mut Trng,
        dpk: Dpk,
    ) -> CaliptraResult<IntermediateMekSecret> {
        hmac_kdf(
            hmac,
            HmacKey::Key(KeyReadArgs::new(KEY_ID_EPK)),
            Self::INTERMEDIATE_MEK_SECRET_LABEL,
            Some(dpk.as_bytes()),
            trng,
            HmacTag::Key(KeyWriteArgs::new(
                KEY_ID_MEK_SECRETS,
                KeyUsage::default().set_hmac_key_en(),
            )),
            HmacMode::Hmac512,
        )?;
        Ok(IntermediateMekSecret)
    }

    /// Consumes `Self` and `AccessKey` to produce a `LockedMpk`
    fn generate_locked_mpk(
        self,
        aes: &mut Aes,
        hmac: &mut Hmac,
        trng: &mut Trng,
        access_key: AccessKey<Current>,
        metadata: &[u8],
    ) -> CaliptraResult<LockedMpk> {
        hmac_kdf(
            hmac,
            HmacKey::Key(KeyReadArgs::new(KEY_ID_EPK)),
            Self::LOCKED_MPK_ENCRYPTION_KEY_LABEL,
            Some(access_key.as_bytes()),
            trng,
            HmacTag::Key(KeyWriteArgs::new(
                KEY_ID_LOCKED_MPK_ENCRYPTION_KEY,
                KeyUsage::default().set_hmac_key_en(),
            )),
            HmacMode::Hmac512,
        )?;

        let aad = LockedMpkAad::new(metadata)?;
        let aad = aad.serialize()?;

        let mpk = Mpk::generate(trng)?;
        let mut encrypted_key = [0; LockedMpk::KEY_LEN];
        let res = preconditioned_aes_encrypt(
            aes,
            hmac,
            trng,
            self.kv,
            HmacKey::Key(KeyReadArgs::new(KEY_ID_LOCKED_MPK_ENCRYPTION_KEY)),
            AesKey::KV(KeyReadArgs::new(KEY_ID_LOCKED_MPK_ENCRYPTION_KEY)),
            Self::LOCKED_MPK_LABEL,
            aad,
            mpk.as_bytes(),
            &mut encrypted_key,
        )?;

        let mut mpk_metadata = [0; OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN];
        mpk_metadata[..metadata.len()].clone_from_slice(metadata);

        Ok(LockedMpk {
            salt: res.salt.into(),
            iv: res.iv.into(),
            tag: res.tag.into(),
            encrypted_key,
            metadata: mpk_metadata,
            metadata_len: metadata.len() as u32,
        })
    }

    /// Consumes `Self`, `AccessKey<Current>` and `AccessKey<New>` to re-encrypt the MPK to the new
    /// access key.
    fn rewrap_mpk(
        mut self,
        aes: &mut Aes,
        hmac: &mut Hmac,
        trng: &mut Trng,
        current_access_key: AccessKey<Current>,
        new_access_key: AccessKey<New>,
        current_locked_mpk: &LockedMpk,
    ) -> CaliptraResult<LockedMpk> {
        let (mpk, aad) =
            self.decrypt_mpk(aes, hmac, trng, &current_access_key, current_locked_mpk)?;
        let aad = aad.serialize()?;

        // Now derive the new MPK Encryption Key from the new access key
        hmac_kdf(
            hmac,
            HmacKey::Key(KeyReadArgs::new(KEY_ID_EPK)),
            Self::LOCKED_MPK_ENCRYPTION_KEY_LABEL,
            Some(new_access_key.as_bytes()),
            trng,
            HmacTag::Key(KeyWriteArgs::new(
                KEY_ID_LOCKED_MPK_ENCRYPTION_KEY,
                KeyUsage::default().set_hmac_key_en(),
            )),
            HmacMode::Hmac512,
        )?;

        let mut encrypted_key = [0; LockedMpk::KEY_LEN];
        let res = preconditioned_aes_encrypt(
            aes,
            hmac,
            trng,
            self.kv,
            HmacKey::Key(KeyReadArgs::new(KEY_ID_LOCKED_MPK_ENCRYPTION_KEY)),
            AesKey::KV(KeyReadArgs::new(KEY_ID_LOCKED_MPK_ENCRYPTION_KEY)),
            Self::LOCKED_MPK_LABEL,
            aad,
            mpk.as_bytes(),
            &mut encrypted_key,
        )?;

        Ok(LockedMpk {
            salt: res.salt.into(),
            iv: res.iv.into(),
            tag: res.tag.into(),
            encrypted_key,
            metadata: current_locked_mpk.metadata,
            metadata_len: current_locked_mpk.metadata_len,
        })
    }

    /// Uses `AccessKey<Current>` to decrypt the Locked MPK
    fn decrypt_mpk(
        &mut self,
        aes: &mut Aes,
        hmac: &mut Hmac,
        trng: &mut Trng,
        access_key: &AccessKey<Current>,
        locked_mpk: &LockedMpk,
    ) -> CaliptraResult<(Mpk, LockedMpkAad)> {
        // Derive current access key's MPK Encryption Key and place in MPK Encryption KV.
        hmac_kdf(
            hmac,
            HmacKey::Key(KeyReadArgs::new(KEY_ID_EPK)),
            Self::LOCKED_MPK_ENCRYPTION_KEY_LABEL,
            Some(access_key.as_bytes()),
            trng,
            HmacTag::Key(KeyWriteArgs::new(
                KEY_ID_LOCKED_MPK_ENCRYPTION_KEY,
                KeyUsage::default().set_hmac_key_en(),
            )),
            HmacMode::Hmac512,
        )?;

        // Decrypt the MPK using the current access key
        let aad = LockedMpkAad::new(
            locked_mpk
                .metadata
                .get(..locked_mpk.metadata_len as usize)
                .ok_or(CaliptraError::RUNTIME_OCP_LOCK_DESERIALIZE_METADATA_FAILURE)?,
        )?;
        let mut mpk = Mpk::generate(trng)?;
        preconditioned_aes_decrypt(
            aes,
            hmac,
            trng,
            self.kv,
            HmacKey::Key(KeyReadArgs::new(KEY_ID_LOCKED_MPK_ENCRYPTION_KEY)),
            AesKey::KV(KeyReadArgs::new(KEY_ID_LOCKED_MPK_ENCRYPTION_KEY)),
            Self::LOCKED_MPK_LABEL,
            aad.serialize()?,
            &locked_mpk.salt.into(),
            &locked_mpk.iv.into(),
            &locked_mpk.tag.into(),
            &locked_mpk.encrypted_key,
            mpk.as_mut(),
        )?;
        Ok((mpk, aad))
    }
}

impl Drop for Epk<'_> {
    // From Spec:
    //   > Held in the Key Vault and zeroized after each use.
    fn drop(&mut self) {
        // We don't set a write or use lock so this should never fail.
        let _ = self.kv.erase_key(KEY_ID_EPK);
        let _ = self.kv.erase_key(KEY_ID_LOCKED_MPK_ENCRYPTION_KEY);
    }
}

/// Provides OCP LOCK functionalities.
pub struct OcpLockContext {
    /// OCP LOCK is supported on both HW and FW
    available: bool,

    /// HEK is available
    hek_available: bool,

    /// Holds Intermediate Mek Secret, initialized by calling INITIALIZE_MEK_SECRET. Some commands do not work until
    /// `intermediate_secret` has a value.
    intermediate_secret: Option<IntermediateMekSecret>,

    /// Manages HPKE Operations
    hpke_context: HpkeContext,
}

impl OcpLockContext {
    pub fn new(soc_ifc: &SocIfc, trng: &mut Trng, hek_available: bool) -> CaliptraResult<Self> {
        let available =
            cfg!(feature = "ocp-lock") && soc_ifc.ocp_lock_enabled() && soc_ifc.subsystem_mode();
        Ok(Self {
            available,
            intermediate_secret: None,
            hek_available,
            hpke_context: HpkeContext::new(trng)?,
        })
    }

    /// Checks if the OCP lock is available.
    ///
    /// Returns `true` if the "ocp-lock" feature is enabled and the OCP lock is enabled in the SoC.
    pub fn available(&self) -> bool {
        self.available
    }

    /// Creates an MEK intermediate secret from `HEK`, `SEK` and `DPK`.
    pub fn create_intermediate_mek_secret(
        &mut self,
        hmac: &mut Hmac,
        trng: &mut Trng,
        kv: &mut KeyVault,
        sek: Sek,
        dpk: Dpk,
    ) -> CaliptraResult<()> {
        if !self.hek_available {
            return Err(CaliptraError::RUNTIME_OCP_LOCK_HEK_UNAVAILABLE);
        } else {
            cfi_assert!(self.hek_available);
        }
        let epk = Epk::new(hmac, trng, kv, sek)?;
        let intermediate_secret = epk.derive_intermediate_mek_secret(hmac, trng, dpk)?;
        self.intermediate_secret = Some(intermediate_secret);
        Ok(())
    }

    /// Derives an MEK
    ///
    /// NOTE: This operation will consume `intermediate_secret` and erase the MEK secret key vault on
    /// completion.
    // TODO(clundin): Maybe we will want to split the MEK
    // release into a separate step since other flows will
    // need it. This will reduce the args.
    #[allow(clippy::too_many_arguments)]
    pub fn derive_mek(
        &mut self,
        aes: &mut Aes,
        dma: &mut Dma,
        hmac: &mut Hmac,
        trng: &mut Trng,
        kv: &mut KeyVault,
        soc: &mut SocIfc,
        expect_mek_checksum: MekChecksum,
    ) -> CaliptraResult<MekChecksum> {
        // After `intermediate_secret` is consumed a new MEK cannot be created without first calling
        // `OCP_LOCK_INITIALIZE_MEK_SECRET` so we take it.
        let Some(intermediate_secret) = self.intermediate_secret.take() else {
            return Err(CaliptraError::RUNTIME_OCP_LOCK_MEK_NOT_INITIALIZED);
        };
        let mek_secret = intermediate_secret.derive_mek_secret(hmac, trng, kv)?;
        let mek_seed = mek_secret.derive_mek_seed(aes)?;
        let checksum = mek_seed.checksum(aes)?;

        // If `expect_mek_checksum` is all zeros, skip checking that the MEK checksum matches.
        // `expect_mek_checksum` should match the `checksum` that was derived.
        // Otherwise we need to report an error.
        if expect_mek_checksum != MekChecksum::default() && expect_mek_checksum != checksum {
            return Err(CaliptraError::RUNTIME_OCP_LOCK_MEK_CHKSUM_FAIL);
        }

        // Decrypt MEK from MEK seed using MDK.
        aes.aes_256_ecb_decrypt_kv(mek_seed.as_ref())?;
        // Release MEK to Encryption Engine.
        dma.ocp_lock_key_vault_release(soc);

        Ok(checksum)
    }

    /// Returns an iterator over the available HPKE handles.
    pub fn iterate_hpke_handles(&self) -> HpkeContextIter<'_> {
        self.hpke_context.iter()
    }

    /// Rotates an HPKE key
    ///
    /// Returns an error if the HPKE handle does not exist.
    pub fn rotate_hpke_key(
        &mut self,
        trng: &mut Trng,
        handle: &HpkeHandle,
    ) -> CaliptraResult<HpkeHandle> {
        self.hpke_context.rotate(trng, handle)
    }

    /// Generate an MEK
    ///
    /// NOTE: This operation will consume `intermediate_secret` and erase the MEK secret key vault on
    /// completion.
    pub fn generate_mek(
        &mut self,
        aes: &mut Aes,
        hmac: &mut Hmac,
        trng: &mut Trng,
        kv: &mut KeyVault,
    ) -> CaliptraResult<WrappedMek> {
        // After `intermediate_secret` is consumed a new MEK cannot be created without first calling
        // `OCP_LOCK_INITIALIZE_MEK_SECRET` so we take it.
        let Some(intermediate_secret) = self.intermediate_secret.take() else {
            return Err(CaliptraError::RUNTIME_OCP_LOCK_MEK_NOT_INITIALIZED);
        };
        let mek_secret = intermediate_secret.wrapping_mek_secret(hmac, trng, kv)?;
        mek_secret.generate_mek(aes, trng, hmac)
    }

    /// Generate a Locked MPK
    #[allow(clippy::too_many_arguments)]
    pub fn generate_mpk(
        &mut self,
        aes: &mut Aes,
        hmac: &mut Hmac,
        trng: &mut Trng,
        kv: &mut KeyVault,
        access_key: AccessKey<Current>,
        sek: Sek,
        metadata: &[u8],
    ) -> CaliptraResult<LockedMpk> {
        if !self.hek_available {
            return Err(CaliptraError::RUNTIME_OCP_LOCK_HEK_UNAVAILABLE);
        } else {
            cfi_assert!(self.hek_available);
        }

        let epk = Epk::new(hmac, trng, kv, sek)?;
        epk.generate_locked_mpk(aes, hmac, trng, access_key, metadata)
    }

    /// Decrypt an encapsulated Access Key
    #[allow(clippy::too_many_arguments)]
    pub fn decapsulate_access_key(
        &mut self,
        sha: &mut Sha3,
        abr: &mut Abr,
        hmac: &mut Hmac,
        trng: &mut Trng,
        aes: &mut Aes,
        hpke_handle: &HpkeHandle,
        enc: &[u8],
        info: &[u8],
        metadata: &[u8],
        tag: &[u8; 16],
        ct: &[u8; AccessKey::<Current>::KEY_LEN],
    ) -> CaliptraResult<AccessKey<Current>> {
        let mut ctx = self
            .hpke_context
            .decap(sha, abr, hmac, trng, hpke_handle, enc, info)?;
        AccessKey::<Current>::from_ciphertext(aes, trng, &mut ctx, metadata, tag, ct)
    }

    /// Decapsulate two access keys from the same HPKE context
    #[allow(clippy::too_many_arguments)]
    pub fn decapsulate_rotation_access_keys(
        &mut self,
        sha: &mut Sha3,
        abr: &mut Abr,
        hmac: &mut Hmac,
        trng: &mut Trng,
        aes: &mut Aes,
        hpke_handle: &HpkeHandle,
        enc: &[u8],
        info: &[u8],
        metadata: &[u8],
        current: &EncryptedAccessKey<Current>,
        new: &EncryptedAccessKey<New>,
    ) -> CaliptraResult<(AccessKey<Current>, AccessKey<New>)> {
        let mut ctx = self
            .hpke_context
            .decap(sha, abr, hmac, trng, hpke_handle, enc, info)?;
        let current = AccessKey::<Current>::from_ciphertext(
            aes,
            trng,
            &mut ctx,
            metadata,
            &current.tag,
            &current.ciphertext,
        )?;
        let new = AccessKey::<New>::from_ciphertext(
            aes,
            trng,
            &mut ctx,
            metadata,
            &new.tag,
            &new.ciphertext,
        )?;
        Ok((current, new))
    }

    /// Rewraps an MPK with a new access key
    #[allow(clippy::too_many_arguments)]
    pub fn rewrap_mpk(
        &mut self,
        aes: &mut Aes,
        hmac: &mut Hmac,
        trng: &mut Trng,
        kv: &mut KeyVault,
        current_access_key: AccessKey<Current>,
        new_access_key: AccessKey<New>,
        sek: Sek,
        current_locked_mpk: &LockedMpk,
    ) -> CaliptraResult<LockedMpk> {
        if !self.hek_available {
            return Err(CaliptraError::RUNTIME_OCP_LOCK_HEK_UNAVAILABLE);
        } else {
            cfi_assert!(self.hek_available);
        }

        let epk = Epk::new(hmac, trng, kv, sek)?;
        epk.rewrap_mpk(
            aes,
            hmac,
            trng,
            current_access_key,
            new_access_key,
            current_locked_mpk,
        )
    }

    /// Enables a Locked MPK and returns an `EnabledMpk`
    /// The decrypted `Mpk` is encrypted to the `Vek`.
    #[allow(clippy::too_many_arguments)]
    pub fn enable_mpk(
        &mut self,
        aes: &mut Aes,
        hmac: &mut Hmac,
        trng: &mut Trng,
        kv: &mut KeyVault,
        access_key: AccessKey<Current>,
        sek: Sek,
        locked_mpk: &LockedMpk,
        state: &mut OcpLockMetadataFirmware,
    ) -> CaliptraResult<EnabledMpk> {
        if !self.hek_available {
            return Err(CaliptraError::RUNTIME_OCP_LOCK_HEK_UNAVAILABLE);
        } else {
            cfi_assert!(self.hek_available);
        }

        Vek::generate(hmac, trng, state)?;

        let (mpk, aad) = {
            let mut epk = Epk::new(hmac, trng, kv, sek)?;
            epk.decrypt_mpk(aes, hmac, trng, &access_key, locked_mpk)?
        };

        let aad = EnabledMpkAad::from(aad);

        let mut encrypted_key = [0; EnabledMpk::KEY_LEN];
        let res = preconditioned_aes_encrypt(
            aes,
            hmac,
            trng,
            kv,
            HmacKey::Key(KeyReadArgs::new(KEY_ID_VEK)),
            // We do not want to erase the `VEK` KV slot so use the MPK Encryption key slot to
            // store the encryption subkey. This is safe because this slot is always erased on use,
            // so we can't overwrite any data.
            AesKey::KV(KeyReadArgs::new(KEY_ID_LOCKED_MPK_ENCRYPTION_KEY)),
            EnabledMpk::KDF_LABEL,
            aad.serialize()?,
            mpk.as_bytes(),
            &mut encrypted_key,
        )?;

        Ok(EnabledMpk {
            salt: res.salt.into(),
            iv: res.iv.into(),
            tag: res.tag.into(),
            encrypted_key,
            metadata: locked_mpk.metadata,
            metadata_len: locked_mpk.metadata_len,
        })
    }

    /// Tests an access key and returns `SHA2-384(metadata || decrypted access key || nonce)` to
    /// provide proof
    #[allow(clippy::too_many_arguments)]
    pub fn test_access_key(
        &mut self,
        aes: &mut Aes,
        hmac: &mut Hmac,
        trng: &mut Trng,
        sha2: &mut Sha2_512_384,
        kv: &mut KeyVault,
        access_key: AccessKey<Current>,
        locked_mpk: &LockedMpk,
        sek: Sek,
        metadata: &[u8],
        nonce: &[u8],
    ) -> CaliptraResult<[u8; 48]> {
        if !self.hek_available {
            return Err(CaliptraError::RUNTIME_OCP_LOCK_HEK_UNAVAILABLE);
        } else {
            cfi_assert!(self.hek_available);
        }

        let mut epk = Epk::new(hmac, trng, kv, sek)?;
        // Check that access key can decrypt the locked mpk.
        let _ = epk.decrypt_mpk(aes, hmac, trng, &access_key, locked_mpk)?;

        let mut op = sha2.sha384_digest_init()?;
        op.update(metadata)?;
        op.update(access_key.as_bytes())?;
        op.update(nonce)?;

        let mut digest = Array4x12::default();
        op.finalize(&mut digest)?;
        Ok(digest.into())
    }

    /// Mixes an `EnabledMpk` into the MEK Secret Seed
    pub fn mix_mpk(
        &mut self,
        aes: &mut Aes,
        hmac: &mut Hmac,
        trng: &mut Trng,
        kv: &mut KeyVault,
        enabled_mpk: &EnabledMpk,
        state: &OcpLockMetadataFirmware,
    ) -> CaliptraResult<()> {
        if !state.flags.contains(OcpLockFlags::VEK_AVAILABLE) {
            return Err(CaliptraError::RUNTIME_OCP_LOCK_VEK_UNAVAILABLE);
        }

        let Some(ref mut intermediate_secret) = self.intermediate_secret else {
            return Err(CaliptraError::RUNTIME_OCP_LOCK_MEK_NOT_INITIALIZED);
        };

        let aad = EnabledMpkAad::new(
            enabled_mpk
                .metadata
                .get(..enabled_mpk.metadata_len as usize)
                .ok_or(CaliptraError::RUNTIME_OCP_LOCK_DESERIALIZE_METADATA_FAILURE)?,
        )?;
        let aad = aad.serialize()?;

        let mut mpk = Mpk::generate(trng)?;
        preconditioned_aes_decrypt(
            aes,
            hmac,
            trng,
            kv,
            HmacKey::Key(KeyReadArgs::new(KEY_ID_VEK)),
            // We do not want to erase the `VEK` KV slot so use the MPK Encryption key slot to
            // store the encryption subkey. This is safe because this slot is always erased on use,
            // so we can't overwrite any data.
            AesKey::KV(KeyReadArgs::new(KEY_ID_LOCKED_MPK_ENCRYPTION_KEY)),
            EnabledMpk::KDF_LABEL,
            aad,
            &enabled_mpk.salt.into(),
            &enabled_mpk.iv.into(),
            &enabled_mpk.tag.into(),
            &enabled_mpk.encrypted_key,
            mpk.as_mut(),
        )?;

        intermediate_secret.mix_mpk(hmac, trng, mpk)?;

        Ok(())
    }

    /// Retrieve the public key for the HPKE handle
    pub fn get_hpke_public_key(
        &mut self,
        sha: &mut Sha3,
        abr: &mut Abr,
        trng: &mut Trng,
        hmac: &mut Hmac,
        hpke_handle: &HpkeHandle,
        pub_out: &mut [u8],
    ) -> CaliptraResult<usize> {
        self.hpke_context
            .get_pub_key(sha, abr, trng, hmac, hpke_handle, pub_out)
    }

    /// Retrieve the Ciphersuite for an HPKE handle
    pub fn get_hpke_cipher_suite(
        &mut self,
        hpke_handle: &HpkeHandle,
    ) -> CaliptraResult<HpkeCipherSuite> {
        self.hpke_context.get_cipher_suite(hpke_handle)
    }
}

type Millisecond = u32;
type Picosecond = u64;

fn timeout_to_mtime(command_timeout: Millisecond, clock_period: Picosecond) -> u64 {
    // MAX_TIMEOUT is one hour. The actual value is TBD
    const MAX_TIMEOUT: Millisecond = 60 * 60 * 1000;
    const ONE_MS_IN_PS: Picosecond = 1_000_000_000u64;

    fn ms_to_ps(time_in_ms: Millisecond) -> Picosecond {
        (time_in_ms as u64) * ONE_MS_IN_PS
    }

    fn walltime_to_mtime(walltime: Millisecond, period: Picosecond) -> Picosecond {
        ms_to_ps(walltime).div_ceil(period)
    }

    let bounded_command_timeout: Millisecond = command_timeout.min(MAX_TIMEOUT);

    // To avoid division by 0, 0 will be replaced by 2500.
    // 2500 is computed from Caliptra's validated frequency 400MHz.
    let period = match clock_period {
        0 => 2500u64,
        non_zero => non_zero,
    };

    walltime_to_mtime(bounded_command_timeout, period)
}

/// Entry point for OCP LOCK commands
pub fn command_handler(
    cmd_id: CommandId,
    drivers: &mut Drivers,
    cmd_bytes: &[u8],
    resp: &mut [u8],
) -> CaliptraResult<usize> {
    // If we have not enabled 'ocp-lock' we don't want the compiler to link these commands, so exit
    // the function early.
    if !cfg!(feature = "ocp-lock") || !drivers.ocp_lock_context.available() {
        Err(CaliptraError::RUNTIME_OCP_LOCK_UNSUPPORTED_COMMAND)?;
    }

    match drivers.caller_privilege_level() {
        // Only PL0 can call OCP_LOCK
        PauserPrivileges::PL0 => (),
        PauserPrivileges::PL1 => {
            return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
        }
    }

    match cmd_id {
        CommandId::OCP_LOCK_GET_ALGORITHMS => GetAlgorithmsCmd::execute(resp),
        CommandId::OCP_LOCK_INITIALIZE_MEK_SECRET => {
            InitializeMekSecretCmd::execute(drivers, cmd_bytes, resp)
        }
        CommandId::OCP_LOCK_MIX_MPK => MixMpkCmd::execute(drivers, cmd_bytes, resp),
        CommandId::OCP_LOCK_DERIVE_MEK => DeriveMekCmd::execute(drivers, cmd_bytes, resp),
        CommandId::OCP_LOCK_ENUMERATE_HPKE_HANDLES => {
            EnumerateHpkeHandles::execute(drivers, cmd_bytes, resp)
        }
        CommandId::OCP_LOCK_ENDORSE_HPKE_PUB_KEY => {
            EndorseHpkePubkeyCmd::execute(drivers, cmd_bytes, resp)
        }
        CommandId::OCP_LOCK_ROTATE_HPKE_KEY => RotateHpkeKeyCmd::execute(drivers, cmd_bytes, resp),
        CommandId::OCP_LOCK_GENERATE_MEK => GenerateMekCmd::execute(drivers, cmd_bytes, resp),
        CommandId::OCP_LOCK_GENERATE_MPK => GenerateMpkCmd::execute(drivers, cmd_bytes, resp),
        CommandId::OCP_LOCK_REWRAP_MPK => RewrapMpkCmd::execute(drivers, cmd_bytes, resp),
        CommandId::OCP_LOCK_ENABLE_MPK => EnableMpkCmd::execute(drivers, cmd_bytes, resp),
        CommandId::OCP_LOCK_TEST_ACCESS_KEY => TestAccessKeyCmd::execute(drivers, cmd_bytes, resp),
        CommandId::OCP_LOCK_GET_STATUS => GetStatusCmd::execute(drivers, cmd_bytes, resp),
        CommandId::OCP_LOCK_CLEAR_KEY_CACHE => ClearKeyCacheCmd::execute(drivers, cmd_bytes, resp),
        CommandId::OCP_LOCK_UNLOAD_MEK => UnloadMekCmd::execute(drivers, cmd_bytes, resp),
        _ => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
    }
}
