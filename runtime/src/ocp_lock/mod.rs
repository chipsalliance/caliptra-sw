// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{CommandId, WrappedKey};
use caliptra_cfi_lib_git::{cfi_assert, cfi_assert_eq};
use caliptra_common::keyids::ocp_lock::{KEY_ID_EPK, KEY_ID_HEK, KEY_ID_MDK, KEY_ID_MEK_SECRETS};
use caliptra_drivers::{
    cmac_kdf, hmac_kdf,
    hpke::{HpkeContext, HpkeContextIter, HpkeHandle},
    preconditioned_aes::preconditioned_aes_encrypt,
    Aes, AesKey, AesOperation, Dma, Hmac, HmacKey, HmacMode, HmacTag, KeyReadArgs, KeyUsage,
    KeyVault, KeyWriteArgs, LEArray4x16, LEArray4x8, SocIfc, Trng,
};
use caliptra_error::{CaliptraError, CaliptraResult};

use enumerate_hpke_handles::EnumerateHpkeHandles;
use generate_mek::GenerateMekCmd;
use rotate_hpke_key::RotateHpkeKeyCmd;
use zerocopy::{transmute, FromBytes, Immutable, IntoBytes, KnownLayout};
use zeroize::ZeroizeOnDrop;

mod derive_mek;
mod enumerate_hpke_handles;
mod generate_mek;
mod get_algorithms;
mod initialize_mek_secret;
mod rotate_hpke_key;

pub use derive_mek::DeriveMekCmd;
pub use get_algorithms::GetAlgorithmsCmd;
pub use initialize_mek_secret::InitializeMekSecretCmd;

use crate::Drivers;

/// Represents the SEK type from OCP LOCK.
#[derive(IntoBytes, KnownLayout, Immutable, ZeroizeOnDrop)]
pub struct Sek(pub [u8; 32]);

/// Represents the DPK type from OCP LOCK.
#[derive(IntoBytes, KnownLayout, Immutable, ZeroizeOnDrop)]
pub struct Dpk(pub [u8; 32]);

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
    tag: [u8; 16],
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
        ciphertext_and_auth_tag[..64].copy_from_slice(&value.encrypted_key);
        ciphertext_and_auth_tag[64..].copy_from_slice(&value.tag);

        Ok(Self {
            key_type: WrappedMek::KEY_TYPE,
            salt: value.salt,
            metadata_len: 0,
            key_len: WrappedMek::KEY_LEN as u32,
            iv: value.iv,
            cipher_text_and_auth_tag: ciphertext_and_auth_tag,
            ..Default::default()
        })
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
            HmacKey::Key(KeyReadArgs::new(KEY_ID_MEK_SECRETS)),
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
            b"ocp_lock_epk",
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
            b"ocp_lock_intermediate_mek_secret",
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
}

impl Drop for Epk<'_> {
    // From Spec:
    //   > Held in the Key Vault and zeroized after each use.
    fn drop(&mut self) {
        // We don't set a write or use lock so this should never fail.
        let _ = self.kv.erase_key(KEY_ID_EPK);
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
        let available = cfg!(feature = "ocp-lock") && soc_ifc.ocp_lock_enabled();
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
    match cmd_id {
        CommandId::OCP_LOCK_GET_ALGORITHMS => GetAlgorithmsCmd::execute(resp),
        CommandId::OCP_LOCK_INITIALIZE_MEK_SECRET => {
            InitializeMekSecretCmd::execute(drivers, cmd_bytes, resp)
        }
        CommandId::OCP_LOCK_DERIVE_MEK => DeriveMekCmd::execute(drivers, cmd_bytes, resp),
        CommandId::OCP_LOCK_ENUMERATE_HPKE_HANDLES => {
            EnumerateHpkeHandles::execute(drivers, cmd_bytes, resp)
        }
        CommandId::OCP_LOCK_ROTATE_HPKE_KEY => RotateHpkeKeyCmd::execute(drivers, cmd_bytes, resp),
        CommandId::OCP_LOCK_GENERATE_MEK => GenerateMekCmd::execute(drivers, cmd_bytes, resp),
        _ => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
    }
}
