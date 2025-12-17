/*++

Licensed under the Apache-2.0 license.

File Name:

    fmc_env.rs

Abstract:

    File implements a context holding all the services utilized by firmware.
    The primary need for this abstraction is to hide the hardware details
    from the ROM/FMC/RT flows. The natural side benefit of this abstraction is it
    makes authoring mocks and unit tests easy.

--*/

use caliptra_drivers::{
    CaliptraResult, Ecc384, Hmac, KeyVault, Mailbox, Mldsa87, PcrBank, PersistentDataAccessor,
    Sha1, Sha256, Sha2_512_384, Sha2_512_384Acc, SocIfc, Trng,
};
use caliptra_registers::{
    abr::AbrReg, csrng::CsrngReg, ecc::EccReg, entropy_src::EntropySrcReg, hmac::HmacReg,
    kv::KvReg, mbox::MboxCsr, pv::PvReg, sha512::Sha512Reg, sha512_acc::Sha512AccCsr,
    soc_ifc::SocIfcReg, soc_ifc_trng::SocIfcTrngReg,
};

/// Hardware Context
/// Contains only the non-cryptographic drivers and those needed before KAT execution
pub struct FmcEnvNonCrypto {
    // SHA2-512/384 Engine
    pub sha2_512_384: Sha2_512_384,

    // SHA2-512/384 Accelerator
    pub sha2_512_384_acc: Sha2_512_384Acc,

    /// Hmac Engine
    pub hmac: Hmac,

    /// Ecc384 Engine
    pub ecc384: Ecc384,

    /// Key Vault
    pub key_vault: KeyVault,

    /// Device state
    pub soc_ifc: SocIfc,

    /// Mailbox
    pub mbox: Mailbox,

    /// PCR Bank
    pub pcr_bank: PcrBank,

    /// Cryptographically Secure Random Number Generator
    pub trng: Trng,

    /// Persistent Data
    pub persistent_data: PersistentDataAccessor,

    /// Mldsa87 Engine
    pub mldsa: Mldsa87,
}

impl FmcEnvNonCrypto {
    /// # Safety
    ///
    /// Callers must ensure that this function is called only once, and that any
    /// concurrent access to these register blocks does not conflict with these
    /// drivers.
    ///
    ///
    pub unsafe fn new_from_registers() -> CaliptraResult<Self> {
        let trng = Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )?;

        Ok(Self {
            sha2_512_384: Sha2_512_384::new(Sha512Reg::new()),
            sha2_512_384_acc: Sha2_512_384Acc::new(Sha512AccCsr::new()),
            hmac: Hmac::new(HmacReg::new()),
            ecc384: Ecc384::new(EccReg::new()),
            key_vault: KeyVault::new(KvReg::new()),
            soc_ifc: SocIfc::new(SocIfcReg::new()),
            mbox: Mailbox::new(MboxCsr::new()),
            pcr_bank: PcrBank::new(PvReg::new()),
            trng,
            persistent_data: PersistentDataAccessor::new(),
            mldsa: Mldsa87::new(AbrReg::new()),
        })
    }
}

/// Full Hardware Context
/// Contains all drivers needed after KAT execution
pub struct FmcEnv {
    /// Non-crypto environment (embedded)
    pub non_crypto: FmcEnvNonCrypto,

    // Crypto engines initialized by KATs
    // SHA1 Engine
    pub sha1: Sha1,

    // SHA2-256 Engine
    pub sha256: Sha256,
}

impl FmcEnv {
    /// Create FmcEnv from non-crypto environment and initialized drivers
    /// # Safety
    /// The KATs have been run.
    pub unsafe fn from_non_crypto(
        non_crypto: FmcEnvNonCrypto,
        initialized: caliptra_kat::InitializedDrivers,
    ) -> Self {
        Self {
            non_crypto,
            sha1: initialized.sha1,
            sha256: initialized.sha256,
        }
    }

    /// Get a mutable reference to the non-crypto environment
    pub fn non_crypto_mut(&mut self) -> &mut FmcEnvNonCrypto {
        &mut self.non_crypto
    }

    /// Get an immutable reference to the non-crypto environment
    pub fn non_crypto(&self) -> &FmcEnvNonCrypto {
        &self.non_crypto
    }
}

// Provide transparent access to non-crypto fields via Deref
impl core::ops::Deref for FmcEnv {
    type Target = FmcEnvNonCrypto;

    fn deref(&self) -> &Self::Target {
        &self.non_crypto
    }
}

impl core::ops::DerefMut for FmcEnv {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.non_crypto
    }
}
