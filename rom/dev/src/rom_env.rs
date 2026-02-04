/*++

Licensed under the Apache-2.0 license.

File Name:

    rom_env.rs

Abstract:

    File implements a context holding all the services utilized by ROM.
    The primary need for this abstraction is to hide the hardware details
    from the ROM flows. The natural side benefit of this abstraction is it
    makes authoring mocks and unit tests easy.

--*/

use caliptra_drivers::{
    AesGcm, DeobfuscationEngine, Dma, Ecc384, Hmac, KeyVault, Lms, Mailbox, Mldsa87, PcrBank,
    PersistentDataAccessor, Sha1, Sha256, Sha2_512_384, Sha2_512_384Acc, Sha3, SocIfc, Trng,
};
use caliptra_error::CaliptraResult;
use caliptra_registers::{
    abr::AbrReg, aes::AesReg, aes_clp::AesClpReg, csrng::CsrngReg, doe::DoeReg, ecc::EccReg,
    entropy_src::EntropySrcReg, hmac::HmacReg, kmac::Kmac as KmacReg, kv::KvReg, mbox::MboxCsr,
    pv::PvReg, sha256::Sha256Reg, sha512::Sha512Reg, sha512_acc::Sha512AccCsr, soc_ifc::SocIfcReg,
    soc_ifc_trng::SocIfcTrngReg,
};

/// Non-Crypto ROM Context
/// Contains only the non-cryptographic drivers and those needed before KAT execution
pub struct RomEnv {
    /// Deobfuscation engine
    pub doe: DeobfuscationEngine,

    // SHA2-256 Engine
    pub sha256: Sha256,

    // SHA2-512/384 Engine
    pub sha2_512_384: Sha2_512_384,

    // SHA2-512/384 Accelerator
    pub sha2_512_384_acc: Sha2_512_384Acc,

    // SHA3/SHAKE
    pub sha3: Sha3,

    /// Hmac Engine
    pub hmac: Hmac,

    /// Ecc384 Engine
    pub ecc384: Ecc384,

    /// LMS Engine
    pub lms: Lms,

    /// Key Vault
    pub key_vault: KeyVault,

    /// SoC interface
    pub soc_ifc: SocIfc,

    /// Mailbox
    pub mbox: Mailbox,

    /// PCR Bank
    pub pcr_bank: PcrBank,

    /// Cryptographically Secure Random Number Generator
    pub trng: Trng,

    /// Mechanism to access the persistent data safely
    pub persistent_data: PersistentDataAccessor,

    /// Mldsa87 Engine
    pub mldsa87: Mldsa87,

    /// Dma engine
    pub dma: Dma,

    /// AES-GCM engine (KATs run at construction after WDT starts)
    pub aes_gcm: AesGcm,
}

impl RomEnv {
    /// Create TRNG early for CFI initialization.
    /// This must be called before `new_from_registers` so CFI can be initialized first.
    pub unsafe fn create_trng() -> CaliptraResult<Trng> {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
            PersistentDataAccessor::new(),
        )
    }

    /// Create the ROM environment. CFI must be initialized before calling this.
    /// Takes ownership of the pre-created TRNG.
    pub unsafe fn new_from_registers(mut trng: Trng) -> CaliptraResult<Self> {
        // Create SocIfc early so we can start the WDT before running AES KATs
        let mut soc_ifc = SocIfc::new(SocIfcReg::new());

        // Start the Watchdog Timer before running KATs
        crate::wdt::start_wdt(&mut soc_ifc);

        // Create AesGcm which runs the GCM and CMAC-KDF KATs at construction time
        let aes_gcm = AesGcm::new(AesReg::new(), AesClpReg::new(), &mut trng)?;
        Ok(Self {
            doe: DeobfuscationEngine::new(DoeReg::new()),
            sha256: Sha256::new(Sha256Reg::new()),
            sha2_512_384: Sha2_512_384::new(Sha512Reg::new()),
            sha2_512_384_acc: Sha2_512_384Acc::new(Sha512AccCsr::new()),
            sha3: Sha3::new(KmacReg::new()),
            hmac: Hmac::new(HmacReg::new()),
            ecc384: Ecc384::new(EccReg::new()),
            lms: Lms::default(),
            key_vault: KeyVault::new(KvReg::new()),
            soc_ifc,
            mbox: Mailbox::new(MboxCsr::new()),
            pcr_bank: PcrBank::new(PvReg::new()),
            trng,
            persistent_data: PersistentDataAccessor::new(),
            mldsa87: Mldsa87::new(AbrReg::new()),
            dma: Dma::default(),
            aes_gcm,
        })
    }
}

/// Full ROM Context
/// Contains all drivers needed after KAT execution
pub struct RomEnvFips {
    /// Non-crypto environment (embedded)
    pub non_crypto: RomEnv,

    // SHA1 Engine (initialized by KATs)
    pub sha1: Sha1,
}

impl RomEnvFips {
    /// Create RomEnvFips from non-crypto environment and initialized drivers
    pub fn from_non_crypto(
        non_crypto: RomEnv,
        initialized: caliptra_kat::InitializedDrivers,
    ) -> Self {
        Self {
            non_crypto,
            sha1: initialized.sha1,
        }
    }

    /// Get a mutable reference to the non-crypto environment
    pub fn non_crypto_mut(&mut self) -> &mut RomEnv {
        &mut self.non_crypto
    }

    /// Get an immutable reference to the non-crypto environment
    #[allow(dead_code)]
    pub fn non_crypto(&self) -> &RomEnv {
        &self.non_crypto
    }
}

// Provide transparent access to non-crypto fields via Deref
impl core::ops::Deref for RomEnvFips {
    type Target = RomEnv;

    fn deref(&self) -> &Self::Target {
        &self.non_crypto
    }
}

impl core::ops::DerefMut for RomEnvFips {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.non_crypto
    }
}
