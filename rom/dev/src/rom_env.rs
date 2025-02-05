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

use crate::fht::FhtDataStore;
use caliptra_drivers::{
    DeobfuscationEngine, Dma, Ecc384, Hmac, KeyVault, Lms, Mailbox, Mldsa87, PcrBank,
    PersistentDataAccessor, Sha1, Sha256, Sha2_512_384, Sha2_512_384Acc, SocIfc, Trng,
};
use caliptra_error::CaliptraResult;
use caliptra_registers::{
    axi_dma::AxiDmaReg, csrng::CsrngReg, doe::DoeReg, ecc::EccReg, entropy_src::EntropySrcReg,
    hmac::HmacReg, kv::KvReg, mbox::MboxCsr, mldsa::MldsaReg, pv::PvReg, sha256::Sha256Reg,
    sha512::Sha512Reg, sha512_acc::Sha512AccCsr, soc_ifc::SocIfcReg, soc_ifc_trng::SocIfcTrngReg,
};

/// Rom Context
pub struct RomEnv {
    /// Deobfuscation engine
    pub doe: DeobfuscationEngine,

    // SHA1 Engine
    pub sha1: Sha1,

    // SHA2-256 Engine
    pub sha256: Sha256,

    // SHA2-512/384 Engine
    pub sha2_512_384: Sha2_512_384,

    // SHA2-512/384 Accelerator
    pub sha2_512_384_acc: Sha2_512_384Acc,

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

    /// FHT Data Store
    pub fht_data_store: FhtDataStore,

    /// Cryptographically Secure Random Number Generator
    pub trng: Trng,

    /// Mechanism to access the persistent data safely
    pub persistent_data: PersistentDataAccessor,

    /// Mldsa87 Engine
    pub mldsa87: Mldsa87,

    /// Dma engine
    pub dma: Dma,
}

impl RomEnv {
    pub unsafe fn new_from_registers() -> CaliptraResult<Self> {
        let trng = Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )?;

        Ok(Self {
            doe: DeobfuscationEngine::new(DoeReg::new()),
            sha1: Sha1::default(),
            sha256: Sha256::new(Sha256Reg::new()),
            sha2_512_384: Sha2_512_384::new(Sha512Reg::new()),
            sha2_512_384_acc: Sha2_512_384Acc::new(Sha512AccCsr::new()),
            hmac: Hmac::new(HmacReg::new()),
            ecc384: Ecc384::new(EccReg::new()),
            lms: Lms::default(),
            key_vault: KeyVault::new(KvReg::new()),
            soc_ifc: SocIfc::new(SocIfcReg::new()),
            mbox: Mailbox::new(MboxCsr::new()),
            pcr_bank: PcrBank::new(PvReg::new()),
            fht_data_store: FhtDataStore::default(),
            trng,
            persistent_data: PersistentDataAccessor::new(),
            mldsa87: Mldsa87::new(MldsaReg::new()),
            dma: Dma::new(AxiDmaReg::new()),
        })
    }
}
