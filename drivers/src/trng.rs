// Licensed under the Apache-2.0 license

use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_registers::{
    csrng::CsrngReg, entropy_src::EntropySrcReg, soc_ifc::SocIfcReg, soc_ifc_trng::SocIfcTrngReg,
};

use crate::{trng_ext::TrngExt, Array4x12, Csrng};

#[repr(u32)]
pub enum Trng {
    Internal(Csrng) = 0xb714a2b1,
    External(TrngExt) = 0xf3702ce3,

    // Teach the compiler that "other" values are possible to encourage it not
    // to get too crazy with optimizations. Match statements should handle `_`
    // by jumping to the CFI handler.
    Invalid0 = 0x0060f20f,
    Invalid1 = 0x0a8dfe7a,
}

impl Trng {
    pub fn new(
        csrng: CsrngReg,
        entropy_src: EntropySrcReg,
        soc_ifc_trng: SocIfcTrngReg,
        soc_ifc: &SocIfcReg,
    ) -> CaliptraResult<Self> {
        if soc_ifc.regs().cptra_hw_config().read().i_trng_en() {
            Ok(Self::Internal(Csrng::new(csrng, entropy_src, soc_ifc)?))
        } else {
            Ok(Self::External(TrngExt::new(soc_ifc_trng)))
        }
    }

    /// # Safety
    ///
    /// If the hardware itrng is enabled, the caller MUST ensure that the
    /// peripheral is in a state where new entropy is accessible via the
    /// generate command.
    pub unsafe fn assume_initialized(
        csrng: CsrngReg,
        entropy_src: EntropySrcReg,
        soc_ifc_trng: SocIfcTrngReg,
        soc_ifc: &SocIfcReg,
    ) -> Self {
        if soc_ifc.regs().cptra_hw_config().read().i_trng_en() {
            Self::Internal(Csrng::assume_initialized(csrng, entropy_src))
        } else {
            Self::External(TrngExt::new(soc_ifc_trng))
        }
    }

    pub fn generate(&mut self) -> CaliptraResult<Array4x12> {
        match self {
            Self::Internal(csrng) => Ok(csrng.generate12()?.into()),
            Self::External(trng_ext) => trng_ext.generate(),
            _ => {
                extern "C" {
                    fn cfi_panic_handler(code: u32) -> !;
                }
                unsafe {
                    cfi_panic_handler(CaliptraError::ROM_CFI_PANIC_UNEXPECTED_MATCH_BRANCH.into())
                }
            }
        }
    }
}
