// Licensed under the Apache-2.0 license

use core::array;

use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_registers::{
    csrng::CsrngReg, entropy_src::EntropySrcReg, soc_ifc::SocIfcReg, soc_ifc_trng::SocIfcTrngReg,
};

use crate::{trng_ext::TrngExt, Array4x12, Csrng, MfgFlags};

#[repr(u32)]
pub enum Trng {
    Internal(Csrng) = 0xb714a2b1,
    External(TrngExt) = 0xf3702ce3,
    MfgMode() = 0x0c702ce3,

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
        // If device is unlocked for debug and RNG support is unavailable, return a fake RNG.
        let flags: MfgFlags = (soc_ifc.regs().cptra_dbg_manuf_service_reg().read() & 0xffff).into();
        if !soc_ifc.regs().cptra_security_state().read().debug_locked()
            & flags.contains(MfgFlags::RNG_SUPPORT_UNAVAILABLE)
        {
            Ok(Self::MfgMode())
        } else if soc_ifc.regs().cptra_hw_config().read().i_trng_en() {
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
        extern "C" {
            fn cfi_panic_handler(code: u32) -> !;
        }

        match self {
            Self::Internal(csrng) => Ok(csrng.generate12()?.into()),
            Self::External(trng_ext) => trng_ext.generate(),
            Self::MfgMode() => {
                unsafe {
                    let soc_ifc = SocIfcReg::new();
                    if soc_ifc.regs().cptra_security_state().read().debug_locked() {
                        cfi_panic_handler(
                            CaliptraError::CFI_PANIC_FAKE_TRNG_USED_WITH_DEBUG_LOCK.into(),
                        )
                    }
                }
                Ok(array::from_fn(|_| 0xdeadbeef_u32).into())
            }
            _ => unsafe {
                cfi_panic_handler(CaliptraError::CFI_PANIC_UNEXPECTED_MATCH_BRANCH.into())
            },
        }
    }
}
