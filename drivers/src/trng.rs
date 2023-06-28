// Licensed under the Apache-2.0 license

use caliptra_error::CaliptraResult;
use caliptra_registers::{
    csrng::CsrngReg, entropy_src::EntropySrcReg, soc_ifc::SocIfcReg, soc_ifc_trng::SocIfcTrngReg,
};

use crate::{trng_ext::TrngExt, Array4x12, Csrng};

pub enum Trng {
    Internal(Csrng),
    External(TrngExt),
}

impl Trng {
    pub fn new(
        csrng: CsrngReg,
        entropy_src: EntropySrcReg,
        soc_ifc_trng: SocIfcTrngReg,
        soc_ifc: &SocIfcReg,
    ) -> CaliptraResult<Self> {
        if soc_ifc.regs().cptra_hw_config().read().i_trng_en() {
            Ok(Self::Internal(Csrng::new(csrng, entropy_src)?))
        } else {
            Ok(Self::External(TrngExt::new(soc_ifc_trng)))
        }
    }

    pub fn generate(&mut self) -> CaliptraResult<Array4x12> {
        match self {
            Self::Internal(csrng) => {
                let mut iter = csrng.generate(12.try_into().unwrap())?;
                Ok(Array4x12::new(core::array::from_fn(|_| {
                    iter.next().unwrap()
                })))
            }
            Self::External(trng_ext) => trng_ext.generate(),
        }
    }
}
