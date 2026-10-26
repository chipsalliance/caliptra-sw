// Licensed under the Apache-2.0 license
//
#![no_std]
#![cfg_attr(hw_rev = "latest", doc = "Hardware revision: _latest_")]
#![cfg_attr(hw_rev = "2.1", doc = "Hardware revision: _2.1_")]
#![cfg_attr(hw_rev = "2.0", doc = "Hardware revision: _2.0_")]

#[cfg(not(any(hw_rev = "latest", hw_rev = "2.1", hw_rev = "2.0")))]
compile_error!("Select one of the supported HW revisions by setting the `hw_rev` cfg");

#[cfg(hw_rev = "latest")]
pub use caliptra_registers_latest::*;

#[cfg(hw_rev = "2.1")]
pub use caliptra_registers_rev_2_1::*;

#[cfg(hw_rev = "2.0")]
compile_error!("TODO: add v2.0 HW register definitions");

// Provide a facade that unifies the divergence in type and method names between
// <2.2 and >=2.2 RTL revisions.
#[cfg(any(hw_rev = "2.2", hw_rev = "latest"))]
mod register_facade {
    pub trait EntropyThresholdReadValFacade {
        fn fips_thresh(&self) -> u32;
    }

    pub trait EntropyThresholdWriteValFacade {
        fn fips_thresh(self, val: u32) -> Self;
    }

    macro_rules! entropy_threshold_facade {
        ($read_val:ty, $write_val:ty, $field:ident) => {
            impl EntropyThresholdReadValFacade for $read_val {
                fn fips_thresh(&self) -> u32 {
                    self.$field()
                }
            }

            impl EntropyThresholdWriteValFacade for $write_val {
                fn fips_thresh(self, val: u32) -> Self {
                    self.$field(val)
                }
            }
        };
    }

    entropy_threshold_facade!(
        crate::entropy_src::regs::RepcntThresholdReadVal,
        crate::entropy_src::regs::RepcntThresholdWriteVal,
        repcnt_threshold
    );
    entropy_threshold_facade!(
        crate::entropy_src::regs::RepcntsThresholdReadVal,
        crate::entropy_src::regs::RepcntsThresholdWriteVal,
        repcnts_threshold
    );
    entropy_threshold_facade!(
        crate::entropy_src::regs::AdaptpHiThresholdReadVal,
        crate::entropy_src::regs::AdaptpHiThresholdWriteVal,
        adaptp_hi_threshold
    );
    entropy_threshold_facade!(
        crate::entropy_src::regs::AdaptpLoThresholdReadVal,
        crate::entropy_src::regs::AdaptpLoThresholdWriteVal,
        adaptp_lo_threshold
    );

    pub trait EntropySrcRegisterBlockFacade<TMmio: caliptra_ureg::Mmio> {
        fn repcnt_thresholds(
            &self,
        ) -> caliptra_ureg::RegRef<crate::entropy_src::meta::RepcntThreshold, &TMmio>;

        fn repcnts_thresholds(
            &self,
        ) -> caliptra_ureg::RegRef<crate::entropy_src::meta::RepcntsThreshold, &TMmio>;

        fn adaptp_hi_thresholds(
            &self,
        ) -> caliptra_ureg::RegRef<crate::entropy_src::meta::AdaptpHiThreshold, &TMmio>;

        fn adaptp_lo_thresholds(
            &self,
        ) -> caliptra_ureg::RegRef<crate::entropy_src::meta::AdaptpLoThreshold, &TMmio>;
    }

    impl<TMmio: caliptra_ureg::Mmio> EntropySrcRegisterBlockFacade<TMmio>
        for crate::entropy_src::RegisterBlock<TMmio>
    {
        fn repcnt_thresholds(
            &self,
        ) -> caliptra_ureg::RegRef<crate::entropy_src::meta::RepcntThreshold, &TMmio> {
            self.repcnt_threshold()
        }

        fn repcnts_thresholds(
            &self,
        ) -> caliptra_ureg::RegRef<crate::entropy_src::meta::RepcntsThreshold, &TMmio> {
            self.repcnts_threshold()
        }

        fn adaptp_hi_thresholds(
            &self,
        ) -> caliptra_ureg::RegRef<crate::entropy_src::meta::AdaptpHiThreshold, &TMmio> {
            self.adaptp_hi_threshold()
        }

        fn adaptp_lo_thresholds(
            &self,
        ) -> caliptra_ureg::RegRef<crate::entropy_src::meta::AdaptpLoThreshold, &TMmio> {
            self.adaptp_lo_threshold()
        }
    }

    pub use crate::{
        entropy_src::regs::{
            AdaptpHiThresholdReadVal as AdaptpHiThresholdsReadVal,
            AdaptpLoThresholdReadVal as AdaptpLoThresholdsReadVal,
            RepcntThresholdReadVal as RepcntThresholdsReadVal,
            RepcntsThresholdReadVal as RepcntsThresholdsReadVal,
        },
        soc_ifc::regs::{
            EntropyConfig0WriteVal as CptraItrngEntropyConfig0WriteVal,
            EntropyConfig1WriteVal as CptraItrngEntropyConfig1WriteVal,
        },
    };
}

#[cfg(not(any(hw_rev = "2.2", hw_rev = "latest")))]
mod register_facade {
    pub trait EntropyThresholdReadValFacade {}
    pub trait EntropyThresholdWriteValFacade {}
    pub trait EntropySrcRegisterBlockFacade {}

    pub use crate::{
        entropy_src::regs::{
            AdaptpHiThresholdsReadVal, AdaptpLoThresholdsReadVal, RepcntThresholdsReadVal,
            RepcntsThresholdsReadVal,
        },
        soc_ifc::regs::{CptraItrngEntropyConfig0WriteVal, CptraItrngEntropyConfig1WriteVal},
    };
}

pub use register_facade::*;
