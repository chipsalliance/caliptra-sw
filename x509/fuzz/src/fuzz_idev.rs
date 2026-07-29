// Licensed under the Apache-2.0 license

#![cfg_attr(feature = "libfuzzer-sys", no_main)]

#[cfg(all(not(feature = "libfuzzer-sys"), not(feature = "afl")))]
compile_error!("Either feature \"libfuzzer-sys\" or \"afl\" must be enabled!");

#[cfg(feature = "libfuzzer-sys")]
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "afl")]
use afl::fuzz;

use arbitrary::Arbitrary;
use caliptra_x509::{InitDevIdCsrTbs, InitDevIdCsrTbsParams};
use x509_fuzz_common::build_and_validate_csr;

#[derive(Debug, Arbitrary)]
struct IdevParams {
    public_key: [u8; InitDevIdCsrTbsParams::PUBLIC_KEY_LEN],
    subject_sn: [u8; InitDevIdCsrTbsParams::SUBJECT_SN_LEN],
    ueid: [u8; InitDevIdCsrTbsParams::UEID_LEN],
}

impl IdevParams {
    fn build<'a>(&'a self) -> InitDevIdCsrTbsParams<'a> {
        InitDevIdCsrTbsParams {
            public_key: &self.public_key,
            subject_sn: &self.subject_sn,
            ueid: &self.ueid,
        }
    }
}

fn harness(data: &IdevParams) {
    let idev_tbs = InitDevIdCsrTbs::new(&data.build());
    build_and_validate_csr(idev_tbs.tbs());
}

// cargo-fuzz target
#[cfg(feature = "libfuzzer-sys")]
fuzz_target!(|data: IdevParams| {
    harness(&data);
});

// cargo-afl target
#[cfg(feature = "afl")]
fn main() {
    fuzz!(|data: IdevParams| {
        harness(&data);
    });
}
