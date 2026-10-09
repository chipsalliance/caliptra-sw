// Licensed under the Apache-2.0 license

#![cfg_attr(feature = "libfuzzer-sys", no_main)]

#[cfg(all(not(feature = "libfuzzer-sys"), not(feature = "afl")))]
compile_error!("Either feature \"libfuzzer-sys\" or \"afl\" must be enabled!");

#[cfg(feature = "libfuzzer-sys")]
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "afl")]
use afl::fuzz;

use arbitrary::Arbitrary;
use caliptra_x509::{RtAliasCertTbs, RtAliasCertTbsParams};
use x509_fuzz_common::build_and_validate_cert;

#[derive(Debug, Arbitrary)]
struct RtParams {
    _serial_number: [u8; RtAliasCertTbsParams::SERIAL_NUMBER_LEN],
    public_key: [u8; RtAliasCertTbsParams::PUBLIC_KEY_LEN],
    subject_sn: [u8; RtAliasCertTbsParams::SUBJECT_SN_LEN],
    issuer_sn: [u8; RtAliasCertTbsParams::ISSUER_SN_LEN],
    ueid: [u8; RtAliasCertTbsParams::UEID_LEN],
    subject_key_id: [u8; RtAliasCertTbsParams::SUBJECT_KEY_ID_LEN],
    authority_key_id: [u8; RtAliasCertTbsParams::AUTHORITY_KEY_ID_LEN],
    tcb_info_rt_svn: [u8; RtAliasCertTbsParams::TCB_INFO_RT_SVN_LEN],
    tcb_info_rt_tci: [u8; RtAliasCertTbsParams::TCB_INFO_RT_TCI_LEN],
    not_before: [u8; RtAliasCertTbsParams::NOT_BEFORE_LEN],
    not_after: [u8; RtAliasCertTbsParams::NOT_AFTER_LEN],
}

impl RtParams {
    fn build<'a>(&'a self) -> RtAliasCertTbsParams<'a> {
        RtAliasCertTbsParams {
            // TODO: ASN.1 integers with the top bit set are invalid, so X.509
            // from_der fails. A better way to deal with this might be to
            // unconditionally set the top bit to 0.
            serial_number: &[0x1F; RtAliasCertTbsParams::SERIAL_NUMBER_LEN],
            public_key: &self.public_key,
            subject_sn: &self.subject_sn,
            issuer_sn: &self.issuer_sn,
            ueid: &self.ueid,
            subject_key_id: &self.subject_key_id,
            authority_key_id: &self.authority_key_id,
            tcb_info_rt_tci: &self.tcb_info_rt_tci,
            tcb_info_rt_svn: &self.tcb_info_rt_svn,
            not_before: &self.not_before,
            not_after: &self.not_after,
        }
    }
}

fn harness(data: &RtParams) {
    let rt_tbs = RtAliasCertTbs::new(&data.build());
    build_and_validate_cert(rt_tbs.tbs());
}

// cargo-fuzz target
#[cfg(feature = "libfuzzer-sys")]
fuzz_target!(|data: RtParams| {
    harness(&data);
});

// cargo-afl target
#[cfg(feature = "afl")]
fn main() {
    fuzz!(|data: RtParams| {
        harness(&data);
    });
}
