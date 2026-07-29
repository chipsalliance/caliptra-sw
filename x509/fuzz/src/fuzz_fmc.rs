// Licensed under the Apache-2.0 license

#![cfg_attr(feature = "libfuzzer-sys", no_main)]

#[cfg(all(not(feature = "libfuzzer-sys"), not(feature = "afl")))]
compile_error!("Either feature \"libfuzzer-sys\" or \"afl\" must be enabled!");

#[cfg(feature = "libfuzzer-sys")]
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "afl")]
use afl::fuzz;

use arbitrary::Arbitrary;
use caliptra_x509::{FmcAliasCertTbs, FmcAliasCertTbsParams};
use x509_fuzz_common::build_and_validate_cert;

#[derive(Debug, Arbitrary)]
struct FmcParams {
    _serial_number: [u8; FmcAliasCertTbsParams::SERIAL_NUMBER_LEN],
    public_key: [u8; FmcAliasCertTbsParams::PUBLIC_KEY_LEN],
    subject_sn: [u8; FmcAliasCertTbsParams::SUBJECT_SN_LEN],
    issuer_sn: [u8; FmcAliasCertTbsParams::ISSUER_SN_LEN],
    ueid: [u8; FmcAliasCertTbsParams::UEID_LEN],
    subject_key_id: [u8; FmcAliasCertTbsParams::SUBJECT_KEY_ID_LEN],
    authority_key_id: [u8; FmcAliasCertTbsParams::AUTHORITY_KEY_ID_LEN],
    tcb_info_flags: [u8; FmcAliasCertTbsParams::TCB_INFO_FLAGS_LEN],
    tcb_info_device_info_hash: [u8; FmcAliasCertTbsParams::TCB_INFO_DEVICE_INFO_HASH_LEN],
    tcb_info_fmc_tci: [u8; FmcAliasCertTbsParams::TCB_INFO_FMC_TCI_LEN],
    tcb_info_fmc_svn: [u8; FmcAliasCertTbsParams::TCB_INFO_FMC_SVN_LEN],
    tcb_info_fmc_svn_fuses: [u8; FmcAliasCertTbsParams::TCB_INFO_FMC_SVN_FUSES_LEN],
    not_before: [u8; FmcAliasCertTbsParams::NOT_BEFORE_LEN],
    not_after: [u8; FmcAliasCertTbsParams::NOT_AFTER_LEN],
}

impl FmcParams {
    fn build<'a>(&'a self) -> FmcAliasCertTbsParams<'a> {
        FmcAliasCertTbsParams {
            // TODO: ASN.1 integers with the top bit set are invalid, so X.509
            // from_der fails. A better way to deal with this might be to
            // unconditionally set the top bit to 0.
            serial_number: &[0x1F; FmcAliasCertTbsParams::SERIAL_NUMBER_LEN],
            public_key: &self.public_key,
            subject_sn: &self.subject_sn,
            issuer_sn: &self.issuer_sn,
            ueid: &self.ueid,
            subject_key_id: &self.subject_key_id,
            authority_key_id: &self.authority_key_id,
            tcb_info_flags: &self.tcb_info_flags,
            tcb_info_device_info_hash: &self.tcb_info_device_info_hash,
            tcb_info_fmc_tci: &self.tcb_info_fmc_tci,
            tcb_info_fmc_svn: &self.tcb_info_fmc_svn,
            tcb_info_fmc_svn_fuses: &self.tcb_info_fmc_svn_fuses,
            not_before: &self.not_before,
            not_after: &self.not_after,
        }
    }
}

fn harness(data: &FmcParams) {
    let fmc_tbs = FmcAliasCertTbs::new(&data.build());
    build_and_validate_cert(fmc_tbs.tbs());
}

// cargo-fuzz target
#[cfg(feature = "libfuzzer-sys")]
fuzz_target!(|data: FmcParams| {
    harness(&data);
});

// cargo-afl target
#[cfg(feature = "afl")]
fn main() {
    fuzz!(|data: FmcParams| {
        harness(&data);
    });
}
