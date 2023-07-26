// Licensed under the Apache-2.0 license

use caliptra_drivers::{CaliptraError, CaliptraResult, DataVault};
use caliptra_x509::{Ecdsa384CertBuilder, Ecdsa384Signature, FmcAliasCertTbs, LocalDevIdCertTbs};
use crate::{MailboxRespHeader, TestGetCertResp};

extern "C" {
    static mut LDEVID_TBS_ORG: [u8; LocalDevIdCertTbs::TBS_TEMPLATE_LEN];
    static mut FMCALIAS_TBS_ORG: [u8; FmcAliasCertTbs::TBS_TEMPLATE_LEN];
}

enum CertType {
    LDevId,
    FmcAlias,
}

/// Copy LDevID certificate produced by ROM to `cert` buffer
///
/// Returns the number of bytes written to `cert`
#[inline(never)]
pub fn copy_ldevid_cert(dv: &DataVault, cert: &mut [u8]) -> CaliptraResult<usize> {
    cert_from_dccm(dv, cert, CertType::LDevId)
}

/// Copy FMC Alias certificate produced by ROM to `cert` buffer
///
/// Returns the number of bytes written to `cert`
#[inline(never)]
pub fn copy_fmc_alias_cert(dv: &DataVault, cert: &mut [u8]) -> CaliptraResult<usize> {
    cert_from_dccm(dv, cert, CertType::FmcAlias)
}

/// Copy a certificate from `dccm_offset`, append signature, and write the
/// output to `cert`.
fn cert_from_dccm(dv: &DataVault, cert: &mut [u8], cert_type: CertType) -> CaliptraResult<usize> {
    let (tbs, sig) = match cert_type {
        CertType::LDevId => (unsafe { &LDEVID_TBS_ORG[..] }, dv.ldev_dice_signature()),
        CertType::FmcAlias => (unsafe { &FMCALIAS_TBS_ORG[..] }, dv.fmc_dice_signature()),
    };

    // DataVault returns a different type than CertBuilder accepts
    let bldr_sig = Ecdsa384Signature {
        r: sig.r.into(),
        s: sig.s.into(),
    };
    let Some(builder) = Ecdsa384CertBuilder::new(tbs, &bldr_sig) else {
        return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
    };

    let Some(size) = builder.build(cert) else {
        return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
    };

    Ok(size)
}

/// Handle the get ldev cert message
///
/// Returns a TestGetCertResp and optionally the response size
pub fn handle_get_ldevid_cert(dv: &DataVault) -> CaliptraResult<(TestGetCertResp, Option<usize>)> {
    let mut resp = TestGetCertResp {
        hdr: MailboxRespHeader::default(),
        data: [0u8; 1024],
    };

    let cert_size = copy_ldevid_cert(dv, &mut resp.data)?;

    Ok((resp, Some(cert_size + core::mem::size_of::<MailboxRespHeader>())))
}

/// Handle the get fmc alias cert message
///
/// Returns a TestGetCertResp and optionally the response size
pub fn handle_get_fmc_alias_cert(dv: &DataVault) -> CaliptraResult<(TestGetCertResp, Option<usize>)> {
    let mut resp = TestGetCertResp {
        hdr: MailboxRespHeader::default(),
        data: [0u8; 1024],
    };

    let cert_size = copy_fmc_alias_cert(dv, &mut resp.data)?;

    Ok((resp, Some(cert_size + core::mem::size_of::<MailboxRespHeader>())))
}