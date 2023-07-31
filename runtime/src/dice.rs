// Licensed under the Apache-2.0 license

use caliptra_drivers::{CaliptraError, CaliptraResult, DataVault};
use caliptra_x509::{Ecdsa384CertBuilder, Ecdsa384Signature, FmcAliasCertTbs, LocalDevIdCertTbs};
use crate::{MailboxResp, MailboxRespHeader, GetLdevCertResp, TestGetFmcAliasCertResp};

extern "C" {
    static mut LDEVID_TBS_ORG: [u8; LocalDevIdCertTbs::TBS_TEMPLATE_LEN];
    static mut FMCALIAS_TBS_ORG: [u8; FmcAliasCertTbs::TBS_TEMPLATE_LEN];
}

enum CertType {
    LDevId,
    FmcAlias,
}

pub struct GetLdevCertCmd;
impl GetLdevCertCmd {
    pub(crate) fn execute(dv: &DataVault) -> CaliptraResult<MailboxResp> {
        let mut resp = GetLdevCertResp {
            hdr: MailboxRespHeader::default(),
            data_size: 0,
            data: [0u8; GetLdevCertResp::DATA_MAX_SIZE],
        };

        resp.data_size = copy_ldevid_cert(dv, &mut resp.data)? as u32;

        Ok(MailboxResp::GetLdevCert(resp))
    }
}

pub struct TestGetFmcAliasCertCmd;
impl TestGetFmcAliasCertCmd {
    pub(crate) fn execute(dv: &DataVault) -> CaliptraResult<MailboxResp> {
        let mut resp = TestGetFmcAliasCertResp {
            hdr: MailboxRespHeader::default(),
            data_size: 0,
            data: [0u8; TestGetFmcAliasCertResp::DATA_MAX_SIZE],
        };

        resp.data_size = copy_fmc_alias_cert(dv, &mut resp.data)? as u32;

        Ok(MailboxResp::TestGetFmcAliasCert(resp))
    }
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
