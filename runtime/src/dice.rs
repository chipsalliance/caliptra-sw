// Licensed under the Apache-2.0 license

#[cfg(feature = "test_only_commands")]
use caliptra_common::mailbox_api::{
    GetLdevCertResp, MailboxResp, MailboxRespHeader, TestGetFmcAliasCertResp,
};

#[cfg(feature = "test_only_commands")]
use crate::Drivers;

use caliptra_drivers::{CaliptraError, CaliptraResult, DataVault, PersistentData};
use caliptra_x509::{Ecdsa384CertBuilder, Ecdsa384Signature};

enum CertType {
    LDevId,
    FmcAlias,
}

pub struct GetLdevCertCmd;
impl GetLdevCertCmd {
    #[cfg(feature = "test_only_commands")]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<MailboxResp> {
        let mut resp = GetLdevCertResp {
            hdr: MailboxRespHeader::default(),
            data_size: 0,
            data: [0u8; GetLdevCertResp::DATA_MAX_SIZE],
        };

        resp.data_size = copy_ldevid_cert(
            &drivers.data_vault,
            drivers.persistent_data.get(),
            &mut resp.data,
        )? as u32;

        Ok(MailboxResp::GetLdevCert(resp))
    }
}

pub struct TestGetFmcAliasCertCmd;
impl TestGetFmcAliasCertCmd {
    #[cfg(feature = "test_only_commands")]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<MailboxResp> {
        let mut resp = TestGetFmcAliasCertResp {
            hdr: MailboxRespHeader::default(),
            data_size: 0,
            data: [0u8; TestGetFmcAliasCertResp::DATA_MAX_SIZE],
        };

        resp.data_size = copy_fmc_alias_cert(
            &drivers.data_vault,
            drivers.persistent_data.get(),
            &mut resp.data,
        )? as u32;

        Ok(MailboxResp::TestGetFmcAliasCert(resp))
    }
}

/// Copy LDevID certificate produced by ROM to `cert` buffer
///
/// Returns the number of bytes written to `cert`
#[inline(never)]
pub fn copy_ldevid_cert(
    dv: &DataVault,
    persistent_data: &PersistentData,
    cert: &mut [u8],
) -> CaliptraResult<usize> {
    cert_from_dccm(dv, persistent_data, cert, CertType::LDevId)
}

/// Copy FMC Alias certificate produced by ROM to `cert` buffer
///
/// Returns the number of bytes written to `cert`
#[inline(never)]
pub fn copy_fmc_alias_cert(
    dv: &DataVault,
    persistent_data: &PersistentData,
    cert: &mut [u8],
) -> CaliptraResult<usize> {
    cert_from_dccm(dv, persistent_data, cert, CertType::FmcAlias)
}

/// Copy a certificate from `dccm_offset`, append signature, and write the
/// output to `cert`.
fn cert_from_dccm(
    dv: &DataVault,
    persistent_data: &PersistentData,
    cert: &mut [u8],
    cert_type: CertType,
) -> CaliptraResult<usize> {
    let (tbs, sig) = match cert_type {
        CertType::LDevId => (
            persistent_data
                .ldevid_tbs
                .get(..persistent_data.fht.ldevid_tbs_size.into()),
            dv.ldev_dice_signature(),
        ),
        CertType::FmcAlias => (
            persistent_data
                .fmcalias_tbs
                .get(..persistent_data.fht.fmcalias_tbs_size.into()),
            dv.fmc_dice_signature(),
        ),
    };
    let Some(tbs) = tbs else {
        return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
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
