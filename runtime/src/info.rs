// Licensed under the Apache-2.0 license

use crate::{handoff::RtHandoff, Drivers};
use caliptra_common::mailbox_api::{
    FwInfoResp, GetIdevCertReq, GetIdevCertResp, GetIdevInfoResp, MailboxResp, MailboxRespHeader,
};
use caliptra_drivers::{CaliptraError, CaliptraResult};
use caliptra_x509::{Ecdsa384CertBuilder, Ecdsa384Signature};
use zerocopy::FromBytes;

pub struct FwInfoCmd;
impl FwInfoCmd {
    pub(crate) fn execute(drivers: &Drivers) -> CaliptraResult<MailboxResp> {
        let pdata = drivers.persistent_data.get();

        let handoff = RtHandoff {
            data_vault: &drivers.data_vault,
            fht: &pdata.fht,
        };

        let runtime_svn = handoff.rt_svn()?;
        let min_runtime_svn = handoff.rt_min_svn()?;
        let fmc_manifest_svn = handoff.fmc_svn()?;

        Ok(MailboxResp::FwInfo(FwInfoResp {
            hdr: MailboxRespHeader::default(),
            pl0_pauser: pdata.manifest1.header.pl0_pauser,
            runtime_svn,
            min_runtime_svn,
            fmc_manifest_svn,
            attestation_disabled: drivers.attestation_disabled.into(),
        }))
    }
}

pub struct IDevIdInfoCmd;
impl IDevIdInfoCmd {
    pub(crate) fn execute(drivers: &Drivers) -> CaliptraResult<MailboxResp> {
        let pdata = drivers.persistent_data.get();
        let pub_key = pdata.fht.idev_dice_pub_key;

        Ok(MailboxResp::GetIdevInfo(GetIdevInfoResp {
            hdr: MailboxRespHeader::default(),
            idev_pub_x: pub_key.x.into(),
            idev_pub_y: pub_key.y.into(),
        }))
    }
}

pub struct IDevIdCertCmd;
impl IDevIdCertCmd {
    pub(crate) fn execute(cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        if let Some(cmd) = GetIdevCertReq::read_from(cmd_args) {
            // Validate tbs
            let Ok(in_len) = usize::try_from(cmd.tbs_size) else {
                return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
            };
            if in_len > cmd.tbs.len() {
                return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
            }

            let sig = Ecdsa384Signature {
                r: cmd.signature_r,
                s: cmd.signature_s,
            };

            let Some(builder) = Ecdsa384CertBuilder::new(&cmd.tbs[..in_len], &sig) else {
                return Err(CaliptraError::RUNTIME_GET_DEVID_CERT_FAILED);
            };

            let mut cert = [0; GetIdevCertResp::DATA_MAX_SIZE];
            let Some(cert_size) = builder.build(&mut cert) else {
                return Err(CaliptraError::RUNTIME_GET_DEVID_CERT_FAILED);
            };
            let Ok(cert_size) = u32::try_from(cert_size) else {
                return Err(CaliptraError::RUNTIME_GET_DEVID_CERT_FAILED);
            };

            Ok(MailboxResp::GetIdevCert(GetIdevCertResp {
                hdr: MailboxRespHeader::default(),
                cert_size,
                cert,
            }))
        } else {
            Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)
        }
    }
}
