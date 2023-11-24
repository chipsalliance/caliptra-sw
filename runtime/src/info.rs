// Licensed under the Apache-2.0 license

use crate::{handoff::RtHandoff, Drivers, MAX_CERT_CHAIN_SIZE, PL0_PAUSER_FLAG};
use arrayvec::ArrayVec;
use caliptra_common::mailbox_api::{
    FwInfoResp, GetIdevCertReq, GetIdevCertResp, GetIdevInfoResp, MailboxResp, MailboxRespHeader,
    PopulateIdevCertReq,
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
            if cmd.tbs_size as usize > cmd.tbs.len() {
                return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
            }

            let sig = Ecdsa384Signature {
                r: cmd.signature_r,
                s: cmd.signature_s,
            };

            let Some(builder) = Ecdsa384CertBuilder::new(&cmd.tbs[..cmd.tbs_size as usize], &sig) else {
                return Err(CaliptraError::RUNTIME_GET_DEVID_CERT_FAILED);
            };

            let mut cert = [0; GetIdevCertResp::DATA_MAX_SIZE];
            let Some(cert_size) = builder.build(&mut cert) else {
                return Err(CaliptraError::RUNTIME_GET_DEVID_CERT_FAILED);
            };

            Ok(MailboxResp::GetIdevCert(GetIdevCertResp {
                hdr: MailboxRespHeader::default(),
                cert_size: cert_size as u32,
                cert,
            }))
        } else {
            Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)
        }
    }
}

pub struct PopulateIDevIdCertCmd;
impl PopulateIDevIdCertCmd {
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        if let Some(cmd) = PopulateIdevCertReq::read_from(cmd_args) {
            let cert_size = cmd.cert_size as usize;
            if cert_size > cmd.cert.len() {
                return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
            }

            let flags = drivers.persistent_data.get().manifest1.header.flags;
            // PL1 cannot call this mailbox command
            if flags & PL0_PAUSER_FLAG == 0 {
                return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
            }

            let mut tmp_chain = ArrayVec::<u8, MAX_CERT_CHAIN_SIZE>::new();
            tmp_chain
                .try_extend_from_slice(&cmd.cert[..cert_size])
                .map_err(|_| CaliptraError::RUNTIME_IDEV_CERT_POPULATION_FAILED)?;
            tmp_chain
                .try_extend_from_slice(drivers.cert_chain.as_slice())
                .map_err(|_| CaliptraError::RUNTIME_IDEV_CERT_POPULATION_FAILED)?;
            drivers.cert_chain = tmp_chain;

            Ok(MailboxResp::default())
        } else {
            Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)
        }
    }
}
