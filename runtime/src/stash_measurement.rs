// Licensed under the Apache-2.0 license

use crate::{dpe_crypto::DpeCrypto, CptraDpeTypes, DpePlatform, Drivers};
use caliptra_common::mailbox_api::{
    MailboxResp, MailboxRespHeader, StashMeasurementReq, StashMeasurementResp,
};
use caliptra_drivers::{pcr_log::PCR_ID_STASH_MEASUREMENT, CaliptraError, CaliptraResult};
use crypto::{AlgLen, Crypto};
use dpe::{
    commands::{CommandExecution, DeriveChildCmd, DeriveChildFlags},
    context::ContextHandle,
    dpe_instance::DpeEnv,
    response::DpeErrorCode,
};
use zerocopy::{AsBytes, FromBytes};

pub struct StashMeasurementCmd;
impl StashMeasurementCmd {
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        if let Some(cmd) = StashMeasurementReq::read_from(cmd_args) {
            let dpe_result = {
                let hashed_rt_pub_key = drivers.compute_rt_alias_sn()?;
                let pdata = drivers.persistent_data.get();
                let rt_pub_key = pdata.fht.rt_dice_pub_key;
                let mut crypto = DpeCrypto::new(
                    &mut drivers.sha384,
                    &mut drivers.trng,
                    &mut drivers.ecc384,
                    &mut drivers.hmac384,
                    &mut drivers.key_vault,
                    rt_pub_key,
                );
                let mut env = DpeEnv::<CptraDpeTypes> {
                    crypto,
                    platform: DpePlatform::new(
                        pdata.manifest1.header.pl0_pauser,
                        hashed_rt_pub_key,
                        &mut drivers.cert_chain,
                    ),
                };

                let locality = drivers.mbox.user();
                // Call DeriveChild to add the measurement to DPE
                let derive_child_resp = DeriveChildCmd {
                    handle: ContextHandle::default(),
                    data: cmd.measurement,
                    flags: DeriveChildFlags::MAKE_DEFAULT
                        | DeriveChildFlags::CHANGE_LOCALITY
                        | DeriveChildFlags::INPUT_ALLOW_CA
                        | DeriveChildFlags::INPUT_ALLOW_X509,
                    tci_type: u32::from_be_bytes(cmd.metadata),
                    target_locality: locality,
                }
                .execute(
                    &mut drivers.persistent_data.get_mut().dpe,
                    &mut env,
                    locality,
                );

                match derive_child_resp {
                    Ok(_) => DpeErrorCode::NoError,
                    Err(e) => e,
                }
            };

            if let DpeErrorCode::NoError = dpe_result {
                // Extend the measurement into PCR31
                drivers.pcr_bank.extend_pcr(
                    PCR_ID_STASH_MEASUREMENT,
                    &mut drivers.sha384,
                    cmd.measurement.as_bytes(),
                )?;
            }

            Ok(MailboxResp::StashMeasurement(StashMeasurementResp {
                hdr: MailboxRespHeader::default(),
                dpe_result: dpe_result as u32,
            }))
        } else {
            Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)
        }
    }
}
