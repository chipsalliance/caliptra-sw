// Licensed under the Apache-2.0 license

use crate::{dpe_crypto::DpeCrypto, CptraDpeTypes, DpePlatform, Drivers};
use caliptra_common::mailbox_api::{
    MailboxResp, MailboxRespHeader, StashMeasurementReq, StashMeasurementResp,
};
use caliptra_drivers::{CaliptraError, CaliptraResult};
use crypto::{AlgLen, Crypto};
use dpe::{
    commands::{CommandExecution, DeriveChildCmd, DeriveChildFlags},
    context::ContextHandle,
    dpe_instance::DpeEnv,
    response::DpeErrorCode,
};
use zerocopy::FromBytes;

pub struct StashMeasurementCmd;
impl StashMeasurementCmd {
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        if let Some(cmd) = StashMeasurementReq::read_from(cmd_args) {
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
            let hashed_rt_pub_key = crypto
                .hash(AlgLen::Bit384, &rt_pub_key.to_der()[1..])
                .map_err(|_| CaliptraError::RUNTIME_INITIALIZE_DPE_FAILED)?;
            let mut env = DpeEnv::<CptraDpeTypes> {
                crypto,
                platform: DpePlatform::new(pdata.manifest1.header.pl0_pauser, hashed_rt_pub_key),
            };

            let locality = drivers.mbox.user();
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
            .execute(&mut drivers.dpe, &mut env, locality);

            let dpe_result = match derive_child_resp {
                Ok(_) => DpeErrorCode::NoError,
                Err(e) => e,
            } as u32;

            Ok(MailboxResp::StashMeasurement(StashMeasurementResp {
                hdr: MailboxRespHeader::default(),
                dpe_result,
            }))
        } else {
            Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)
        }
    }
}
