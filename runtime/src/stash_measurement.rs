/*++

Licensed under the Apache-2.0 license.

File Name:

    stash_measurement.rs

Abstract:

    File contains StashMeasurement mailbox command.

--*/

use crate::{dpe_crypto::DpeCrypto, CptraDpeTypes, DpePlatform, Drivers, PauserPrivileges};
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_common::mailbox_api::{
    MailboxResp, MailboxRespHeader, StashMeasurementReq, StashMeasurementResp,
};
use caliptra_drivers::{pcr_log::PCR_ID_STASH_MEASUREMENT, CaliptraError, CaliptraResult};
use crypto::{AlgLen, Crypto};
use dpe::{
    commands::{CommandExecution, DeriveContextCmd, DeriveContextFlags},
    context::ContextHandle,
    dpe_instance::DpeEnv,
    response::DpeErrorCode,
};
use zerocopy::{AsBytes, FromBytes};

pub struct StashMeasurementCmd;
impl StashMeasurementCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn stash_measurement(
        drivers: &mut Drivers,
        metadata: &[u8; 4],
        measurement: &[u8; 48],
    ) -> CaliptraResult<DpeErrorCode> {
        let dpe_result = {
            match drivers.caller_privilege_level() {
                // Only PL0 can call STASH_MEASUREMENT
                PauserPrivileges::PL0 => (),
                PauserPrivileges::PL1 => {
                    return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
                }
            }

            // Check that adding this measurement to DPE doesn't cause
            // the PL0 context threshold to be exceeded.
            drivers.is_dpe_context_threshold_exceeded()?;

            let hashed_rt_pub_key = drivers.compute_rt_alias_sn()?;
            let key_id_rt_cdi = Drivers::get_key_id_rt_cdi(drivers)?;
            let key_id_rt_priv_key = Drivers::get_key_id_rt_priv_key(drivers)?;
            let pdata = drivers.persistent_data.get_mut();
            let mut crypto = DpeCrypto::new(
                &mut drivers.sha384,
                &mut drivers.trng,
                &mut drivers.ecc384,
                &mut drivers.hmac384,
                &mut drivers.key_vault,
                &mut pdata.fht.rt_dice_pub_key,
                key_id_rt_cdi,
                key_id_rt_priv_key,
            );
            let (nb, nf) = Drivers::get_cert_validity_info(&pdata.manifest1);
            let mut env = DpeEnv::<CptraDpeTypes> {
                crypto,
                platform: DpePlatform::new(
                    pdata.manifest1.header.pl0_pauser,
                    &hashed_rt_pub_key,
                    &drivers.cert_chain,
                    &nb,
                    &nf,
                    None,
                ),
            };

            let locality = drivers.mbox.user();

            let derive_context_resp = DeriveContextCmd {
                handle: ContextHandle::default(),
                data: *measurement,
                flags: DeriveContextFlags::MAKE_DEFAULT
                    | DeriveContextFlags::CHANGE_LOCALITY
                    | DeriveContextFlags::INPUT_ALLOW_CA
                    | DeriveContextFlags::INPUT_ALLOW_X509,
                tci_type: u32::from_ne_bytes(*metadata),
                target_locality: locality,
            }
            .execute(&mut pdata.dpe, &mut env, locality);

            match derive_context_resp {
                Ok(_) => DpeErrorCode::NoError,
                Err(e) => {
                    // If there is extended error info, populate CPTRA_FW_EXTENDED_ERROR_INFO
                    if let Some(ext_err) = e.get_error_detail() {
                        drivers.soc_ifc.set_fw_extended_error(ext_err);
                    }
                    e
                }
            }
        };

        if let DpeErrorCode::NoError = dpe_result {
            // Extend the measurement into PCR31
            drivers.pcr_bank.extend_pcr(
                PCR_ID_STASH_MEASUREMENT,
                &mut drivers.sha384,
                measurement.as_bytes(),
            )?;
        }

        Ok(dpe_result)
    }

    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        let cmd = StashMeasurementReq::read_from(cmd_args)
            .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;

        let dpe_result = Self::stash_measurement(drivers, &cmd.metadata, &cmd.measurement)?;

        Ok(MailboxResp::StashMeasurement(StashMeasurementResp {
            hdr: MailboxRespHeader::default(),
            dpe_result: dpe_result.get_error_code(),
        }))
    }
}
