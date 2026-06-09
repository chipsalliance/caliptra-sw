/*++

Licensed under the Apache-2.0 license.

File Name:

    stash_measurement.rs

Abstract:

    File contains StashMeasurement mailbox command.

--*/

use crate::{invoke_dpe::invoke_dpe_cmd, Drivers, PauserPrivileges};
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::mailbox_api::{
    MailboxResp, MailboxRespHeader, StashMeasurementReq, StashMeasurementResp,
};
use caliptra_drivers::{pcr_log::PCR_ID_STASH_MEASUREMENT, CaliptraError, CaliptraResult};
use dpe::{
    commands::{Command, DeriveContextCmd, DeriveContextFlags},
    context::ContextHandle,
    response::{DeriveContextExportedCdiResp, DpeErrorCode},
    tci::TciMeasurement,
};
use zerocopy::{FromBytes, IntoBytes};

pub struct StashMeasurementCmd;
impl StashMeasurementCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn stash_measurement(
        drivers: &mut Drivers,
        metadata: &[u8; 4],
        measurement: &[u8; 48],
        svn: u32,
    ) -> CaliptraResult<DpeErrorCode> {
        let dpe_result = {
            let caller_privilege_level = drivers.caller_privilege_level();
            match caller_privilege_level {
                // Only PL0 can call STASH_MEASUREMENT
                PauserPrivileges::PL0 => (),
                PauserPrivileges::PL1 => {
                    return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
                }
            }

            // Check that adding this measurement to DPE doesn't cause
            // the PL0 context threshold to be exceeded.
            drivers.is_dpe_context_threshold_exceeded(caller_privilege_level)?;

            let locality = drivers.mbox.user();
            let cmd = DeriveContextCmd {
                handle: ContextHandle::default(),
                data: TciMeasurement(*measurement),
                flags: DeriveContextFlags::MAKE_DEFAULT
                    | DeriveContextFlags::CHANGE_LOCALITY
                    | DeriveContextFlags::ALLOW_NEW_CONTEXT_TO_EXPORT
                    | DeriveContextFlags::INPUT_ALLOW_X509
                    | DeriveContextFlags::ALLOW_RECURSIVE,
                tci_type: u32::from_ne_bytes(*metadata),
                target_locality: locality,
                svn,
            };
            let command = Command::from(&cmd);
            let ueid = Some(drivers.soc_ifc.fuse_bank().ueid());
            let mut buf = [0u8; size_of::<DeriveContextExportedCdiResp>()];
            let derive_context_resp =
                invoke_dpe_cmd(drivers, &command, None, ueid, Some(locality), &mut buf);

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
        let cmd = StashMeasurementReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;

        let dpe_result =
            Self::stash_measurement(drivers, &cmd.metadata, &cmd.measurement, cmd.svn)?;

        Ok(MailboxResp::StashMeasurement(StashMeasurementResp {
            hdr: MailboxRespHeader::default(),
            dpe_result: dpe_result.get_error_code(),
        }))
    }
}
