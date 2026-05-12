/*++

Licensed under the Apache-2.0 license.

File Name:

    stash_measurement.rs

Abstract:

    File contains StashMeasurement mailbox command.

--*/

use crate::{
    invoke_dpe::invoke_dpe_cmd, mutrefbytes, CaliptraDpeProfile, Drivers, PauserPrivileges,
};
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::mailbox_api::{MailboxRespHeader, StashMeasurementReq, StashMeasurementResp};
use caliptra_dpe::{
    commands::{Command, DeriveContextCmd, DeriveContextFlags},
    context::{ContextHandle, ContextState},
    response::{DeriveContextResp, DpeErrorCode},
    tci::TciMeasurement,
};
use caliptra_drivers::{pcr_log::PCR_ID_STASH_MEASUREMENT, CaliptraError, CaliptraResult};
use zerocopy::{FromBytes, IntoBytes};

const MCU_TCI_TYPE: u32 = u32::from_be_bytes(*b"MCFW");

pub struct StashMeasurementCmd;
impl StashMeasurementCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    /// This function MUST ONLY be called by Caliptra.
    /// Mailbox commands MUST use the `execute` function.
    pub(crate) fn stash_measurement(
        drivers: &mut Drivers,
        metadata: &[u8; 4],
        measurement: &[u8; 48],
        svn: u32,
        caller_privilege_level: PauserPrivileges,
        locality: u32,
    ) -> CaliptraResult<DpeErrorCode> {
        let dpe_result = {
            // Check for MCU FW ID and swap it's TCI type
            let tci_type = if metadata == &[2, 0, 0, 0] {
                MCU_TCI_TYPE
            } else {
                u32::from_ne_bytes(*metadata)
            };

            // Check that adding this measurement to DPE doesn't cause
            // the PL0 context threshold to be exceeded.
            drivers.is_dpe_context_threshold_exceeded(caller_privilege_level)?;

            let cmd = DeriveContextCmd {
                handle: ContextHandle::default(),
                data: TciMeasurement(*measurement),
                flags: DeriveContextFlags::MAKE_DEFAULT
                    | DeriveContextFlags::CHANGE_LOCALITY
                    | DeriveContextFlags::ALLOW_NEW_CONTEXT_TO_EXPORT
                    | DeriveContextFlags::INPUT_ALLOW_X509
                    | DeriveContextFlags::ALLOW_RECURSIVE,
                tci_type,
                target_locality: locality,
                svn,
            };

            let profile = CaliptraDpeProfile::Ecc384;
            let cmd = &Command::from(&cmd);
            let mut resp_buf = [0u32; size_of::<DeriveContextResp>() / 4];
            let resp = resp_buf.as_mut_bytes();
            let ueid = Some(drivers.soc_ifc.fuse_bank().ueid());
            let result = &invoke_dpe_cmd(profile, drivers, cmd, None, ueid, Some(locality), resp);
            match result {
                Ok(_) => DpeErrorCode::NoError,
                Err(e) => {
                    // If there is extended error info, populate CPTRA_FW_EXTENDED_ERROR_INFO
                    if let Some(ext_err) = e.get_error_detail() {
                        drivers.soc_ifc.set_fw_extended_error(ext_err);
                    }
                    *e
                }
            }
        };

        if let DpeErrorCode::NoError = dpe_result {
            // Extend the measurement into PCR31
            drivers.pcr_bank.extend_pcr(
                PCR_ID_STASH_MEASUREMENT,
                &mut drivers.sha2_512_384,
                measurement.as_bytes(),
            )?;
        }

        Ok(dpe_result)
    }

    /// Update an existing DPE context's measurement using RECURSIVE DeriveContext.
    /// This extends the cumulative TCI without allocating a new context slot.
    ///
    /// The context to update is identified by `tci_type` (from the `context` field).
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn update_measurement(
        drivers: &mut Drivers,
        measurement: &[u8; 48],
        tci_type_bytes: &[u8; 4],
        svn: u32,
        locality: u32,
    ) -> CaliptraResult<DpeErrorCode> {
        let tci_type = u32::from_be_bytes(*tci_type_bytes);

        // Find the existing context by TCI type and locality
        let handle = {
            let dpe = &drivers.persistent_data.get().fw.dpe.state;
            let mut found = None;
            for ctx in dpe.contexts.iter() {
                if ctx.state != ContextState::Inactive
                    && ctx.tci.tci_type == tci_type
                    && ctx.locality == locality
                {
                    found = Some(ctx.handle);
                    break;
                }
            }
            found.ok_or(CaliptraError::RUNTIME_INTERNAL)?
        };

        let cmd = DeriveContextCmd {
            handle,
            data: TciMeasurement(*measurement),
            flags: DeriveContextFlags::RECURSIVE,
            tci_type,
            target_locality: locality,
            svn,
        };

        let profile = CaliptraDpeProfile::Ecc384;
        let cmd = &Command::from(&cmd);
        let mut resp_buf = [0u32; size_of::<DeriveContextResp>() / 4];
        let resp = resp_buf.as_mut_bytes();
        let ueid = Some(drivers.soc_ifc.fuse_bank().ueid());
        let dpe_result =
            match &invoke_dpe_cmd(profile, drivers, cmd, None, ueid, Some(locality), resp) {
                Ok(_) => DpeErrorCode::NoError,
                Err(e) => {
                    if let Some(ext_err) = e.get_error_detail() {
                        drivers.soc_ifc.set_fw_extended_error(ext_err);
                    }
                    *e
                }
            };

        if let DpeErrorCode::NoError = dpe_result {
            drivers.pcr_bank.extend_pcr(
                PCR_ID_STASH_MEASUREMENT,
                &mut drivers.sha2_512_384,
                measurement.as_bytes(),
            )?;
        }

        Ok(dpe_result)
    }

    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let caller_privilege_level = drivers.caller_privilege_level();
        match caller_privilege_level {
            // Only PL0 can call STASH_MEASUREMENT
            PauserPrivileges::PL0 => (),
            PauserPrivileges::PL1 => {
                return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
            }
        }

        let cmd = StashMeasurementReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
        let locality = drivers.mbox.id();

        let dpe_result = Self::stash_measurement(
            drivers,
            &cmd.metadata,
            &cmd.measurement,
            cmd.svn,
            caller_privilege_level,
            locality,
        )?;

        let resp = mutrefbytes::<StashMeasurementResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.dpe_result = dpe_result.get_error_code();
        Ok(core::mem::size_of::<StashMeasurementResp>())
    }
}
