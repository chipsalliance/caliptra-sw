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
#[cfg(feature = "cfi")]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::mailbox_api::{
    ActivateFirmwareReq, MailboxRespHeader, StashMeasurementReq, StashMeasurementResp,
};
use caliptra_dpe::{
    commands::{Command, DeriveContextCmd, DeriveContextFlags},
    context::ContextHandle,
    error::DpeErrorCode,
    response::DeriveContextResp,
    tci::TciMeasurement,
};
use caliptra_drivers::{pcr_log::PCR_ID_STASH_MEASUREMENT, CaliptraError, CaliptraResult};
use zerocopy::{FromBytes, IntoBytes};

const MCU_TCI_TYPE: u32 = u32::from_be_bytes(*b"MCFW");

/// Firmware ID reserved for the Caliptra-managed MCU runtime DPE context.
///
/// Measurements stashed under this ID are tagged with the `MCFW` TCI type and
/// re-point the cached MCU RT context index, so it may only be used with a
/// measurement Caliptra has authorized against the signed SoC manifest.
pub(crate) const MCU_RT_RESERVED_FW_ID: [u8; 4] = ActivateFirmwareReq::MCU_IMAGE_ID.to_le_bytes();

/// Identifies whether Caliptra has authorized the measurement being stashed.
///
/// The reserved MCU RT firmware ID tags the measurement with the `MCFW` TCI
/// type and re-points the cached MCU RT context index, so it must only be
/// reachable with a measurement Caliptra has authorized against the signed SoC
/// manifest (or produced itself).
///
/// This deliberately has no `Default` impl and no conversion from raw mailbox
/// bytes so that a mailbox caller cannot forge [`StashAuthorization::Authorized`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum StashAuthorization {
    /// The measurement was authorized against the signed SoC manifest, or was
    /// produced by a Caliptra-internal flow such as recovery.
    Authorized,
    /// The measurement was supplied verbatim by the SoC over the mailbox and has
    /// not been authorized against the SoC manifest.
    Unauthorized,
}

pub struct StashMeasurementCmd;
impl StashMeasurementCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    /// This function MUST ONLY be called by Caliptra.
    /// Mailbox commands MUST use the `execute` function.
    ///
    /// Callers passing a measurement they have not authorized MUST pass
    /// `StashAuthorization::Unauthorized`; only authorized measurements may
    /// use `MCU_RT_RESERVED_FW_ID`.
    pub(crate) fn stash_measurement(
        drivers: &mut Drivers,
        metadata: &[u8; 4],
        measurement: &[u8; 48],
        svn: u32,
        caller_privilege_level: PauserPrivileges,
        locality: u32,
        authorization: StashAuthorization,
    ) -> CaliptraResult<DpeErrorCode> {
        // The reserved MCU RT firmware ID creates or re-points the
        // Caliptra-managed MCFW context. Reject it for unauthorized
        // measurements so the SoC cannot forge the MCU RT measurement or steal
        // its cached context index via STASH_MEASUREMENT.
        let is_mcu_rt = metadata == &MCU_RT_RESERVED_FW_ID;
        if is_mcu_rt && authorization == StashAuthorization::Unauthorized {
            return Err(CaliptraError::RUNTIME_STASH_MEASUREMENT_RESERVED_FW_ID);
        }

        let dpe_result = {
            // Check for MCU FW ID and swap it's TCI type
            let tci_type = if is_mcu_rt {
                MCU_TCI_TYPE
            } else {
                u32::from_ne_bytes(*metadata)
            };

            // Check that adding this measurement to DPE doesn't cause
            // the PL0 context threshold to be exceeded.
            drivers.is_dpe_context_threshold_exceeded(caller_privilege_level)?;

            let invoke_derive_context = |drivers: &mut Drivers, flags: DeriveContextFlags| {
                let cmd = DeriveContextCmd {
                    handle: ContextHandle::default(),
                    data: TciMeasurement(*measurement),
                    flags,
                    tci_type,
                    target_locality: locality,
                    svn,
                };

                let profile = CaliptraDpeProfile::Ecc384;
                let cmd = &Command::from(&cmd);
                let mut resp_buf = [0u32; size_of::<DeriveContextResp>() / 4];
                let resp = resp_buf.as_mut_bytes();
                let ueid = Some(drivers.soc_ifc.fuse_bank().ueid());
                invoke_dpe_cmd(profile, drivers, cmd, None, ueid, Some(locality), resp)
            };
            let flags = DeriveContextFlags::MAKE_DEFAULT
                | DeriveContextFlags::CHANGE_LOCALITY
                | DeriveContextFlags::ALLOW_NEW_CONTEXT_TO_EXPORT
                | DeriveContextFlags::INPUT_ALLOW_X509
                | DeriveContextFlags::ALLOW_RECURSIVE;
            let result = invoke_derive_context(drivers, flags).or_else(|e| {
                if e == DpeErrorCode::InvalidArgument {
                    invoke_derive_context(drivers, DeriveContextFlags::RECURSIVE)
                } else {
                    Err(e)
                }
            });
            match result {
                Ok(_) => DpeErrorCode::NoError,
                Err(e) => {
                    // If there is extended error info, populate CPTRA_FW_EXTENDED_ERROR_INFO
                    if let Some(ext_err) = crate::invoke_dpe::dpe_error_detail(&e) {
                        drivers.soc_ifc.set_fw_extended_error(ext_err);
                    }
                    e
                }
            }
        };

        if let DpeErrorCode::NoError = dpe_result {
            if is_mcu_rt {
                let mcu_rt_dpe_context_idx = drivers
                    .persistent_data
                    .get()
                    .state
                    .get_active_context_pos(&ContextHandle::default(), locality)
                    .map_err(|_| CaliptraError::RUNTIME_DPE_CONTEXT_NOT_FOUND)?;
                let mcu_rt_dpe_context_idx = u8::try_from(mcu_rt_dpe_context_idx)
                    .map_err(|_| CaliptraError::RUNTIME_DPE_CONTEXT_NOT_FOUND)?;
                drivers
                    .persistent_data
                    .get_mut()
                    .caliptra_managed_dpe_context_indices
                    .set_mcu_rt(mcu_rt_dpe_context_idx);
            }

            // Extend the measurement into PCR31
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
            StashAuthorization::Unauthorized,
        )?;

        let resp = mutrefbytes::<StashMeasurementResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.dpe_result = dpe_result.get_error_code();
        Ok(core::mem::size_of::<StashMeasurementResp>())
    }
}
