/*++

Licensed under the Apache-2.0 license.

File Name:

    reallocate_dpe_context_limits.rs

Abstract:

    File contains mailbox command implementation for reallocating DPE contexts between PL0 and PL1.

--*/

use crate::Drivers;
use crate::{
    PauserPrivileges, PL0_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD,
    PL0_DPE_ACTIVE_CONTEXT_THRESHOLD_MIN, PL1_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD,
};
use caliptra_common::cprint;
use caliptra_common::mailbox_api::{
    MailboxResp, MailboxRespHeader, ReallocateDpeContextLimitsReq, ReallocateDpeContextLimitsResp,
};
use caliptra_drivers::{CaliptraError, CaliptraResult};
use caliptra_image_types::RomInfo;
use dpe::context::{Context, ContextState, ContextType};

use zerocopy::FromBytes;

pub struct ReallocateDpeContextLimitsCmd;
impl ReallocateDpeContextLimitsCmd {
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_bytes: &[u8]) -> CaliptraResult<MailboxResp> {
        let cmd = ReallocateDpeContextLimitsReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;

        const TOTAL_DPE_CONTEXT_LIMIT: usize =
            PL0_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD + PL1_DPE_ACTIVE_CONTEXT_DEFAULT_THRESHOLD;
        let pl1_context_limit = TOTAL_DPE_CONTEXT_LIMIT as u32 - cmd.pl0_context_limit;

        // Only allowed by PL0
        if drivers.caller_privilege_level() != PauserPrivileges::PL0 {
            Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL)?
        }

        // Error checking for distribution limits
        if cmd.pl0_context_limit < PL0_DPE_ACTIVE_CONTEXT_THRESHOLD_MIN as u32 {
            Err(CaliptraError::RUNTIME_REALLOCATE_DPE_CONTEXTS_PL0_LESS_THAN_MIN)?
        }
        if cmd.pl0_context_limit > TOTAL_DPE_CONTEXT_LIMIT as u32 {
            Err(CaliptraError::RUNTIME_REALLOCATE_DPE_CONTEXTS_PL0_GREATER_THAN_MAX)?
        }

        // Error checking against used contexts
        let (used_pl0_dpe_context_count, used_pl1_dpe_context_count) =
            drivers.dpe_get_used_context_counts()?;

        if cmd.pl0_context_limit < used_pl0_dpe_context_count as u32 {
            Err(CaliptraError::RUNTIME_REALLOCATE_DPE_CONTEXTS_PL0_LESS_THAN_USED)?
        }
        if pl1_context_limit < used_pl1_dpe_context_count as u32 {
            Err(CaliptraError::RUNTIME_REALLOCATE_DPE_CONTEXTS_PL1_LESS_THAN_USED)?
        }

        // Update limits in persistent data now that error checking has passed
        drivers.persistent_data.get_mut().dpe_pl0_context_limit = cmd.pl0_context_limit as u8;
        drivers.persistent_data.get_mut().dpe_pl1_context_limit =
            TOTAL_DPE_CONTEXT_LIMIT as u8 - cmd.pl0_context_limit as u8;

        let resp = ReallocateDpeContextLimitsResp {
            hdr: MailboxRespHeader::default(),
            new_pl0_context_limit: drivers.persistent_data.get().dpe_pl0_context_limit as u32,
            new_pl1_context_limit: drivers.persistent_data.get().dpe_pl1_context_limit as u32,
        };

        Ok(MailboxResp::ReallocateDpeContextLimits(resp))
    }
}
