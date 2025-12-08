/*++

Licensed under the Apache-2.0 license.

File Name:

    report_hek_metadata.rs

Abstract:

    File contains OCP_LOCK_REPORT_HEK_METADATA mailbox command.

--*/

use caliptra_api::mailbox::OcpLockReportHekMetadataReq;
use caliptra_drivers::{CaliptraError, CaliptraResult, PersistentData, SocIfc};
use zerocopy::{FromBytes, IntoBytes};

use crate::flow::cold_reset::ocp_lock;

pub struct OcpLockReportHekMetadataCmd;
impl OcpLockReportHekMetadataCmd {
    #[inline(always)]
    pub(crate) fn execute(
        cmd_bytes: &[u8],
        soc_ifc: &mut SocIfc,
        persistent_data: &mut PersistentData,
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let request = OcpLockReportHekMetadataReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        if !soc_ifc.ocp_lock_enabled() {
            Err(CaliptraError::FW_PROC_OCP_LOCK_UNSUPPORTED)?;
        }

        // Use the response buffer directly as OcpLockReportHekMetadataResp.
        // The buffer is zeroized at the start of the loop
        let resp_buffer_size =
            core::mem::size_of::<caliptra_api::mailbox::OcpLockReportHekMetadataResp>();
        let resp = resp
            .get_mut(..resp_buffer_size)
            .ok_or(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;
        let hek_resp = caliptra_api::mailbox::OcpLockReportHekMetadataResp::mut_from_bytes(resp)
            .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        let hek_resp_data = ocp_lock::handle_report_hek_metadata(
            soc_ifc.lifecycle(),
            persistent_data,
            request,
            &soc_ifc.fuse_bank().ocp_hek_seed(),
        )?;

        // Copy the data from the response
        hek_resp.flags = hek_resp_data.flags;
        hek_resp.hdr = hek_resp_data.hdr;
        let resp_bytes = hek_resp.as_bytes();
        Ok(resp_bytes.len())
    }
}
