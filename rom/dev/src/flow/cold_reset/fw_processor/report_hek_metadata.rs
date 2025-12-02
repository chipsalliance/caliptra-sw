/*++

Licensed under the Apache-2.0 license.

File Name:

    report_hek_metadata.rs

Abstract:

    File contains REPORT_HEK_METADATA mailbox command.

--*/

use caliptra_api::mailbox::ReportHekMetadataReq;
use caliptra_common::mailbox_api::Response;
use caliptra_drivers::{CaliptraError, CaliptraResult, PersistentData, SocIfc};
use zerocopy::{FromBytes, IntoBytes};

use crate::flow::cold_reset::ocp_lock;

pub struct ReportHekMetadataCmd;
impl ReportHekMetadataCmd {
    #[inline(always)]
    pub(crate) fn execute(
        cmd_bytes: &[u8],
        soc_ifc: &mut SocIfc,
        persistent_data: &mut PersistentData,
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let request = ReportHekMetadataReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        if !soc_ifc.ocp_lock_enabled() {
            Err(CaliptraError::FW_PROC_OCP_LOCK_UNSUPPORTED)?;
        }

        let mut hek_resp = ocp_lock::handle_report_hek_metadata(
            soc_ifc.lifecycle(),
            persistent_data,
            request,
            &soc_ifc.fuse_bank().ocp_hek_seed(),
        )?;

        hek_resp.populate_chksum();
        let resp_bytes = hek_resp.as_bytes();
        resp[..resp_bytes.len()].copy_from_slice(resp_bytes);
        Ok(resp_bytes.len())
    }
}
