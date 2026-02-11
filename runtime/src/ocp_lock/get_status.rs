/*++

Licensed under the Apache-2.0 license.

File Name:

    get_status.rs

Abstract:

    File contains GET_STATUS mailbox command.

--*/

use crate::mutrefbytes;
use crate::Drivers;
use caliptra_common::mailbox_api::{MailboxRespHeader, OcpLockGetStatusReq, OcpLockGetStatusResp};
use caliptra_drivers::{CaliptraError, CaliptraResult, DmaEncryptionEngine};

pub struct GetStatusCmd;
impl GetStatusCmd {
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if cmd_bytes.len() != size_of::<OcpLockGetStatusReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }

        // Read CTRL register from encryption engine
        let addr = drivers.soc_ifc.ocp_lock_get_key_release_addr();
        let dma_encryption_engine = DmaEncryptionEngine::new(addr.into(), &drivers.dma);
        let ctrl_value = dma_encryption_engine.read_ctrl();

        // Populate response
        let resp = mutrefbytes::<OcpLockGetStatusResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.ctrl_register = ctrl_value;

        Ok(core::mem::size_of::<OcpLockGetStatusResp>())
    }
}
