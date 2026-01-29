/*++

Licensed under the Apache-2.0 license.

File Name:

    clear_key_cache.rs

Abstract:

    File contains CLEAR_KEY_CACHE mailbox command.

--*/

use crate::mutrefbytes;
use crate::Drivers;
use caliptra_common::mailbox_api::{
    MailboxRespHeader, OcpLockClearKeyCacheReq, OcpLockClearKeyCacheResp,
};
use caliptra_drivers::{CaliptraError, CaliptraResult, DmaEncryptionEngine};
use zerocopy::FromBytes;

use super::timeout_to_mtime;

pub struct ClearKeyCacheCmd;
impl ClearKeyCacheCmd {
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if cmd_bytes.len() != size_of::<OcpLockClearKeyCacheReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }

        let cmd = OcpLockClearKeyCacheReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
        let soc_ifc = &mut drivers.soc_ifc;

        // Convert timeout into mtime
        let cmd_mtimeout = timeout_to_mtime(cmd.cmd_timeout, soc_ifc.get_clock_period() as u64);

        // Prepare an encryption engine DMA
        let addr = soc_ifc.ocp_lock_get_key_release_addr();
        let dma_encryption_engine = DmaEncryptionEngine::new(addr.into(), &drivers.dma);

        // Clear pending done bit
        dma_encryption_engine.clear_ctrl();

        // Check if the encryption engine is ready
        dma_encryption_engine.check_ready()?;

        // Write Zeroization command
        dma_encryption_engine.execute_zeroization_command();

        // Wait the execution to be done
        let result = dma_encryption_engine.wait_done(soc_ifc, cmd_mtimeout)?;

        // Clear register by writing done bit
        dma_encryption_engine.clear_ctrl();

        // Handle encryption engine error
        if let Some(error_code) = result {
            soc_ifc.set_fw_extended_error(error_code.into());
            Err(CaliptraError::OCP_LOCK_ENGINE_ERR)?
        };

        // Populate response
        let resp = mutrefbytes::<OcpLockClearKeyCacheResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();

        Ok(core::mem::size_of::<OcpLockClearKeyCacheResp>())
    }
}
