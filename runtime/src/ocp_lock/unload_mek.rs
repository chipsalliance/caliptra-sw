/*++

Licensed under the Apache-2.0 license.

File Name:

    unload_mek.rs

Abstract:

    File contains UNLOAD_MEK mailbox command.

--*/

// use caliptra_common::cprintln;
use crate::mutrefbytes;
use crate::Drivers;
use caliptra_common::mailbox_api::{MailboxRespHeader, OcpLockUnloadMekReq, OcpLockUnloadMekResp};
use caliptra_drivers::{CaliptraError, CaliptraResult, DmaEncryptionEngine};
use zerocopy::FromBytes;

use super::{
    create_error_code_from_ctrl, timeout_to_mtime, wait_encryption_engine_done,
    wait_encryption_engine_ready, EncryptionEngineCommandCode, EncryptionEngineCtrl,
};

pub struct UnloadMekCmd;
impl UnloadMekCmd {
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if cmd_bytes.len() != size_of::<OcpLockUnloadMekReq>() {
            Err(CaliptraError::RUNTIME_INVALID_REQUEST_LENGTH)?;
        }

        let cmd = OcpLockUnloadMekReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
        let soc_ifc = &drivers.soc_ifc;

        // Convert timeout into mtime
        let (ready_mtimeout, cmd_mtimeout) =
            timeout_to_mtime(cmd.rdy_timeout, cmd.cmd_timeout, soc_ifc.get_clock_period());
        let start_mtime = soc_ifc.get_timestamp();

        // Prepare an encryption engine DMA
        let addr = soc_ifc.ocp_lock_get_key_release_addr();
        let dma_encryption_engine = DmaEncryptionEngine::new(addr.into(), &drivers.dma, None);

        // Clear pending done bit
        let mut clear_ctrl = EncryptionEngineCtrl(0);
        clear_ctrl.set_done_bit(true);
        dma_encryption_engine.write_ctrl(&clear_ctrl.0.to_le_bytes());

        // Wait until encryption engine to be ready
        let target_mtimeout = ready_mtimeout.min(cmd_mtimeout);
        wait_encryption_engine_ready(
            &dma_encryption_engine,
            soc_ifc,
            start_mtime,
            target_mtimeout,
        )?;

        // Write METD
        dma_encryption_engine.write_metadata(&cmd.metadata);

        // Write Unload command
        let mut execution_ctrl = EncryptionEngineCtrl(0);
        execution_ctrl.set_command_code(EncryptionEngineCommandCode::UnloadMek.into());
        execution_ctrl.set_execute_bit(true);
        dma_encryption_engine.write_ctrl(&execution_ctrl.0.to_le_bytes());

        // Wait the execution to be done
        let output_ctrl = wait_encryption_engine_done(
            &dma_encryption_engine,
            soc_ifc,
            start_mtime,
            cmd_mtimeout,
        )?;

        // Clear register by writing done bit
        dma_encryption_engine.write_ctrl(&clear_ctrl.0.to_le_bytes());

        // Handle encryption engine error
        if output_ctrl.error_code() != 0u8 {
            Err(create_error_code_from_ctrl(output_ctrl.0))?
        }

        // Populate response
        let resp = mutrefbytes::<OcpLockUnloadMekResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();

        Ok(core::mem::size_of::<OcpLockUnloadMekResp>())
    }
}
