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
use caliptra_common::mailbox_api::{
    MailboxRespHeader, OcpLockUnloadMekReq, OcpLockUnloadMekResp,
    OCP_LOCK_ENCRYPTION_ENGINE_METADATA_SIZE,
};
use caliptra_drivers::{CaliptraError, CaliptraResult, DmaEncryptionEngine};
use zerocopy::FromBytes;

use super::timeout_to_mtime;

pub struct UnloadMekCmd;
impl UnloadMekCmd {
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if cmd_bytes.len() != size_of::<OcpLockUnloadMekReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }

        let cmd = OcpLockUnloadMekReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
        let soc_ifc = &mut drivers.soc_ifc;

        // Convert timeout into mtime
        let (ready_mtimeout, cmd_mtimeout) =
            timeout_to_mtime(cmd.rdy_timeout, cmd.cmd_timeout, soc_ifc.get_clock_period());
        let start_mtime = soc_ifc.get_timestamp();

        // Prepare an encryption engine DMA
        let addr = soc_ifc.ocp_lock_get_key_release_addr();
        let dma_encryption_engine = DmaEncryptionEngine::new(addr.into(), &drivers.dma);

        // Clear pending done bit
        dma_encryption_engine.clear_ctrl();

        // Wait until encryption engine to be ready
        dma_encryption_engine.wait_ready(soc_ifc, start_mtime, ready_mtimeout)?;

        // Write METD
        let aligned_metadata = cmd
            .metadata
            .chunks_exact(size_of::<u32>())
            .enumerate()
            .fold(
                [0u32; OCP_LOCK_ENCRYPTION_ENGINE_METADATA_SIZE / size_of::<u32>()],
                |mut acc, (idx, chunk)| {
                    acc[idx] = u32::from_le_bytes(chunk.try_into().unwrap());
                    acc
                },
            );
        dma_encryption_engine.write_metadata(&aligned_metadata);

        // Write Unload command
        let start_mtime = soc_ifc.get_timestamp();
        dma_encryption_engine.execute_unload_command();

        // Wait the execution to be done
        let result = dma_encryption_engine.wait_done(soc_ifc, start_mtime, cmd_mtimeout)?;

        // Clear register by writing done bit
        dma_encryption_engine.clear_ctrl();

        // Handle encryption engine error
        if let Some(error_code) = result {
            soc_ifc.set_fw_extended_error(error_code.into());
            Err(CaliptraError::OCP_LOCK_ENGINE_ERR)?
        };

        // Populate response
        let resp = mutrefbytes::<OcpLockUnloadMekResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();

        Ok(core::mem::size_of::<OcpLockUnloadMekResp>())
    }
}
