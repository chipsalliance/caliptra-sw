/*++

Licensed under the Apache-2.0 license.

File Name:

    load_kat_mek.rs

Abstract:

    File contains LOAD_KAT_MEK mailbox command.

--*/

use crate::mutrefbytes;
use crate::Drivers;
#[cfg(feature = "cfi")]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::mailbox_api::{
    MailboxRespHeader, OcpLockLoadKatMekReq, OcpLockLoadKatMekResp,
    OCP_LOCK_ENCRYPTION_ENGINE_MAX_MEK_SIZE,
};
use caliptra_drivers::{CaliptraError, CaliptraResult, DmaEncryptionEngine};
use zerocopy::FromBytes;

use super::timeout_to_mtime;

/// MEK for KAT support. The value is fixed in the OCP L.O.C.K. specification
const KAT_MEK: [u32; OCP_LOCK_ENCRYPTION_ENGINE_MAX_MEK_SIZE / size_of::<u32>()] = [
    0x0000_0000,
    0x0000_0000,
    0x0000_0000,
    0x0000_0000,
    0x1111_1111,
    0x1111_1111,
    0x1111_1111,
    0x1111_1111,
    0x2222_2222,
    0x2222_2222,
    0x2222_2222,
    0x2222_2222,
    0x3333_3333,
    0x3333_3333,
    0x3333_3333,
    0x3333_3333,
];

pub struct LoadKatMekCmd;
impl LoadKatMekCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if cmd_bytes.len() != size_of::<OcpLockLoadKatMekReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }

        let cmd = OcpLockLoadKatMekReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
        let soc_ifc = &mut drivers.soc_ifc;

        // Convert timeout into mtime
        let cmd_mtimeout = timeout_to_mtime(cmd.cmd_timeout, soc_ifc.get_clock_period() as u64);

        // Prepare an encryption engine DMA
        let addr = soc_ifc.ocp_lock_get_key_release_addr();
        let dma_encryption_engine = DmaEncryptionEngine::new(addr.into(), &drivers.dma);

        // Clear pending done bit
        dma_encryption_engine.clear_ctrl();

        // Wait until encryption engine to be ready
        dma_encryption_engine.check_ready()?;

        // Write METD
        dma_encryption_engine.write_metadata(&cmd.metadata);

        // Write AUX
        dma_encryption_engine.write_aux(&cmd.aux_metadata);

        // Write Known MEK
        dma_encryption_engine.write_kat_mek(&KAT_MEK, soc_ifc.ocp_lock_get_key_size())?;

        // Write Load KAT test key command
        dma_encryption_engine.execute_load_kat_command();

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
        let resp = mutrefbytes::<OcpLockLoadKatMekResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();

        Ok(core::mem::size_of::<OcpLockLoadKatMekResp>())
    }
}
