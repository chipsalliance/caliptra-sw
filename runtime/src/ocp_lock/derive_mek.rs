// Licensed under the Apache-2.0 license

use crate::{mutrefbytes, Drivers};

use caliptra_api::mailbox::{MailboxRespHeader, OcpLockDeriveMekReq, OcpLockDeriveMekResp};
#[cfg(feature = "cfi")]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::keyids::ocp_lock::KEY_ID_MEK;
use caliptra_drivers::DmaEncryptionEngine;

use caliptra_error::{CaliptraError, CaliptraResult};

use zerocopy::FromBytes;

use super::{timeout_to_mtime, MekChecksum};

pub struct DeriveMekCmd;
impl DeriveMekCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let cmd = OcpLockDeriveMekReq::ref_from_bytes(cmd_args)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

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

        let expected_mek_checksum = MekChecksum(cmd.mek_checksum);
        let checksum = drivers.ocp_lock_context.derive_mek(
            &mut drivers.aes,
            &mut drivers.hmac,
            &mut drivers.trng,
            &mut drivers.key_vault,
            expected_mek_checksum,
        )?;

        // Write MEK
        dma_encryption_engine
            .release_mek_from_key_vault(soc_ifc.ocp_lock_get_key_size(), || {
                drivers.key_vault.erase_key(KEY_ID_MEK)
            })?;

        // Write Load command
        dma_encryption_engine.execute_load_command();

        // Wait the execution to be done
        let result = dma_encryption_engine.wait_done(soc_ifc, cmd_mtimeout)?;

        // Clear register by writing done bit
        dma_encryption_engine.clear_ctrl();

        // Handle encryption engine error
        if let Some(error_code) = result {
            soc_ifc.set_fw_extended_error(error_code.into());
            Err(CaliptraError::OCP_LOCK_ENGINE_ERR)?
        };

        let resp = mutrefbytes::<OcpLockDeriveMekResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.mek_checksum = checksum.0;
        Ok(core::mem::size_of::<OcpLockDeriveMekResp>())
    }
}
