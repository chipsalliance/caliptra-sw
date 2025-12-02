/*++

Licensed under the Apache-2.0 license.

File Name:

    zeroize_uds_fe.rs

Abstract:

    File contains ZEROIZE_UDS_FE mailbox command.

--*/

use caliptra_api::mailbox::{
    ZeroizeUdsFeReq, ZeroizeUdsFeResp, ZEROIZE_FE0_FLAG, ZEROIZE_FE1_FLAG, ZEROIZE_FE2_FLAG,
    ZEROIZE_FE3_FLAG, ZEROIZE_UDS_FLAG,
};
use caliptra_common::mailbox_api::{MailboxRespHeader, Response};
use caliptra_common::uds_fe_programming::UdsFeProgrammingFlow;
use caliptra_drivers::{CaliptraError, CaliptraResult, Dma, SocIfc};
use zerocopy::{FromBytes, IntoBytes};

pub struct ZeroizeUdsFeCmd;
impl ZeroizeUdsFeCmd {
    #[inline(always)]
    pub(crate) fn execute(
        cmd_bytes: &[u8],
        soc_ifc: &mut SocIfc,
        dma: &mut Dma,
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let request = ZeroizeUdsFeReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        let result = (|| -> CaliptraResult<()> {
            // Zeroize UDS partition
            if request.flags & ZEROIZE_UDS_FLAG != 0 {
                let uds_flow = UdsFeProgrammingFlow::Uds;
                uds_flow.zeroize(soc_ifc, dma)?;
            }

            // Zeroize FE partitions (0-3)
            const FE_FLAGS: [u32; 4] = [
                ZEROIZE_FE0_FLAG,
                ZEROIZE_FE1_FLAG,
                ZEROIZE_FE2_FLAG,
                ZEROIZE_FE3_FLAG,
            ];
            for (partition, &flag) in FE_FLAGS.iter().enumerate() {
                if request.flags & flag != 0 {
                    let fe_flow = UdsFeProgrammingFlow::Fe {
                        partition: partition as u32,
                    };
                    fe_flow.zeroize(soc_ifc, dma)?;
                }
            }

            Ok(())
        })();

        // Use the response buffer directly as ZeroizeUdsFeResp.
        // The buffer is zeroized at the start of the loop
        let resp_buffer_size = core::mem::size_of::<ZeroizeUdsFeResp>();
        let resp = resp
            .get_mut(..resp_buffer_size)
            .ok_or(CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;
        let zeroize_resp = ZeroizeUdsFeResp::mut_from_bytes(resp)
            .map_err(|_| CaliptraError::FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH)?;

        zeroize_resp.hdr = MailboxRespHeader::default();
        zeroize_resp.dpe_result = match result {
            Ok(()) => 0,   // NoError
            Err(_) => 0x1, // InternalError
        };
        zeroize_resp.populate_chksum();

        let resp_bytes = zeroize_resp.as_bytes();
        Ok(resp_bytes.len())
    }
}
