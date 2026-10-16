/*++

Licensed under the Apache-2.0 license.

File Name:

    zeroize_uds_fe.rs

Abstract:

    File contains the Runtime ZEROIZE_UDS_FE mailbox command.

--*/

use crate::{mutrefbytes, Drivers, FipsShutdownCmd};
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_cfi_lib::{cfi_assert, cfi_assert_bool, cfi_launder};
use caliptra_common::{
    cfi_check,
    mailbox_api::{
        ZeroizeUdsFeReq, ZeroizeUdsFeResp, ZEROIZE_FE0_FLAG, ZEROIZE_FE1_FLAG, ZEROIZE_FE2_FLAG,
        ZEROIZE_FE3_FLAG, ZEROIZE_UDS_FLAG,
    },
    uds_fe_programming::UdsFeProgrammingFlow,
};
use caliptra_drivers::{report_fw_error_non_fatal, CaliptraError, CaliptraResult};
use zerocopy::FromBytes;

const VALID_FLAGS: u32 =
    ZEROIZE_UDS_FLAG | ZEROIZE_FE0_FLAG | ZEROIZE_FE1_FLAG | ZEROIZE_FE2_FLAG | ZEROIZE_FE3_FLAG;

pub struct ZeroizeUdsFeCmd;

impl ZeroizeUdsFeCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        drivers.ensure_pl0()?;
        let request = ZeroizeUdsFeReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        if request.flags == 0 || request.flags & !VALID_FLAGS != 0 {
            return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
        }
        if !drivers.soc_ifc.subsystem_mode() {
            return Err(CaliptraError::RUNTIME_ZEROIZE_UDS_FE_NOT_SUBSYSTEM_MODE);
        }
        let response = mutrefbytes::<ZeroizeUdsFeResp>(resp)?;

        let result = Self::zeroize_partitions(drivers, request.flags);
        cfi_check!(result);

        // Even partial zeroization invalidates the running identity; cleanup failure must not resume it.
        drivers.is_shutdown = true;
        FipsShutdownCmd::execute(drivers)?;

        if let Err(error) = result {
            report_fw_error_non_fatal(error.into());
        }
        *response = ZeroizeUdsFeResp {
            dpe_result: u32::from(result.is_err()),
            ..Default::default()
        };
        Ok(core::mem::size_of::<ZeroizeUdsFeResp>())
    }

    fn zeroize_partitions(drivers: &mut Drivers, flags: u32) -> CaliptraResult<()> {
        if flags & ZEROIZE_UDS_FLAG != 0 {
            UdsFeProgrammingFlow::Uds.zeroize(&mut drivers.soc_ifc, &drivers.dma)?;
        }
        for (partition, flag) in [
            ZEROIZE_FE0_FLAG,
            ZEROIZE_FE1_FLAG,
            ZEROIZE_FE2_FLAG,
            ZEROIZE_FE3_FLAG,
        ]
        .into_iter()
        .enumerate()
        {
            if flags & flag != 0 {
                UdsFeProgrammingFlow::Fe {
                    partition: partition as u32,
                }
                .zeroize(&mut drivers.soc_ifc, &drivers.dma)?;
            }
        }
        Ok(())
    }
}
