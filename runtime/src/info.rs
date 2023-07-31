// Licensed under the Apache-2.0 license

use crate::{CommandId, Drivers};
use caliptra_common::checksum::calc_checksum;
use core::mem::size_of;
use zerocopy::{AsBytes, FromBytes};

pub struct FwInfoCmd;

impl FwInfoCmd {
    pub(crate) fn execute(drivers: &Drivers) -> FwInfoResp {
        let mut resp = FwInfoResp {
            chksum: 0,
            pl0_pauser: drivers.manifest.header.pl0_pauser,
        };

        let bytes = &resp.as_bytes()[size_of::<i32>()..];
        resp.chksum = calc_checksum(u32::from(CommandId::FW_INFO), bytes);
        resp
    }
}

#[repr(C)]
#[derive(AsBytes, FromBytes)]
pub struct FwInfoResp {
    pub chksum: i32,
    pub pl0_pauser: u32,
    // TODO: Decide what other information to report for general firmware
    // status.
}
