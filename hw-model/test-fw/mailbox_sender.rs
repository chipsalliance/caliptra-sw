// Licensed under the Apache-2.0 license

//! A very simple program that sends mailbox transactions.

#![no_main]
#![no_std]

// Needed to bring in startup code
#[allow(unused)]
use caliptra_test_harness::println;

use caliptra_registers::{self};

#[panic_handler]
pub fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

struct Response {
    cmd: u32,
    dlen: u32,
    buf: &'static [u32],
}

const RESPONSES: [Response; 3] = [
    Response {
        cmd: 0xe000_0000,
        dlen: 8,
        buf: &[0x6745_2301, 0xefcd_ab89],
    },
    Response {
        cmd: 0xe000_1000,
        dlen: 3,
        buf: &[0xaabbccdd],
    },
    Response {
        cmd: 0xe000_2000,
        dlen: 0,
        buf: &[],
    },
];

#[no_mangle]
extern "C" fn main() {
    let soc_ifc = caliptra_registers::soc_ifc::RegisterBlock::soc_ifc_reg();
    soc_ifc.cptra_flow_status().write(|w| w.ready_for_fw(true));
    let mbox = caliptra_registers::mbox::RegisterBlock::mbox_csr();

    let mut response_iter = RESPONSES.iter().cycle();
    loop {
        soc_ifc.cptra_fw_extended_error_info().at(0).write(|_| 0);
        assert!(!mbox.lock().read().lock());

        let response = response_iter.next().unwrap();
        mbox.cmd().write(|_| response.cmd);
        mbox.dlen().write(|_| response.dlen);
        for word in response.buf.iter() {
            mbox.datain().write(|_| *word);
        }
        mbox.execute().write(|w| w.execute(true));
        while mbox.status().read().status().cmd_busy() {}
        let status = mbox.status().read().status();
        soc_ifc
            .cptra_fw_extended_error_info()
            .at(1)
            .write(|_| mbox.dlen().read());
        soc_ifc
            .cptra_fw_extended_error_info()
            .at(2)
            .write(|_| mbox.dataout().read());
        soc_ifc
            .cptra_fw_extended_error_info()
            .at(3)
            .write(|_| mbox.dataout().read());
        soc_ifc
            .cptra_fw_extended_error_info()
            .at(4)
            .write(|_| mbox.dataout().read());
        // Transition the state machine to idle.
        mbox.execute().write(|w| w.execute(false));
        soc_ifc
            .cptra_fw_extended_error_info()
            .at(0)
            .write(|_| status.into());
    }
}
