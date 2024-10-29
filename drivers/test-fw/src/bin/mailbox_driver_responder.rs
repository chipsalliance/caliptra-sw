// Licensed under the Apache-2.0 license

//! A very simple program that uses the driver to respond to the mailbox.

#![no_main]
#![no_std]

// Needed to bring in startup code
#[allow(unused)]
use caliptra_test_harness::{self, println};

use caliptra_drivers::{self, Mailbox};
use caliptra_registers::mbox::MboxCsr;
use zerocopy::IntoBytes;

#[panic_handler]
pub fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
extern "C" fn main() {
    let mut mbox = unsafe { Mailbox::new(MboxCsr::new()) };
    loop {
        let Some(mut txn) = mbox.try_start_recv_txn() else {
            continue;
        };
        println!("cmd: 0x{:x}", txn.cmd());
        match txn.cmd() {
            // Test recv_request function
            0x5000_0000 => {
                let mut buf = [0u32; 4];
                let dlen = txn.dlen();
                println!("dlen: {dlen}");
                txn.recv_request(buf.as_mut_bytes()).unwrap();
                println!("buf: {:08x?}", buf);
            }
            // Test recv_request with non-multiple-of-4 result buffer
            0x5000_0001 => {
                let mut buf = [0u8; 5];
                let dlen = txn.dlen();
                println!("dlen: {dlen}");
                txn.recv_request(&mut buf).unwrap();
                println!("buf: {:02x?}", buf);
            }
            // Test copy_request function
            0x6000_0000 => {
                let mut buf = [0u32; 2];
                let dlen = txn.dlen() as usize;
                let dlen_words = (dlen + 3) / 4;
                println!("dlen: {dlen}");
                for _ in 0..((dlen_words + (buf.len() - 1)) / buf.len()) {
                    txn.copy_request(buf.as_mut_bytes()).unwrap();
                    println!("buf: {:08x?}", buf);
                }
                txn.complete(true).unwrap();
            }
            // Test success completion without pulling data out of the fifo
            0x7000_0000 => {
                txn.complete(true).unwrap();
            }
            // Test failure completion without pulling data out of the fifo
            0x8000_0000 => {
                txn.complete(false).unwrap();
            }
            // Test dropping first half of words and then printing the remaining words
            0x9000_0000 => {
                let dlen = txn.dlen() as usize;
                let dlen_words = (dlen + 3) / 4;
                println!("dlen: {dlen}");
                txn.drop_words(dlen_words / 2).unwrap();
                let rem_words = dlen_words / 2;
                let mut buf = [0u32; 1];
                for _ in 0..rem_words {
                    txn.copy_request(buf.as_mut_bytes()).unwrap();
                    println!("buf: {:08x?}", buf);
                }
                txn.complete(true).unwrap();
            }
            // Test responding with 4 bytes copy_response and no request data
            0xA000_0000 => {
                txn.send_response(&mut [0x12, 0x34, 0x56, 0x78]).unwrap();
            }
            // Test responding with request data
            0xB000_0000 => {
                let mut buf = [0u32; 2];
                let dlen = txn.dlen() as usize;
                let dlen_words = (dlen + 3) / 4;
                println!("dlen: {dlen}");
                for _ in 0..((dlen_words + (buf.len() - 1)) / buf.len()) {
                    txn.copy_request(buf.as_mut_bytes()).unwrap();
                    println!("buf: {:08x?}", buf);
                }
                txn.send_response(&mut [0x98, 0x76]).unwrap();
            }
            // Test responding with 9 byte copy_response
            0xC000_0000 => {
                txn.send_response(&mut [0x0A, 0x0B, 0x0C, 0x0D, 0x05, 0x04, 0x03, 0x02, 0x01])
                    .unwrap();
            }
            // Test responding with 0 byte copy_response
            0xD000_0000 => {
                txn.send_response(&mut []).unwrap();
            }
            // Test transaction dropped immediately
            _ => {}
        }
    }
}
