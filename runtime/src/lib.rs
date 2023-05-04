// Licensed under the Apache-2.0 license

#![no_std]

mod mailbox;

use mailbox::Mailbox;

use caliptra_common::cprintln;
use caliptra_drivers::{caliptra_err_def, CaliptraResult};
use caliptra_registers::mbox::enums::MboxStatusE;

use core::mem::size_of;

caliptra_err_def! {
    Runtime,
    RuntimeErr
    {
        // Internal
        InternalErr = 0x1,
    }
}

fn wait_for_cmd() {
    // TODO: Enable interrupts?
    //#[cfg(feature = "riscv")]
    //unsafe {
    //core::arch::asm!("wfi");
    //}
}

fn handle_command() -> CaliptraResult<()> {
    let cmd_id = Mailbox::cmd();
    let dlen_words = Mailbox::dlen_words() as usize;
    let mut buf = [0u32; 1024];
    Mailbox::copy_from_mbox(buf.get_mut(..dlen_words).ok_or(err_u32!(InternalErr))?);

    // TODO: Actually handle command
    cprintln!("[rt] Received command={}, len={}", cmd_id, Mailbox::dlen());

    // Write response
    let out_buf = [0xFFFFFFFFu32; 4];
    Mailbox::set_dlen((out_buf.len() * size_of::<u32>()) as u32);
    Mailbox::copy_to_mbox(&out_buf);

    Ok(())
}

pub fn handle_mailbox_commands() {
    loop {
        wait_for_cmd();

        if Mailbox::is_cmd_ready() {
            if handle_command().is_ok() {
                Mailbox::set_status(MboxStatusE::DataReady);
            } else {
                Mailbox::set_status(MboxStatusE::CmdFailure);
            }
        }
    }
}
