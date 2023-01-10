/*++

Licensed under the Apache-2.0 license.

File Name:

    mod.rs

Abstract:

    File contains register definitions for Caliptra

--*/

pub(crate) mod static_ref;

pub(crate) mod doe_regs;
pub(crate) mod hmac384_regs;
pub(crate) mod sha256_regs;
pub(crate) mod sha512_regs;

cfg_if::cfg_if! {
    if #[cfg(feature = "emu")] {
        pub(crate) mod emu_ctrl_regs;
    }
}
