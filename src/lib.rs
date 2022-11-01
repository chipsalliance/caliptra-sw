/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains exports for for Caliptra Library.

--*/

#![no_std]

mod reg;

mod error;
mod slice;

mod sha384;

pub type CptrResult<T> = Result<T, u32>;
pub use error::CptrComponent;
pub use sha384::Sha384;

cfg_if::cfg_if! {
    if #[cfg(feature = "emu")] {
        mod uart;
        mod emu_ctrl;

        pub use uart::Uart;
        pub use emu_ctrl::EmuCtrl;
    }
}
