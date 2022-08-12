/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains exports for for Caliptra Emulator Bus library.

--*/
mod bus;
mod dynamic_bus;
mod mem;
mod ram;
mod register;
mod rom;

pub use crate::bus::{Bus, BusError};
pub use crate::dynamic_bus::DynamicBus;
pub use crate::ram::Ram;
pub use crate::register::{
    ReadOnlyMemory, ReadOnlyRegister, ReadWriteMemory, ReadWriteRegister, Register,
    WriteOnlyMemory, WriteOnlyRegister,
};
pub use crate::rom::Rom;
