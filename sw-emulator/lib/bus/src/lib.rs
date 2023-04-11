/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains exports for for Caliptra Emulator Bus library.

--*/
mod bus;
mod clock;
mod dynamic_bus;
mod mem;
mod ram;
mod register;
mod register_array;
mod rom;
pub mod testing;

pub use crate::bus::{Bus, BusError};
pub use crate::clock::{ActionHandle, Clock, Timer, TimerActionType};
pub use crate::dynamic_bus::DynamicBus;
pub use crate::ram::Ram;
pub use crate::register::{
    ReadOnlyMemory, ReadOnlyRegister, ReadWriteMemory, ReadWriteRegister, Register,
    WriteOnlyMemory, WriteOnlyRegister,
};
pub use crate::register_array::{ReadWriteRegisterArray, RegisterArray};
pub use crate::rom::Rom;
