/*++

Licensed under the Apache-2.0 license.

File Name:

pic.rs

Abstract:

File contains a driver for the RISC-V VeeR EL2 programmable interrupt controller

--*/

use caliptra_registers::el2_pic_ctrl::*;

pub enum IntSource {
    DoeErr = 1,
    DoeNotif = 2,
    EccErr = 3,
    EccNotif = 4,
    HmacErr = 5,
    HmacNotif = 6,
    KvErr = 7,
    KvNotif = 8,
    Sha512Err = 9,
    Sha512Notif = 10,
    Sha256Err = 11,
    Sha256Notif = 12,
    QspiErr = 13,
    QspiNotif = 14,
    UartErr = 15,
    UartNotif = 16,
    I3cErr = 17,
    I3cNotif = 18,
    SocIfcErr = 19,
    SocIfcNotif = 20,
    Sha512AccErr = 21,
    Sha512AccNotif = 22,
}

impl From<IntSource> for usize {
    fn from(source: IntSource) -> Self {
        source as Self
    }
}

pub struct Pic {
    pic: El2PicCtrl,
}

impl Pic {
    pub fn new(pic: El2PicCtrl) -> Self {
        Self { pic }
    }

    pub fn int_set_max_priority(&mut self, source: IntSource) {
        self.pic
            .regs_mut()
            .meipl()
            .at(source.into())
            .write(|v| v.priority(15));
        #[cfg(feature = "riscv")]
        unsafe {
            core::arch::asm!("fence");
        }
    }

    pub fn int_enable(&mut self, source: IntSource) {
        self.pic
            .regs_mut()
            .meie()
            .at(source.into())
            .write(|v| v.inten(true));
        #[cfg(feature = "riscv")]
        unsafe {
            core::arch::asm!("fence");
        }
    }
}
