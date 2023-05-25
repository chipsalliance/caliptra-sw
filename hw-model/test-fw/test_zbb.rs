// Licensed under the Apache-2.0 license

//! Basic test for the zbb extensions

#![no_main]
#![no_std]

// Needed to bring in startup code
#[allow(unused)]
use caliptra_test_harness;

use caliptra_registers::{self, soc_ifc::SocIfcReg};

use core::arch::asm;

#[panic_handler]
pub fn panic(_info: &core::panic::PanicInfo) -> ! {
    let mut soc_ifc = unsafe { SocIfcReg::new() };
    // Exit failure
    soc_ifc
        .regs_mut()
        .cptra_generic_output_wires()
        .at(0)
        .write(|_| 0x01);

    loop {}
}

#[no_mangle]
extern "C" fn main() {
    unsafe {
        let mut rd: u32;

        asm!("andn {rd}, {rs1}, {rs2}", rd = out(reg) rd, rs1 = in(reg) 0x958b_c66d_u32, rs2 = in(reg) 0xdd74_23f1_u32);
        assert_eq!(rd, 0x008b_c40c);

        asm!("orn {rd}, {rs1}, {rs2}", rd = out(reg) rd, rs1 = in(reg) 0x4828_aacd_u32, rs2 = in(reg) 0x702d_7829_u32);
        assert_eq!(rd, 0xcffa_afdf);

        asm!("xnor {rd}, {rs1}, {rs2}", rd = out(reg) rd, rs1 = in(reg) 0xc9b1_ad5c_u32, rs2 = in(reg) 0x2135_163d_u32);
        assert_eq!(rd, 0x177b_449e);

        asm!("clz {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x0018_1234_u32);
        assert_eq!(rd, 11);

        asm!("clz {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x0000_0000_u32);
        assert_eq!(rd, 32);

        asm!("clz {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x8000_0000_u32);
        assert_eq!(rd, 0);

        asm!("ctz {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x0002_3540_u32);
        assert_eq!(rd, 6);

        asm!("ctz {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x0000_0000_u32);
        assert_eq!(rd, 32);

        asm!("ctz {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x0000_0001_u32);
        assert_eq!(rd, 0);

        asm!("cpop {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0xf832_2501_u32);
        assert_eq!(rd, 12);

        asm!("cpop {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x0000_0000_u32);
        assert_eq!(rd, 0);

        asm!("cpop {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0xffff_ffff_u32);
        assert_eq!(rd, 32);

        asm!("max {rd}, {rs1}, {rs2}", rd = out(reg) rd, rs1 = in(reg) -5, rs2 = in(reg) 77);
        assert_eq!(rd, 77 as u32);

        asm!("max {rd}, {rs1}, {rs2}", rd = out(reg) rd, rs1 = in(reg) 238123, rs2 = in(reg) 912382);
        assert_eq!(rd, 912382);

        asm!("max {rd}, {rs1}, {rs2}", rd = out(reg) rd, rs1 = in(reg) 912382, rs2 = in(reg) 238123);
        assert_eq!(rd, 912382);

        asm!("maxu {rd}, {rs1}, {rs2}", rd = out(reg) rd, rs1 = in(reg) 0xffff_fffb_u32, rs2 = in(reg) 0x0000_004d);
        assert_eq!(rd, 0xffff_fffb);

        asm!("maxu {rd}, {rs1}, {rs2}", rd = out(reg) rd, rs1 = in(reg) 238123, rs2 = in(reg) 912382);
        assert_eq!(rd, 912382);

        asm!("maxu {rd}, {rs1}, {rs2}", rd = out(reg) rd, rs1 = in(reg) 912382, rs2 = in(reg) 238123);
        assert_eq!(rd, 912382);

        asm!("min {rd}, {rs1}, {rs2}", rd = out(reg) rd, rs1 = in(reg) -5, rs2 = in(reg) 77);
        assert_eq!(rd, -5_i32 as u32);

        asm!("min {rd}, {rs1}, {rs2}", rd = out(reg) rd, rs1 = in(reg) 238123, rs2 = in(reg) 912382);
        assert_eq!(rd, 238123);

        asm!("min {rd}, {rs1}, {rs2}", rd = out(reg) rd, rs1 = in(reg) 912382, rs2 = in(reg) 238123);
        assert_eq!(rd, 238123);

        asm!("minu {rd}, {rs1}, {rs2}", rd = out(reg) rd, rs1 = in(reg) 0xffff_fffb_u32, rs2 = in(reg) 0x0000_004d);
        assert_eq!(rd, 0x0000_004d);

        asm!("minu {rd}, {rs1}, {rs2}", rd = out(reg) rd, rs1 = in(reg) 238123, rs2 = in(reg) 912382);
        assert_eq!(rd, 238123);

        asm!("minu {rd}, {rs1}, {rs2}", rd = out(reg) rd, rs1 = in(reg) 912382, rs2 = in(reg) 238123);
        assert_eq!(rd, 238123);

        asm!("sext.b {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x00);
        assert_eq!(rd, 0x00);

        asm!("sext.b {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x7d);
        assert_eq!(rd, 0x7d);

        asm!("sext.b {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x1122_337d);
        assert_eq!(rd, 0x7d);

        asm!("sext.b {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x7f);
        assert_eq!(rd, 0x7f);

        asm!("sext.b {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x80);
        assert_eq!(rd, 0xffff_ff80);

        asm!("sext.b {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0xae);
        assert_eq!(rd, 0xffff_ffae);

        asm!("sext.b {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0xff);
        assert_eq!(rd, 0xffff_ffff);

        asm!("sext.b {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x1122_3380);
        assert_eq!(rd, 0xffff_ff80);

        asm!("sext.b {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x1122_33ae);
        assert_eq!(rd, 0xffff_ffae);

        asm!("sext.b {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x1122_33ff);
        assert_eq!(rd, 0xffff_ffff);

        asm!("sext.h {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x0000);
        assert_eq!(rd, 0x0000);

        asm!("sext.h {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x7f);
        assert_eq!(rd, 0x7f);

        asm!("sext.h {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x7fff);
        assert_eq!(rd, 0x7fff);

        asm!("sext.h {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x1122_7fff);
        assert_eq!(rd, 0x7fff);

        asm!("sext.h {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x8000);
        assert_eq!(rd, 0xffff_8000);

        asm!("sext.h {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0xaeae);
        assert_eq!(rd, 0xffff_aeae);

        asm!("sext.h {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0xffff);
        assert_eq!(rd, 0xffff_ffff);

        asm!("sext.h {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x1122_8000);
        assert_eq!(rd, 0xffff_8000);

        asm!("sext.h {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x1122_aeae);
        assert_eq!(rd, 0xffff_aeae);

        asm!("sext.h {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x1122_ffff);
        assert_eq!(rd, 0xffff_ffff);

        asm!("zext.h {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x1122_3344);
        assert_eq!(rd, 0x0000_3344);

        asm!("zext.h {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0xffff_ffff_u32);
        assert_eq!(rd, 0x0000_ffff);

        asm!("rol {rd}, {rs1}, {rs2}", rd = out(reg) rd, rs1 = in(reg) 0x5678_9abc, rs2 = in(reg) 0);
        assert_eq!(rd, 0x5678_9abc);

        asm!("rol {rd}, {rs1}, {rs2}", rd = out(reg) rd, rs1 = in(reg) 0x5678_9abc, rs2 = in(reg) 4);
        assert_eq!(rd, 0x6789_abc5);

        asm!("rol {rd}, {rs1}, {rs2}", rd = out(reg) rd, rs1 = in(reg) 0x5678_9abc, rs2 = in(reg) 12);
        assert_eq!(rd, 0x89ab_c567);

        asm!("rol {rd}, {rs1}, {rs2}", rd = out(reg) rd, rs1 = in(reg) 0x5678_9abc, rs2 = in(reg) 31);
        assert_eq!(rd, 0x2b3c_4d5e);

        asm!("rol {rd}, {rs1}, {rs2}", rd = out(reg) rd, rs1 = in(reg) 0x5678_9abc, rs2 = in(reg) 32);
        assert_eq!(rd, 0x5678_9abc);

        asm!("rol {rd}, {rs1}, {rs2}", rd = out(reg) rd, rs1 = in(reg) 0x5678_9abc, rs2 = in(reg) 36);
        assert_eq!(rd, 0x6789_abc5);

        asm!("ror {rd}, {rs1}, {rs2}", rd = out(reg) rd, rs1 = in(reg) 0x5678_9abc, rs2 = in(reg) 0);
        assert_eq!(rd, 0x5678_9abc);

        asm!("ror {rd}, {rs1}, {rs2}", rd = out(reg) rd, rs1 = in(reg) 0x5678_9abc, rs2 = in(reg) 4);
        assert_eq!(rd, 0xc567_89ab);

        asm!("ror {rd}, {rs1}, {rs2}", rd = out(reg) rd, rs1 = in(reg) 0x5678_9abc, rs2 = in(reg) 12);
        assert_eq!(rd, 0xabc5_6789);

        asm!("ror {rd}, {rs1}, {rs2}", rd = out(reg) rd, rs1 = in(reg) 0x5678_9abc, rs2 = in(reg) 31);
        assert_eq!(rd, 0xacf1_3578);

        asm!("ror {rd}, {rs1}, {rs2}", rd = out(reg) rd, rs1 = in(reg) 0x5678_9abc, rs2 = in(reg) 32);
        assert_eq!(rd, 0x5678_9abc);

        asm!("ror {rd}, {rs1}, {rs2}", rd = out(reg) rd, rs1 = in(reg) 0x5678_9abc, rs2 = in(reg) 36);
        assert_eq!(rd, 0xc567_89ab);

        asm!("rori {rd}, {rs}, 0", rd = out(reg) rd, rs = in(reg) 0x5678_9abc);
        assert_eq!(rd, 0x5678_9abc);

        asm!("rori {rd}, {rs}, 4", rd = out(reg) rd, rs = in(reg) 0x5678_9abc);
        assert_eq!(rd, 0xc567_89ab);

        asm!("rori {rd}, {rs}, 12", rd = out(reg) rd, rs = in(reg) 0x5678_9abc);
        assert_eq!(rd, 0xabc5_6789);

        asm!("rori {rd}, {rs}, 31", rd = out(reg) rd, rs = in(reg) 0x5678_9abc);
        assert_eq!(rd, 0xacf1_3578);

        asm!("orc.b {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x0000_0000_u32);
        assert_eq!(rd, 0x0000_0000);

        asm!("orc.b {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x0000_0001_u32);
        assert_eq!(rd, 0x0000_00ff);

        asm!("orc.b {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x4000_0100_u32);
        assert_eq!(rd, 0xff00_ff00);

        asm!("orc.b {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x8044_0073_u32);
        assert_eq!(rd, 0xffff_00ff);

        asm!("orc.b {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x8044_0273_u32);
        assert_eq!(rd, 0xffff_ffff);

        asm!("rev8 {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0x0102_0304_u32);
        assert_eq!(rd, 0x0403_0201);

        asm!("rev8 {rd}, {rs}", rd = out(reg) rd, rs = in(reg) 0xe58d_d63f_u32);
        assert_eq!(rd, 0x3fd6_8de5);
    }

    // Exit success
    let mut soc_ifc = unsafe { SocIfcReg::new() };
    soc_ifc
        .regs_mut()
        .cptra_generic_output_wires()
        .at(0)
        .write(|_| 0xff);
}
