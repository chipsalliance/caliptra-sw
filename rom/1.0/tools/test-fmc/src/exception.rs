/*++

Licensed under the Apache-2.0 license.

File Name:

    exception.rs

Abstract:

    File contains exception related structures

--*/

/// Exception Record
#[repr(C)]
pub(crate) struct ExceptionRecord {
    pub ra: u32,
    pub sp: u32,
    pub a0: u32,
    pub a1: u32,
    pub a2: u32,
    pub a3: u32,
    pub a4: u32,
    pub a5: u32,
    pub a6: u32,
    pub a7: u32,
    pub t0: u32,
    pub t1: u32,
    pub t2: u32,
    pub t3: u32,
    pub t4: u32,
    pub t5: u32,
    pub t6: u32,
    pub mepc: u32,
    pub mcause: u32,
    pub mscause: u32,
    pub mstatus: u32,
    pub mtval: u32,
}
