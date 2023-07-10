/*++

Licensed under the Apache-2.0 license.

File Name:

    start.S

Abstract:

    File contains startup code for Caliptra.

Environment:

    ROM
   
--*/

.section .init, "ax"
.global _start
_start:
   .cfi_startproc
   .cfi_undefined ra

   // Clear minstret
   csrw minstret, zero
   csrw minstreth, zero
    
   // Disable interrupts and clear pending interrupts
   csrw mstatus, 0
   csrw mie, 0
   csrw mip, 0

   // Clear all registers
   li x1,  0; li x2,  0; li x3,  0; li x4,  0;
   li x5,  0; li x6,  0; li x7,  0; li x8,  0;
   li x9,  0; li x10, 0; li x11, 0; li x12, 0;
   li x13, 0; li x14, 0; li x15, 0; li x16, 0;
   li x17, 0; li x18, 0; li x19, 0; li x20, 0;
   li x21, 0; li x22, 0; li x23, 0; li x24, 0;
   li x25, 0; li x26, 0; li x27, 0; li x28, 0;
   li x29, 0; li x30, 0; li x31, 0;

   // Setup the global pointer to enable linker relaxation.
   // Linker relaxation enables generation of relative jump
   // instruction on function calls and jumps. The relative
   // jumps have a tighter encoding than absolute jumps hence
   // reducing code memory usage.
   .option push
   .option norelax
      la gp, __global_pointer$
   .option pop

    // Setup Memory Region Attributes
    //
    // Veer Core Memory is divided in to 16 regions of 256 MB
    // each. Each region has 2 possible attributes:
    //  1. Cacheability
    //  2. Side Effects
    // 
    // Caliptra does not have any caches hence the Cacheability
    // attribute is zero for all regions. Side-effect as not
    // observable in memory regions containing ROM, ICCM & DCCM.
    // However they are enabled for regions containing peripheral
    // registers.
    //
    // ---------------------------------------------
    // | Region       | Side Effect |  Cacheable   |      
    // ---------------------------------------------
    // | 0x0000_0000  |    0        |      1       |  
    // | 0x4000_0000  |    0        |      0       |  
    // | 0x5000_0000  |    0        |      0       |  
    // | Others       |    1        |      0       |  
    // ---------------------------------------------
    //
    // CSR MRAC = 0x7C0 
    li x1, 0xAAAAA0A9
    csrw 0x7C0, x1

    // Setup stack pointer   
    la sp, _sstack
    
    // Interrupts are disabled and will remain disabled in ROM so we only
    // need to worry about exceptions, so no reason to do vectored.
    // Setup Direct Exception Vector
    la t0, _exception_handler
    csrw mtvec, t0

    // Setup NMI Vector
    // Load address of NMI handler
    la t0, _nmi_handler
    // Load address of MMIO NMI vector register
    // CLP_SOC_IFC_REG_INTERNAL_NMI_VECTOR = 0x3003062c
    li t1, 0x3003062c
    // Store address of NMI handler in MMIO NMI vector register
    sw t0, 0x0(t1)

    // Initialize ICCM & DCCM on cold boot to
    // all zeros. This is needed to intialize the ECC
    // in ICCM & DCCM.
    // CLP_SOC_IFC_REG_CPTRA_RESET_REASON = 0x30030040
    li t0, 0x30030040
    lw t1, 0x0(t0)
    andi t1, t1, 0x3
    bne t1, x0, post_ecc_init

    // Cold Boot
    la a0, ICCM_ORG         // dest
    la a1, ICCM_SIZE        // len 
    call _zero_mem256

    la a0, DCCM_ORG         // dest
    la a1, DCCM_SIZE        // len 
    call _zero_mem256

post_ecc_init:

    // Copy Data Section    
    // la a0, _sdata        // dest
    // la a1, _sidata       // src
    // la a2, _data_len     // len 
    // call _copy_mem32

    // Zero BSS Section    
    // la a0, _sbss         // dest
    // la a1, _bss_len      // len 
    // call _zero_mem32

    tail rom_entry

    .cfi_endproc 

.section .init.text, "ax"
.align 2
_zero_mem256:
    .cfi_startproc
    // Can't use "sw x0" below if we want c.sw
    li a2, 0
    add a1, a1, a0
1:    
    sw a2, 0(a0)
    sw a2, 4(a0)
    sw a2, 8(a0)
    sw a2, 12(a0)
    sw a2, 16(a0)
    sw a2, 20(a0)
    sw a2, 24(a0)
    sw a2, 28(a0)
    addi a0, a0, 32
    bltu a0, a1, 1b
    ret
    .cfi_endproc

.section .init.text, "ax"
.align 2
_copy_mem32:
    .cfi_startproc
    li t0, 4
1:  
    beqz a2, 1f
    lw t1, 0(a1)
    sw t1, 0(a0)
    addi a0, a0, 4
    addi a1, a1, 4
    sub a2, a2, t0
    j 1b
1:
    ret   
    .cfi_endproc

.section .init.text, "ax"
.align 2
_exception_handler:
    // Save sp to mscratch
    csrw mscratch, sp

    // Switch to exception stack
    la sp, _sestack

    // Allocate space for all relevant registers 
    // (ra, sp, a0-7, t0-6, mepc, mcause, mscause, mstatus, mtval)
    addi sp, sp, -88

    // Save relevant registers to stack except x2(sp) since that is in mscratch
    sw ra,  0x0(sp)
    // Skipping 0x4(sp) for now to store sp later
    sw a0, 0x8(sp)
    sw a1, 0xC(sp)
    sw a2, 0x10(sp)
    sw a3, 0x14(sp)
    sw a4, 0x18(sp)
    sw a5, 0x1C(sp)
    sw a6, 0x20(sp)
    sw a7, 0x24(sp)
    sw t0, 0x28(sp)
    sw t1, 0x2C(sp)
    sw t2, 0x30(sp)
    sw t3, 0x34(sp)
    sw t4, 0x38(sp)
    sw t5, 0x3C(sp)
    sw t6, 0x40(sp)

    // Save original sp to 0x4(sp)
    csrr t0, mscratch // Load mscratch (original sp) to t0
    sw t0, 0x4(sp)

    // Save mepc to 0x44(sp)
    csrr t0, mepc // Load mepc to t0
    sw t0, 0x44(sp)

    // Save mcause to 0x48(sp)
    csrr t0, mcause // Load mcause to t0
    sw t0, 0x48(sp)

    # // Save mscause to 0x4C(sp)
    // MSCAUSE = 0x7FF
    csrr t0, 0x7FF // Load mscause to t0
    sw t0, 0x4C(sp)

    // Save mstatus to 0x50(sp)
    csrr t0, mstatus // Load mstatus to t0
    sw t0, 0x50(sp)

    // Save mtval to 0x54(sp)
    csrr t0, mtval // Load mtval to t0
    sw t0, 0x54(sp)

    // Call the rust trap handler with the stack pointer as the parameter
    addi a0, sp, 0
    jal exception_handler

    // Restore relevant registers except x2(sp)
    lw ra,  0x0(sp)
    // Skipping 0x4(sp) for now to store sp later
    lw a0, 0x8(sp)
    lw a1, 0xC(sp)
    lw a2, 0x10(sp)
    lw a3, 0x14(sp)
    lw a4, 0x18(sp)
    lw a5, 0x1C(sp)
    lw a6, 0x20(sp)
    lw a7, 0x24(sp)
    lw t0, 0x28(sp)
    lw t1, 0x2C(sp)
    lw t2, 0x30(sp)
    lw t3, 0x34(sp)
    lw t4, 0x38(sp)
    lw t5, 0x3C(sp)
    lw t6, 0x40(sp)

    // Restore original sp from 0x4(sp)
    lw sp,  0x4(sp)

    mret

.section .init.text, "ax"
.align 2
_nmi_handler:
    // Save sp to mscratch
    csrw mscratch, sp

    // Switch to exception stack
    la sp, _snstack

    // Allocate space for all relevant registers (ra, sp, a0-7, t0-6, mepc, mcause, mscause, mstatus, mtval)
    addi sp, sp, -88

    // Save relevant registers to stack except x2(sp) since that is in mscratch
    sw ra,  0x0(sp)
    // Skipping 0x4(sp) for now to store sp later
    sw a0, 0x8(sp)
    sw a1, 0xC(sp)
    sw a2, 0x10(sp)
    sw a3, 0x14(sp)
    sw a4, 0x18(sp)
    sw a5, 0x1C(sp)
    sw a6, 0x20(sp)
    sw a7, 0x24(sp)
    sw t0, 0x28(sp)
    sw t1, 0x2C(sp)
    sw t2, 0x30(sp)
    sw t3, 0x34(sp)
    sw t4, 0x38(sp)
    sw t5, 0x3C(sp)
    sw t6, 0x40(sp)

    // Save original sp to 0x4(sp)
    csrr t0, mscratch // Load mscratch (original sp) to t0
    sw t0, 0x4(sp)

    // Save mepc to 0x44(sp)
    csrr t0, mepc // Load mepc to t0
    sw t0, 0x44(sp)

    // Save mcause to 0x48(sp)
    csrr t0, mcause // Load mcause to t0
    sw t0, 0x48(sp)

    # // Save mscause to 0x4C(sp)
    // MSCAUSE = 0x7FF
    csrr t0, 0x7FF // Load mscause to t0
    sw t0, 0x4C(sp)

    // Save mstatus to 0x50(sp)
    csrr t0, mstatus // Load mstatus to t0
    sw t0, 0x50(sp)

    // Save mtval to 0x54(sp)
    csrr t0, mtval // Load mtval to t0
    sw t0, 0x54(sp)

    // Call the rust nmi handler with the stack pointer as the parameter
    addi a0, sp, 0
    jal nmi_handler

    // Restore relevant registers except x2(sp)
    lw ra,  0x0(sp)
    // Skipping 0x4(sp) for now to store sp later
    lw a0, 0x8(sp)
    lw a1, 0xC(sp)
    lw a2, 0x10(sp)
    lw a3, 0x14(sp)
    lw a4, 0x18(sp)
    lw a5, 0x1C(sp)
    lw a6, 0x20(sp)
    lw a7, 0x24(sp)
    lw t0, 0x28(sp)
    lw t1, 0x2C(sp)
    lw t2, 0x30(sp)
    lw t3, 0x34(sp)
    lw t4, 0x38(sp)
    lw t5, 0x3C(sp)
    lw t6, 0x40(sp)

    // Restore original sp from 0x4(sp)
    lw sp,  0x4(sp)

    mret

.section .init.text, "ax"
.align 2
.global exit_rom
exit_rom:
    .cfi_startproc
    jr a0
1:
    j 1b
    .cfi_endproc
