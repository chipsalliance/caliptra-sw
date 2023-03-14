/*++

Licensed under the Apache-2.0 license.

File Name:

    start.S

Abstract:

    File contains startup code for Caliptra.

Environment:

    ROM
   
--*/

#define MRAC        0x7C0
#define REGBYTES    (4)

.section .init, "ax"
.global _start
_start:
   .cfi_startproc
   .cfi_undefined ra

   // Disable interrupts and clear pending interrupts
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
   // jumps have a tigher encoding than absolute jumps hence
   // reducing code memory usage.
   .option push
   .option norelax
      la gp, __global_pointer$
   .option pop

    // Setup Memory Region Attributes
    //
    // Veer Core Memory is divided in to 16 regions of 256 MB
    // each. Each region has 2 possiblie attributes:
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
    // | 0x0000_0000  |    0        |      0       |  
    // | 0x4000_0000  |    0        |      0       |  
    // | 0x5000_0000  |    0        |      0       |  
    // | Others       |    1        |      0       |  
    // ---------------------------------------------
    //
    // CSR MRAC = 0x7C0 
    li x1, 0xAAAAA0A8
    csrw 0x7C0, x1
 
    // Setup stack pointer   
    la sp, _sstack

    // TODO: Initialize ICCM & DCCM on cold boot to
    // all zeros. This is needed to intialize the ECC
    // in ICCM & DCCM.

    // Setup Exception Vector
    la   t0, _trap_entry
    csrw   mtvec, t0
    // TODO: Setup NMI Vector

    // Copy Data Section    
    la a0, _sdata        // dest
    la a1, _sidata       // src
    la a2, _data_len     // len 
    call _copy_mem32
    
    // Zero BSS Section    
    la a0, _sbss         // dest
    la a1, _bss_len      // len 
    call _zero_mem32

    tail main

    .cfi_endproc 

.section .init.text, "ax"
.align 2
_zero_mem32:
    .cfi_startproc
    li t0, 4
1:    
    beqz a1, 1f
    sw x0, 0(a0) 
    addi a0, a0, 4
    sub a1, a1, t0
    j 1b
1:
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

/* 
    Trap entry point (_trap_entry)
    Saves caller saved registers ra, t0..6, a0..7, calls trap handler in rust,
    restores caller saved registers and then returns.    
*/
.section .trap, "ax"
.global  _trap_entry    

_trap_entry:
    addi sp, sp, -16*4
    sw     ra, 0*4(sp)
/* Save temporary registers t0-t6 */
    sw     t0, 1*4(sp)
    sw     t1, 2*4(sp)
    sw     t2, 3*4(sp)
    sw     t3, 4*4(sp)
    sw     t4, 5*4(sp)
    sw     t5, 6*4(sp)
    sw     t6, 7*4(sp)

/* Save argument registers a0-a7 */
    sw     a0, 8*4(sp)
    sw     a1, 9*4(sp)
    sw     a2, 10*4(sp)
    sw     a3, 11*4(sp)
    sw     a4, 12*4(sp)
    sw     a5, 13*4(sp)
    sw     a6, 14*4(sp)
    sw     a7, 15*4(sp)

    jal    zero, _rust_trap_entry 

    lw     ra, 0*4(sp)
    lw     t0, 1*4(sp)
    lw     t1, 2*4(sp)
    lw     t2, 3*4(sp)
    lw     t3, 4*4(sp)
    lw     t4, 5*4(sp)
    lw     t5, 6*4(sp)
    lw     t6, 7*4(sp)

    lw     a0, 8*4(sp)
    lw     a1, 9*4(sp)
    lw     a2, 10*4(sp)
    lw     a3, 11*4(sp)
    lw     a4, 12*4(sp)
    lw     a5, 13*4(sp)
    lw     a6, 14*4(sp)
    lw     a7, 15*4(sp)


    addi sp, sp, 16*4
    mret